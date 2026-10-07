// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EIP712} from "@openzeppelin/contracts/utils/cryptography/EIP712.sol";
import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {IDeviceRegistry} from "./interfaces/IDeviceRegistry.sol";

/**
 * @title SecureMessaging
 * @notice Authenticated, authorised and replay-protected device-to-device communication.
 *
 * Flow:
 *  1. Each device publishes an X25519 public key (`publishEncryptionKey`). Peers derive a shared secret
 *     (ECDH) and encrypt payloads off-chain with AES-256-GCM. Only hashes ever touch the chain.
 *  2. The receiver's owner allows a sender device to talk to it (`grantAccess`), optionally with expiry.
 *  3. The sender device signs an EIP-712 `DeviceMessage` with its device key. The domain separator binds
 *     the signature to this chain and contract, the nonce prevents replays and the deadline bounds latency.
 *  4. A gateway can verify for free with `verifyMessage` (view) and/or anchor the message on-chain with
 *     `anchorMessage`, which consumes the nonce and leaves a tamper-evident audit trail.
 */
contract SecureMessaging is EIP712 {
    /// @dev Result of a message verification. Returned by `verifyMessage` and used in `MessageRejected`.
    enum Verdict {
        Valid,
        SenderInactive,
        ReceiverInactive,
        NotAuthorized,
        Expired,
        InvalidNonce,
        InvalidSignature
    }

    bytes32 public constant MESSAGE_TYPEHASH =
        keccak256(
            "DeviceMessage(uint256 senderId,uint256 receiverId,bytes32 payloadHash,uint256 nonce,uint256 deadline)"
        );

    IDeviceRegistry public immutable registry;

    /// @notice receiverId => senderId => access expiry (Unix seconds). 0 means no access.
    mapping(uint256 => mapping(uint256 => uint256)) public accessExpiry;

    /// @notice Next expected nonce for each sender device.
    mapping(uint256 => uint256) public nonces;

    /// @notice X25519 public key of each device used for end-to-end payload encryption.
    mapping(uint256 => bytes32) public encryptionKeyOf;

    /// @notice EIP-712 digest => block timestamp at which the message was anchored.
    mapping(bytes32 => uint256) public anchoredAt;

    event AccessGranted(uint256 indexed receiverId, uint256 indexed senderId, uint256 expiresAt);
    event AccessRevoked(uint256 indexed receiverId, uint256 indexed senderId);
    event EncryptionKeyPublished(uint256 indexed deviceId, bytes32 publicKey);
    event MessageAnchored(
        bytes32 indexed digest,
        uint256 indexed senderId,
        uint256 indexed receiverId,
        bytes32 payloadHash,
        uint256 nonce
    );

    error NotDeviceOwner(uint256 deviceId, address caller);
    error NotDeviceController(uint256 deviceId, address caller);
    error DeviceNotActive(uint256 deviceId);
    error InvalidAccessExpiry(uint256 expiresAt);
    error SelfAccess(uint256 deviceId);
    error InvalidPublicKey();
    error MessageRejected(Verdict verdict);

    constructor(IDeviceRegistry _registry) EIP712("IoT SecureMessaging", "1") {
        registry = _registry;
    }

    // ---------------------------------------------------------------------
    // Key distribution
    // ---------------------------------------------------------------------

    /**
     * @notice Publishes the device's X25519 public key. Callable by the device owner or the device key itself.
     * Publishing a new key rotates it; peers should always read the latest value.
     */
    function publishEncryptionKey(uint256 _deviceId, bytes32 _publicKey) external {
        if (!registry.isActive(_deviceId)) revert DeviceNotActive(_deviceId);
        if (msg.sender != registry.ownerOf(_deviceId) && msg.sender != registry.signerOf(_deviceId)) {
            revert NotDeviceController(_deviceId, msg.sender);
        }
        if (_publicKey == bytes32(0)) revert InvalidPublicKey();

        encryptionKeyOf[_deviceId] = _publicKey;

        emit EncryptionKeyPublished(_deviceId, _publicKey);
    }

    // ---------------------------------------------------------------------
    // Access control
    // ---------------------------------------------------------------------

    /**
     * @notice Allows `_senderId` to send messages to `_receiverId` until `_expiresAt`.
     * Only the receiver's owner can grant access to their device.
     */
    function grantAccess(uint256 _receiverId, uint256 _senderId, uint256 _expiresAt) external {
        _requireOwner(_receiverId);
        if (_receiverId == _senderId) revert SelfAccess(_receiverId);
        if (_expiresAt <= block.timestamp) revert InvalidAccessExpiry(_expiresAt);

        accessExpiry[_receiverId][_senderId] = _expiresAt;

        emit AccessGranted(_receiverId, _senderId, _expiresAt);
    }

    /// @notice Revokes a previously granted access right.
    function revokeAccess(uint256 _receiverId, uint256 _senderId) external {
        _requireOwner(_receiverId);
        delete accessExpiry[_receiverId][_senderId];

        emit AccessRevoked(_receiverId, _senderId);
    }

    /// @notice True if both devices are active and the sender currently has access to the receiver.
    function canSend(uint256 _senderId, uint256 _receiverId) public view returns (bool) {
        return
            accessExpiry[_receiverId][_senderId] > block.timestamp &&
            registry.isActive(_senderId) &&
            registry.isActive(_receiverId);
    }

    // ---------------------------------------------------------------------
    // Messaging
    // ---------------------------------------------------------------------

    /// @notice EIP-712 digest the sender device must sign.
    function hashMessage(
        uint256 _senderId,
        uint256 _receiverId,
        bytes32 _payloadHash,
        uint256 _nonce,
        uint256 _deadline
    ) public view returns (bytes32) {
        return
            _hashTypedDataV4(
                keccak256(abi.encode(MESSAGE_TYPEHASH, _senderId, _receiverId, _payloadHash, _nonce, _deadline))
            );
    }

    /**
     * @notice Gas-free check of a message. Gateways can call this before forwarding a payload.
     * @return verdict `Verdict.Valid` or the first reason the message would be rejected.
     */
    function verifyMessage(
        uint256 _senderId,
        uint256 _receiverId,
        bytes32 _payloadHash,
        uint256 _nonce,
        uint256 _deadline,
        bytes calldata _signature
    ) public view returns (Verdict) {
        if (!registry.isActive(_senderId)) return Verdict.SenderInactive;
        if (!registry.isActive(_receiverId)) return Verdict.ReceiverInactive;
        if (accessExpiry[_receiverId][_senderId] <= block.timestamp) return Verdict.NotAuthorized;
        if (_deadline < block.timestamp) return Verdict.Expired;
        if (_nonce != nonces[_senderId]) return Verdict.InvalidNonce;

        bytes32 digest = hashMessage(_senderId, _receiverId, _payloadHash, _nonce, _deadline);
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(digest, _signature);
        if (err != ECDSA.RecoverError.NoError || recovered != registry.signerOf(_senderId)) {
            return Verdict.InvalidSignature;
        }
        return Verdict.Valid;
    }

    /**
     * @notice Verifies and anchors a message on-chain. Anyone (typically a gateway) can relay it because
     * authenticity comes from the device signature, not from msg.sender. Consumes the sender nonce.
     * @return digest The EIP-712 digest, usable with `anchoredAt` as a receipt.
     */
    function anchorMessage(
        uint256 _senderId,
        uint256 _receiverId,
        bytes32 _payloadHash,
        uint256 _nonce,
        uint256 _deadline,
        bytes calldata _signature
    ) external returns (bytes32 digest) {
        Verdict verdict = verifyMessage(_senderId, _receiverId, _payloadHash, _nonce, _deadline, _signature);
        if (verdict != Verdict.Valid) revert MessageRejected(verdict);

        nonces[_senderId] = _nonce + 1;
        digest = hashMessage(_senderId, _receiverId, _payloadHash, _nonce, _deadline);
        anchoredAt[digest] = block.timestamp;

        emit MessageAnchored(digest, _senderId, _receiverId, _payloadHash, _nonce);
    }

    function _requireOwner(uint256 _deviceId) private view {
        if (registry.ownerOf(_deviceId) != msg.sender) revert NotDeviceOwner(_deviceId, msg.sender);
    }
}
