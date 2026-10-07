// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {ECDSA} from "@openzeppelin/contracts/utils/cryptography/ECDSA.sol";
import {MessageHashUtils} from "@openzeppelin/contracts/utils/cryptography/MessageHashUtils.sol";
import {MerkleProof} from "@openzeppelin/contracts/utils/cryptography/MerkleProof.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title DeviceRegistry
 * @notice Stores IoT devices and exposes integrity / authenticity checks on them.
 */
abstract contract DeviceRegistry {
    using EnumerableSet for EnumerableSet.UintSet;

    /// @dev Lifecycle state of a device. `None` is only returned for IDs that were never created.
    enum DeviceStatus {
        None,
        Active,
        Suspended,
        Revoked
    }

    /// @dev Main device structure. The first four fields pack into a single storage slot.
    struct Device {
        // Ethereum address of the device owner.
        address owner;
        DeviceStatus status;
        uint40 registeredAt;
        uint40 updatedAt;
        // Unique device identifier. Recommended to be the device's Ethereum address left-padded to 32 bytes,
        // so the device can sign messages that are verifiable on-chain. Can also hold any other 32 byte
        // public key fingerprint. If a device wants to be its own entity, use the owner address.
        bytes32 identifier;
        // Merkle root of device metadata. Lets a device prove a single attribute without revealing the rest.
        bytes32 metadataHash;
        // Hash of the actual firmware hash ("hash of hash"): keeps the firmware hash private while still
        // allowing integrity verification.
        bytes32 firmwareHash;
    }

    /// @dev Index in the array is the device ID.
    Device[] internal _devices;

    /// @dev Device IDs owned by each address.
    mapping(address => EnumerableSet.UintSet) internal _ownedDevices;

    /// @dev identifier => deviceId + 1 (0 means unregistered). Enforces identifier uniqueness.
    mapping(bytes32 => uint256) internal _identifierToDeviceId;

    /// @dev Fired on creation of a new device.
    event DeviceCreated(
        uint256 indexed deviceId,
        address indexed owner,
        bytes32 identifier,
        bytes32 metadataHash,
        bytes32 firmwareHash
    );

    error DeviceNotFound(uint256 deviceId);
    error NotDeviceOwner(uint256 deviceId, address caller);
    error InvalidIdentifier();
    error IdentifierAlreadyRegistered(bytes32 identifier, uint256 deviceId);
    error DeviceIsRevoked(uint256 deviceId);

    modifier deviceExists(uint256 _deviceId) {
        if (_deviceId >= _devices.length) revert DeviceNotFound(_deviceId);
        _;
    }

    /// @dev Ensures the message sender owns the device (also checks that it exists).
    modifier onlyOwnerOf(uint256 _deviceId) {
        if (_deviceId >= _devices.length) revert DeviceNotFound(_deviceId);
        if (_devices[_deviceId].owner != msg.sender) revert NotDeviceOwner(_deviceId, msg.sender);
        _;
    }

    modifier notRevoked(uint256 _deviceId) {
        if (_devices[_deviceId].status == DeviceStatus.Revoked) revert DeviceIsRevoked(_deviceId);
        _;
    }

    /**
     * @notice Registers a new device owned by the caller. Emits DeviceCreated.
     * @param _identifier Unique device identifier (recommended: device Ethereum address, left-padded).
     * @param _metadataHash Merkle root of metadata.
     * @param _firmwareHash Hash of the actual firmware hash.
     * @return deviceId Created device ID.
     */
    function createDevice(
        bytes32 _identifier,
        bytes32 _metadataHash,
        bytes32 _firmwareHash
    ) external returns (uint256 deviceId) {
        _reserveIdentifier(_identifier, _devices.length);

        deviceId = _devices.length;
        _devices.push(
            Device({
                owner: msg.sender,
                status: DeviceStatus.Active,
                registeredAt: uint40(block.timestamp),
                updatedAt: uint40(block.timestamp),
                identifier: _identifier,
                metadataHash: _metadataHash,
                firmwareHash: _firmwareHash
            })
        );
        _ownedDevices[msg.sender].add(deviceId);

        emit DeviceCreated(deviceId, msg.sender, _identifier, _metadataHash, _firmwareHash);
    }

    // ---------------------------------------------------------------------
    // Getters
    // ---------------------------------------------------------------------

    function getDevice(uint256 _deviceId) external view deviceExists(_deviceId) returns (Device memory) {
        return _devices[_deviceId];
    }

    function totalDevices() external view returns (uint256) {
        return _devices.length;
    }

    function ownerDeviceCount(address _owner) external view returns (uint256) {
        return _ownedDevices[_owner].length();
    }

    /**
     * @notice Gets all devices owned by the given address. O(owned devices) instead of O(all devices).
     * @param _owner Owner address.
     * @return Array of device IDs.
     */
    function getDevicesByOwner(address _owner) external view returns (uint256[] memory) {
        return _ownedDevices[_owner].values();
    }

    function ownerOf(uint256 _deviceId) external view deviceExists(_deviceId) returns (address) {
        return _devices[_deviceId].owner;
    }

    /// @notice Address that is expected to sign on behalf of the device (derived from its identifier).
    function signerOf(uint256 _deviceId) public view deviceExists(_deviceId) returns (address) {
        return address(uint160(uint256(_devices[_deviceId].identifier)));
    }

    /// @notice True only for existing devices in the Active state. Never reverts.
    function isActive(uint256 _deviceId) public view returns (bool) {
        return _deviceId < _devices.length && _devices[_deviceId].status == DeviceStatus.Active;
    }

    /// @notice Looks up a device ID by its identifier.
    function deviceIdOf(bytes32 _identifier) external view returns (uint256) {
        uint256 idPlusOne = _identifierToDeviceId[_identifier];
        if (idPlusOne == 0) revert InvalidIdentifier();
        return idPlusOne - 1;
    }

    // ---------------------------------------------------------------------
    // Verification helpers
    // ---------------------------------------------------------------------

    /// @notice Checks whether the device is also an entity (identifier equals owner address).
    function isDeviceAnEntity(uint256 _deviceId) external view deviceExists(_deviceId) returns (bool) {
        return _devices[_deviceId].owner == signerOf(_deviceId);
    }

    /**
     * @notice Checks if `_leaf` is part of the device's metadata Merkle tree (sorted-pair hashing).
     * @param _deviceId ID of a device containing the metadata root.
     * @param _proof Sibling hashes on the branch from the leaf to the root.
     * @param _leaf Leaf of the Merkle tree.
     */
    function isValidMetadataMember(
        uint256 _deviceId,
        bytes32[] calldata _proof,
        bytes32 _leaf
    ) external view deviceExists(_deviceId) returns (bool) {
        return MerkleProof.verifyCalldata(_proof, _devices[_deviceId].metadataHash, _leaf);
    }

    /**
     * @notice Checks if the provided value equals the stored firmware hash.
     * @param _firmwareHash Hash of the firmware hash (not the actual firmware hash).
     */
    function isValidFirmwareHash(
        uint256 _deviceId,
        bytes32 _firmwareHash
    ) external view deviceExists(_deviceId) returns (bool) {
        return _devices[_deviceId].firmwareHash == _firmwareHash;
    }

    /**
     * @notice Validates that `_messageHash` was signed by the device key using an EIP-191
     * personal_sign / eth_sign signature. Rejects malleable signatures.
     * @param _messageHash Hash of the sent message (the signer prefixes it with "\x19Ethereum Signed Message:\n32").
     * @param _signature 65 byte signature.
     */
    function isValidEthMessage(
        uint256 _deviceId,
        bytes32 _messageHash,
        bytes calldata _signature
    ) external view returns (bool) {
        (address recovered, ECDSA.RecoverError err, ) = ECDSA.tryRecover(
            MessageHashUtils.toEthSignedMessageHash(_messageHash),
            _signature
        );
        return err == ECDSA.RecoverError.NoError && recovered == signerOf(_deviceId);
    }

    // ---------------------------------------------------------------------
    // Internal
    // ---------------------------------------------------------------------

    /// @dev Hash of the device properties that an attestation vouches for.
    function _deviceStateHash(uint256 _deviceId) internal view returns (bytes32) {
        Device storage device = _devices[_deviceId];
        return keccak256(abi.encode(device.identifier, device.metadataHash, device.firmwareHash));
    }

    function _reserveIdentifier(bytes32 _identifier, uint256 _deviceId) internal {
        if (_identifier == bytes32(0)) revert InvalidIdentifier();
        uint256 existing = _identifierToDeviceId[_identifier];
        if (existing != 0) revert IdentifierAlreadyRegistered(_identifier, existing - 1);
        _identifierToDeviceId[_identifier] = _deviceId + 1;
    }
}
