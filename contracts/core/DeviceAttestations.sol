// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DeviceRegistry} from "./DeviceRegistry.sol";

/**
 * @title DeviceAttestations
 * @notice Third parties (manufacturers, auditors, operators) can vouch for a device.
 * @dev Previously called "signatures". An attestation is bound to a snapshot of the device's identifier,
 * metadata and firmware. Any later change to those properties (e.g. an OTA firmware update) automatically
 * invalidates the attestation, so the device has to be re-attested.
 */
abstract contract DeviceAttestations is DeviceRegistry {
    struct Attestation {
        address attester;
        uint40 expiryTime;
        bool revoked;
        uint256 deviceId;
        bytes32 deviceStateHash;
    }

    /// @dev Index in the array is the attestation ID.
    Attestation[] internal _attestations;

    /// @dev All attestation IDs ever issued for a device.
    mapping(uint256 => uint256[]) internal _deviceAttestations;

    /// @dev deviceId => attester => latest attestation ID + 1.
    mapping(uint256 => mapping(address => uint256)) internal _latestAttestation;

    event DeviceAttested(
        uint256 indexed attestationId,
        uint256 indexed deviceId,
        address indexed attester,
        uint256 expiryTime
    );
    event AttestationRevoked(uint256 indexed attestationId, uint256 indexed deviceId);

    error AttestationNotFound(uint256 attestationId);
    error InvalidExpiryTime(uint256 expiryTime);
    error SelfAttestation(uint256 deviceId);
    error AlreadyAttested(uint256 deviceId, address attester, uint256 attestationId);
    error NotAttester(uint256 attestationId, address caller);
    error AttestationAlreadyRevoked(uint256 attestationId);
    error DeviceNotActive(uint256 deviceId);

    /**
     * @notice Attests the current state of a device. Emits DeviceAttested.
     * @param _deviceId Device to attest. Must be active and not owned by the caller.
     * @param _expiryTime Expiry in Unix seconds, must be in the future.
     * @return attestationId Created attestation ID.
     */
    function attestDevice(uint256 _deviceId, uint256 _expiryTime) external returns (uint256 attestationId) {
        if (!isActive(_deviceId)) revert DeviceNotActive(_deviceId);
        if (_devices[_deviceId].owner == msg.sender) revert SelfAttestation(_deviceId);
        if (_expiryTime <= block.timestamp || _expiryTime > type(uint40).max) revert InvalidExpiryTime(_expiryTime);

        uint256 latest = _latestAttestation[_deviceId][msg.sender];
        if (latest != 0 && isAttestationValid(latest - 1)) {
            revert AlreadyAttested(_deviceId, msg.sender, latest - 1);
        }

        attestationId = _attestations.length;
        _attestations.push(
            Attestation({
                attester: msg.sender,
                expiryTime: uint40(_expiryTime),
                revoked: false,
                deviceId: _deviceId,
                deviceStateHash: _deviceStateHash(_deviceId)
            })
        );
        _deviceAttestations[_deviceId].push(attestationId);
        _latestAttestation[_deviceId][msg.sender] = attestationId + 1;

        emit DeviceAttested(attestationId, _deviceId, msg.sender, _expiryTime);
    }

    /**
     * @notice Revokes an attestation. Only the original attester can revoke. Emits AttestationRevoked.
     */
    function revokeAttestation(uint256 _attestationId) external {
        if (_attestationId >= _attestations.length) revert AttestationNotFound(_attestationId);
        Attestation storage attestation = _attestations[_attestationId];
        if (attestation.attester != msg.sender) revert NotAttester(_attestationId, msg.sender);
        if (attestation.revoked) revert AttestationAlreadyRevoked(_attestationId);

        attestation.revoked = true;

        emit AttestationRevoked(_attestationId, attestation.deviceId);
    }

    /**
     * @notice An attestation is valid when it is not revoked, not expired, the device is not revoked and
     * the device properties have not changed since it was issued.
     */
    function isAttestationValid(uint256 _attestationId) public view returns (bool) {
        if (_attestationId >= _attestations.length) return false;
        Attestation storage attestation = _attestations[_attestationId];
        uint256 deviceId = attestation.deviceId;
        return
            !attestation.revoked &&
            attestation.expiryTime > block.timestamp &&
            _devices[deviceId].status != DeviceStatus.Revoked &&
            attestation.deviceStateHash == _deviceStateHash(deviceId);
    }

    function getAttestation(uint256 _attestationId) external view returns (Attestation memory) {
        if (_attestationId >= _attestations.length) revert AttestationNotFound(_attestationId);
        return _attestations[_attestationId];
    }

    function totalAttestations() external view returns (uint256) {
        return _attestations.length;
    }

    /// @notice All attestation IDs ever issued for the device, including revoked/expired ones.
    function getAttestationsForDevice(uint256 _deviceId) external view returns (uint256[] memory) {
        return _deviceAttestations[_deviceId];
    }

    /// @notice Currently valid attestation IDs for the device.
    function getActiveAttestationsForDevice(uint256 _deviceId) public view returns (uint256[] memory) {
        uint256[] storage all = _deviceAttestations[_deviceId];
        uint256[] memory result = new uint256[](all.length);
        uint256 count = 0;
        for (uint256 i = 0; i < all.length; i++) {
            if (isAttestationValid(all[i])) {
                result[count++] = all[i];
            }
        }
        // Shrink the array to the number of valid entries.
        assembly {
            mstore(result, count)
        }
        return result;
    }

    /// @notice True if `_attester` currently holds a valid attestation for the device.
    function isAttestedBy(uint256 _deviceId, address _attester) external view returns (bool) {
        uint256 latest = _latestAttestation[_deviceId][_attester];
        return latest != 0 && isAttestationValid(latest - 1);
    }

    /// @notice True if the device is active and holds at least one valid attestation.
    function isTrusted(uint256 _deviceId) external view returns (bool) {
        return isActive(_deviceId) && getActiveAttestationsForDevice(_deviceId).length > 0;
    }
}
