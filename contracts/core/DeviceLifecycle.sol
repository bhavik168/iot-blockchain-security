// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {DeviceAttestations} from "./DeviceAttestations.sol";
import {EnumerableSet} from "@openzeppelin/contracts/utils/structs/EnumerableSet.sol";

/**
 * @title DeviceLifecycle
 * @notice Ownership transfer, property updates and status management (suspend / reactivate / revoke).
 */
abstract contract DeviceLifecycle is DeviceAttestations {
    using EnumerableSet for EnumerableSet.UintSet;

    /// @dev Fired on ownership transfer; keeps track of historical owners.
    event DeviceTransferred(uint256 indexed deviceId, address indexed oldOwner, address indexed newOwner);

    /// @dev Fired on property update; keeps track of historical property values.
    event DevicePropertyUpdated(uint256 indexed deviceId, bytes32 indexed property, bytes32 newValue);

    /// @dev Fired on status change.
    event DeviceStatusChanged(uint256 indexed deviceId, DeviceStatus previousStatus, DeviceStatus newStatus);

    error InvalidRecipient(address recipient);
    error InvalidStatusTransition(uint256 deviceId, DeviceStatus from, DeviceStatus to);

    /**
     * @notice Transfers device ownership. Attestations stay valid because the device itself is unchanged.
     */
    function transferDevice(uint256 _deviceId, address _to) external onlyOwnerOf(_deviceId) notRevoked(_deviceId) {
        if (_to == address(0) || _to == msg.sender) revert InvalidRecipient(_to);

        _devices[_deviceId].owner = _to;
        _devices[_deviceId].updatedAt = uint40(block.timestamp);
        _ownedDevices[msg.sender].remove(_deviceId);
        _ownedDevices[_to].add(_deviceId);

        emit DeviceTransferred(_deviceId, msg.sender, _to);
    }

    /// @notice Rotates the device identifier (e.g. after a key rotation). Invalidates attestations.
    function updateIdentifier(
        uint256 _deviceId,
        bytes32 _newIdentifier
    ) external onlyOwnerOf(_deviceId) notRevoked(_deviceId) {
        // The old identifier stays reserved so a retired key can never be re-registered.
        _reserveIdentifier(_newIdentifier, _deviceId);
        _devices[_deviceId].identifier = _newIdentifier;
        _touch(_deviceId);

        emit DevicePropertyUpdated(_deviceId, "identifier", _newIdentifier);
    }

    /// @notice Updates the metadata Merkle root. Invalidates attestations.
    function updateMetadataHash(
        uint256 _deviceId,
        bytes32 _newMetadataHash
    ) external onlyOwnerOf(_deviceId) notRevoked(_deviceId) {
        _devices[_deviceId].metadataHash = _newMetadataHash;
        _touch(_deviceId);

        emit DevicePropertyUpdated(_deviceId, "metadata", _newMetadataHash);
    }

    /// @notice Records a firmware update. Invalidates attestations until the device is re-attested.
    function updateFirmwareHash(
        uint256 _deviceId,
        bytes32 _newFirmwareHash
    ) external onlyOwnerOf(_deviceId) notRevoked(_deviceId) {
        _devices[_deviceId].firmwareHash = _newFirmwareHash;
        _touch(_deviceId);

        emit DevicePropertyUpdated(_deviceId, "firmware", _newFirmwareHash);
    }

    /// @notice Temporarily disables a device (e.g. suspicious behaviour). Reversible.
    function suspendDevice(uint256 _deviceId) external onlyOwnerOf(_deviceId) {
        _setStatus(_deviceId, DeviceStatus.Active, DeviceStatus.Suspended);
    }

    /// @notice Re-enables a suspended device.
    function reactivateDevice(uint256 _deviceId) external onlyOwnerOf(_deviceId) {
        _setStatus(_deviceId, DeviceStatus.Suspended, DeviceStatus.Active);
    }

    /// @notice Permanently revokes a device (e.g. compromised key). Irreversible.
    function revokeDevice(uint256 _deviceId) external onlyOwnerOf(_deviceId) notRevoked(_deviceId) {
        DeviceStatus previous = _devices[_deviceId].status;
        _devices[_deviceId].status = DeviceStatus.Revoked;
        _devices[_deviceId].updatedAt = uint40(block.timestamp);

        emit DeviceStatusChanged(_deviceId, previous, DeviceStatus.Revoked);
    }

    function _setStatus(uint256 _deviceId, DeviceStatus _expected, DeviceStatus _next) private {
        DeviceStatus current = _devices[_deviceId].status;
        if (current != _expected) revert InvalidStatusTransition(_deviceId, current, _next);
        _devices[_deviceId].status = _next;
        _devices[_deviceId].updatedAt = uint40(block.timestamp);

        emit DeviceStatusChanged(_deviceId, current, _next);
    }

    function _touch(uint256 _deviceId) private {
        _devices[_deviceId].updatedAt = uint40(block.timestamp);
    }
}
