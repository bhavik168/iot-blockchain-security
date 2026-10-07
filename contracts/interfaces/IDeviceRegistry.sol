// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/// @notice Subset of DeviceManager used by SecureMessaging.
interface IDeviceRegistry {
    function ownerOf(uint256 deviceId) external view returns (address);

    function signerOf(uint256 deviceId) external view returns (address);

    function isActive(uint256 deviceId) external view returns (bool);
}
