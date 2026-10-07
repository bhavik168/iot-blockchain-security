// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title EntityRegistry
 * @notice Lets any participant (manufacturer, auditor, device owner) publish public profile data.
 */
abstract contract EntityRegistry {
    /// @dev Entity in the device management system.
    struct Entity {
        // Arbitrary public data, e.g. a name, website or a link to a JSON profile.
        string data;
    }

    /// @notice Maps an address to its Entity.
    mapping(address => Entity) public ownerToEntity;

    /// @dev Fired on entity data update.
    event EntityDataUpdated(address indexed owner, string newData);

    /**
     * @notice Update the caller's entity data.
     * @param _data Entity data.
     */
    function updateEntityData(string calldata _data) external {
        ownerToEntity[msg.sender].data = _data;

        emit EntityDataUpdated(msg.sender, _data);
    }
}
