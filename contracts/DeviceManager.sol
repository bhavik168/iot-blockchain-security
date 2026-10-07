// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import {EntityRegistry} from "./core/EntityRegistry.sol";
import {DeviceLifecycle} from "./core/DeviceLifecycle.sol";

/**
 * @title DeviceManager
 * @notice Core registry for IoT devices: identities, metadata/firmware integrity, third-party attestations
 * and lifecycle management. Used by SecureMessaging as the source of truth for device keys and status.
 */
contract DeviceManager is EntityRegistry, DeviceLifecycle {
    string public constant VERSION = "2.0.0";
}
