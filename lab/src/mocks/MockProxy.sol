// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockProxy
 * @notice VULNERABLE upgradeable proxy — initialize() is callable by anyone
 *         with no guard, so the first caller becomes owner and can upgrade
 *         the implementation.
 * @dev Matches the template IUUPS interface
 *      (initialize / upgradeToAndCall / owner / implementation).
 */
contract MockProxy {
    address public owner;          // unset at deploy (address(0))
    address public implementation;

    // VULN: no `initializer` guard — first caller wins
    function initialize(address _owner) external {
        owner = _owner;
    }

    function upgradeToAndCall(address newImplementation, bytes calldata) external {
        require(msg.sender == owner, "not owner");
        implementation = newImplementation;
    }

    // owner() and implementation() getters are auto-generated from the
    // public storage vars, matching the template IUUPS interface
}
