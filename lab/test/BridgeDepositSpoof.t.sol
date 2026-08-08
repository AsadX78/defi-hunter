// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockBridge.sol";
import "../src/attacks/bridge_deposit_spoof.sol";

/**
 * @title BridgeDepositSpoofTest
 * @notice Proves the `bridge_deposit_spoof` template: the bridge mints wrapped
 *         tokens without verifying the deposit proof — attacker mints for free.
 */
contract BridgeDepositSpoofTest is Test {
    MockBridge public bridge;
    BridgeSpoof public spoof;

    function setUp() public {
        bridge = new MockBridge();
        spoof = new BridgeSpoof(address(bridge));
    }

    function testUnverifiedMint() public {
        spoof.attackMint(address(this), 1_000_000 ether);
        assertEq(bridge.balanceOf(address(this)), 1_000_000 ether, "minted without deposit");
        assertEq(bridge.totalSupply(), 1_000_000 ether, "supply inflated");
    }

    function testForgedProof() public {
        spoof.attack("totally forged proof");
        assertGt(bridge.balanceOf(address(spoof)), 0, "forged proof minted tokens");
    }
}
