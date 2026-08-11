// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockSavingsVault.sol";
import "../src/attacks/withdraw_frontrun.sol";

/**
 * @title WithdrawFrontrunTest
 * @notice Proves the `withdraw_frontrun` TEMPLATE: the shipped
 *         WithdrawFrontRun contract front-runs a redemption to move the
 *         exchange rate and steal the rounding remainder from fresh deposits.
 */
contract WithdrawFrontrunTest is Test {
    MockSavingsVault public vault;
    WithdrawFrontRun public attacker;
    address public victim;

    function setUp() public {
        victim = makeAddr("victim");
        vault = new MockSavingsVault(address(this));
        attacker = new WithdrawFrontRun(address(vault));
    }

    function testWithdrawFrontrun() public {
        // victim already holds 10 shares from a 10 ETH deposit
        vm.deal(victim, 10 ether);
        vm.startPrank(victim);
        vault.deposit{value: 10 ether}(10 ether, victim);
        vm.stopPrank();

        // attacker front-runs: deposits 5 ETH at the manipulated rate
        vm.deal(address(attacker), 5 ether);
        attacker.frontRunDeposit(5 ether);

        // share price moved mid-transaction -> front-runnable conversion rate
        assertGt(vault.convertToAssets(1 ether), 1 ether, "conversion rate manipulable");

        // fresh 1 ETH deposit mints less than 1 share (dilution loss)
        vm.deal(address(this), 2 ether);
        uint256 shares = vault.deposit{value: 1 ether}(1 ether, address(this));
        assertLt(shares, 1 ether, "deposit diluted");

        // and a 1-wei deposit rounds to exactly 0 shares (rounding theft)
        uint256 weiShares = vault.deposit{value: 1}(1, address(this));
        assertEq(weiShares, 0, "rounding captures the deposit");
    }
}
