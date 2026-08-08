// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockVulnerableVault.sol";
import "../src/attacks/reentrancy_attack.sol";

/**
 * @title ReentrancyAttackTest
 * @notice Proves the `reentrancy_attack` template: withdraw sends ETH before
 *         zeroing the balance, so the attacker's fallback re-enters and drains
 *         the vault.
 */
contract ReentrancyAttackTest is Test {
    MockVulnerableVault public vault;
    ReentrancyAttack public attacker;

    function setUp() public {
        vault = new MockVulnerableVault();
        attacker = new ReentrancyAttack(address(vault));

        // victims deposit 10 ETH (keeps vault accounting consistent)
        address victim = makeAddr("victim");
        vm.deal(victim, 10 ether);
        vm.startPrank(victim);
        vault.deposit{value: 10 ether}();
        vm.stopPrank();
    }

    function testReentrancyAttack() public {
        vm.deal(address(attacker), 1 ether);
        attacker.attack{value: 1 ether}();

        // Attacker extracted ~10x their deposit (10 ETH of 11 total)
        assertGe(address(attacker).balance, 9 ether, "attacker drained the vault");
        assertLt(address(vault).balance, 2 ether, "vault nearly empty");
    }
}
