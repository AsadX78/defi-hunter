// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockSavingsVault.sol";
import "../src/attacks/admin_ssr_manipulation.sol";

/**
 * @title AdminSsrManipulationTest
 * @notice Proves the `admin_ssr_manipulation` template: a compromised admin
 *         sets an extreme savings rate and drips the entire vault to the vow.
 */
contract AdminSsrManipulationTest is Test {
    MockSavingsVault public vault;
    AdminAttack public attacker;
    address public attackerEoa;
    address public admin;

    function setUp() public {
        attackerEoa = makeAddr("attacker");
        admin = makeAddr("admin");
        vault = new MockSavingsVault(attackerEoa); // vow = attacker
        attacker = new AdminAttack(address(vault));
        // grant the attack contract admin (ward) powers
        vault.rely(address(attacker));

        // victims deposited 10 ETH
        vm.deal(address(vault), 10 ether);
    }

    function testAdminSsrManipulation() public {
        // Compromised admin key drives the attack contract
        vm.prank(admin);
        attacker.attack();

        // Entire vault drained to the attacker-controlled vow
        assertEq(attackerEoa.balance, 10 ether, "vault drained to vow");
        assertEq(address(vault).balance, 0, "vault empty");
    }
}
