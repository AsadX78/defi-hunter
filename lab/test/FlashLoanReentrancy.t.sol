// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockRebaseToken.sol";
import "../src/mocks/MockTokenPool.sol";
import "../src/attacks/flash_loan_reentrancy.sol";

/**
 * @title FlashLoanReentrancyTest
 * @notice Proves the `flash_loan_reentrancy` template inline: the flash loan
 *         provides the capital, and the ERC777-style transfer hook lets the
 *         attacker re-enter withdraw() before the pool updates balances.
 */
contract FlashLoanReentrancyTest is Test {
    MockRebaseToken public token;
    MockTokenPool public pool;
    FlashLoanReentrancy public attacker;

    function setUp() public {
        token = new MockRebaseToken();
        pool = new MockTokenPool(address(token));
        attacker = new FlashLoanReentrancy(address(pool), address(token));

        // victim deposited 1000 tokens
        token.mint(address(this), 1000 ether);
        token.approve(address(pool), type(uint256).max);
        pool.deposit(address(token), 1000 ether);
    }

    function testFlashLoanReentrancy() public {
        attacker.attack(100 ether);

        // attacker net profit after repaying the 100 flash loan
        assertGt(token.balanceOf(address(attacker)), 300 ether, "drained pool via reentrancy");
        // victim's funds lost
        assertLt(token.balanceOf(address(pool)), 1000 ether, "pool lost funds");
    }
}
