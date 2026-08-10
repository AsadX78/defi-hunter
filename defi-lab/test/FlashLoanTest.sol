// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/FlashLoanPool.sol";
import "../src/AttackFlashLoan.sol";

contract FlashLoanTest is Test {
    FlashLoanPool public pool;
    AttackFlashLoan public attacker;
    
    function setUp() public {
        pool = new FlashLoanPool(address(0), address(0));
    }
    
    function testDepositLiquidity() public {
        vm.deal(address(this), 100 ether);
        pool.deposit{value: 100 ether}();
        assertEq(address(pool).balance, 100 ether);
    }
    
    function testPriceManipulation() public {
        vm.deal(address(this), 10 ether);
        pool.deposit{value: 10 ether}();
        
        // Anyone can manipulate price
        pool.updatePrice(100 ether, 1 ether);
        
        // Price is now manipulated
        assertEq(pool.rateA(), 100 ether);
    }
}
