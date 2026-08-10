// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/MockSUsds.sol";

contract InflationAttackTest is Test {
    MockSUsds public susds;
    address public attacker = address(0x1);
    address public victim = address(0x2);
    address public admin = address(0x3);
    
    function setUp() public {
        susds = new MockSUsds(address(0x0));
        vm.deal(attacker, 100 ether);
        vm.deal(victim, 100 ether);
    }
    
    function testFirstDepositInflation() public {
        // Step 1: Attacker deposits 1 wei to be the first depositor
        vm.prank(attacker);
        susds.deposit(1, attacker);
        uint256 attackerShares = susds.balanceOf(attacker);
        assertEq(attackerShares, 1);
        
        // Step 2: Attacker manipulates price by being first donor
        // In ERC4626-style: donate assets to inflate share price
        // Here we simulate by having admin set high SSR
        vm.prank(address(this));
        susds.rely(admin);
        vm.prank(admin);
        susds.file("ssr", 1000 * 1e27);
        
        // Step 3: Advance time so drip applies
        vm.warp(block.timestamp + 365 days);
        
        // Step 4: Attacker calls drip to accumulate yield
        susds.drip();
        
        // Step 5: Victim deposits after price manipulation
        vm.prank(victim);
        susds.deposit(1 ether, victim);
        
        // Attacker should have same shares but worth more due to inflation
        uint256 attackerAssets = susds.convertToAssets(susds.balanceOf(attacker));
        assertGt(attackerAssets, 1); // More than original 1 wei
    }
    
    function testAdminSsrManipulation() public {
        // Admin can set arbitrary SSR
        vm.prank(address(this));
        susds.rely(admin);
        vm.prank(admin);
        susds.file("ssr", 1000000 * 1e27);
        assertEq(susds.ssr(), 1000000 * 1e27);
    }
    
    function testDripAccumulatesYield() public {
        // Deposit first
        vm.prank(attacker);
        susds.deposit(1 ether, attacker);
        
        // Set high SSR
        vm.prank(address(this));
        susds.rely(admin);
        vm.prank(admin);
        susds.file("ssr", 2 * 1e27); // 100% APR
        
        // Advance time
        vm.warp(block.timestamp + 365 days);
        
        // Drip accumulates yield
        uint256 chiBefore = susds.chi();
        susds.drip();
        uint256 chiAfter = susds.chi();
        
        // Chi should have increased
        assertGt(chiAfter, chiBefore);
    }
}
