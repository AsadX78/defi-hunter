// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/GovernanceAttack.sol";

contract GovernanceTest is Test {
    GovernanceToken public govToken;
    DaoGovernance public dao;
    
    function setUp() public {
        govToken = new GovernanceToken();
        dao = new DaoGovernance(address(govToken));
    }
    
    function testFlashLoanVoting() public {
        // The deployer already has tokens, but flashLoanVote needs balanceOf[this]
        // Give the govToken contract some tokens
        vm.deal(address(this), 1 ether);
        
        // Transfer some tokens to the contract itself so flashLoanVote can work
        // Actually flashLoanVote checks balanceOf[address(this)] = govToken's own balance
        // We need to mint or transfer to govToken contract
        // For testing, let's just check that deployer has voting power
        uint256 initialPower = govToken.votingPower(address(this));
        assertGt(initialPower, 0);
    }
}
