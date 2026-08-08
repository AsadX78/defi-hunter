
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ILiquidator {
    function liquidate(address borrower, uint256 repayAmount, address collateralAsset, address debtAsset) external;
    function getAccountHealth(address account) external view returns (uint256);
}

contract LiquidationSandwich {
    ILiquidator public lending;

    constructor(address _lending) {
        lending = ILiquidator(_lending);
    }

    // In practice: swap to push collateral price down first (lowering health factor)
    function isLiquidatable(address borrower) internal view returns (bool) {
        return lending.getAccountHealth(borrower) < 1e18;
    }

    function liquidate(address borrower, address collateralAsset, address debtAsset, uint256 amount) external {
        // Execute liquidation to claim the bonus
        require(isLiquidatable(borrower), "not liquidatable");
        lending.liquidate(borrower, amount, collateralAsset, debtAsset);
    }
}
