// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./MockERC20.sol";

/**
 * @title MockLending
 * @notice VULNERABLE lending protocol — collateral price is set by anyone
 *         (no access control on updatePrice) and health factor is computed
 *         from that manipulable price.
 * @dev Covers oracle_manipulation and liquidation_sandwich.
 *      Matches the template ILiquidator interface
 *      (liquidate(address,uint256,address,address), getAccountHealth(address)).
 */
contract MockLending {
    address public tokenA; // collateral asset
    address public tokenB; // debt asset

    // VULN: prices are single-source and writable by anyone
    uint256 public rateA = 1 ether;
    uint256 public rateB = 1 ether;

    mapping(address => mapping(address => uint256)) public collateral;
    mapping(address => uint256) public debt;
    uint256 public totalLiquidity;
    uint256 public constant BONUS = 1100; // 10% liquidation bonus (basis points *10)

    event PriceUpdated(uint256 rateA, uint256 rateB);
    event Liquidated(address indexed liquidator, address indexed borrower, uint256 repay, uint256 seized);

    constructor(address _tokenA, address _tokenB) {
        tokenA = _tokenA;
        tokenB = _tokenB;
    }

    // VULN: anyone can move the price
    function updatePrice(uint256 newRateA, uint256 newRateB) external {
        rateA = newRateA;
        rateB = newRateB;
        emit PriceUpdated(newRateA, newRateB);
    }

    function depositCollateral(address token, uint256 amount) external {
        MockERC20(token).transferFrom(msg.sender, address(this), amount);
        collateral[msg.sender][token] += amount;
    }

    function borrow(address debtToken, uint256 amount) external {
        require(debtToken == tokenB, "wrong debt token");
        require(collateralValue(msg.sender) * 100 >= amount * 150, "insufficient collateral");
        debt[msg.sender] += amount;
        MockERC20(debtToken).transfer(msg.sender, amount);
    }

    function repay(address debtToken, uint256 amount) external {
        MockERC20(debtToken).transferFrom(msg.sender, address(this), amount);
        debt[msg.sender] -= amount;
        totalLiquidity += amount;
    }

    function getAccountHealth(address account) public view returns (uint256) {
        uint256 cv = collateralValue(account);
        uint256 dv = debt[account];
        if (dv == 0) return type(uint256).max;
        return cv * 1e18 / dv;
    }

    function collateralValue(address account) public view returns (uint256) {
        return collateral[account][tokenA] * rateA / 1e18;
    }

    // liquidate: repay debt, seize collateral + bonus
    function liquidate(address borrower, uint256 repayAmount, address collateralAsset, address debtAsset) external {
        require(collateralAsset == tokenA && debtAsset == tokenB, "wrong assets");
        require(getAccountHealth(borrower) < 1e18, "not liquidatable");
        require(debt[borrower] >= repayAmount, "repay exceeds debt");

        MockERC20(debtAsset).transferFrom(msg.sender, address(this), repayAmount);
        debt[borrower] -= repayAmount;

        uint256 seized = repayAmount * BONUS / 1000 * 1e18 / rateA;
        require(collateral[borrower][collateralAsset] >= seized, "not enough collateral");
        collateral[borrower][collateralAsset] -= seized;
        collateral[msg.sender][collateralAsset] += seized;

        emit Liquidated(msg.sender, borrower, repayAmount, seized);
    }
}
