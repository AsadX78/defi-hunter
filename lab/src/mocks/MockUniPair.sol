// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./MockERC20.sol";

/**
 * @title MockUniPair
 * @notice Constant-product AMM pair (like UniswapV2) for sandwich tests.
 * @dev Sender must transfer input tokens in BEFORE calling swap (standard V2 flow).
 */
contract MockUniPair {
    MockERC20 public token0;
    MockERC20 public token1;
    uint256 public reserve0;
    uint256 public reserve1;

    constructor(address _token0, address _token1) {
        token0 = MockERC20(_token0);
        token1 = MockERC20(_token1);
    }

    function getReserves() external view returns (uint256, uint256) {
        return (reserve0, reserve1);
    }

    function sync() external {
        reserve0 = token0.balanceOf(address(this));
        reserve1 = token1.balanceOf(address(this));
    }

    function swap(uint256 amount0Out, uint256 amount1Out, address to) external {
        require(amount0Out > 0 || amount1Out > 0, "no output");
        // snapshot from stored reserves (UniswapV2 semantics)
        uint256 _r0 = reserve0;
        uint256 _r1 = reserve1;

        if (amount0Out > 0) token0.transfer(to, amount0Out);
        if (amount1Out > 0) token1.transfer(to, amount1Out);

        uint256 b0 = token0.balanceOf(address(this));
        uint256 b1 = token1.balanceOf(address(this));
        uint256 amt0In = b0 > (_r0 - amount0Out) ? b0 - (_r0 - amount0Out) : 0;
        uint256 amt1In = b1 > (_r1 - amount1Out) ? b1 - (_r1 - amount1Out) : 0;
        require(amt0In > 0 || amt1In > 0, "no input");

        // constant product with 0.3% fee
        uint256 balance0Adjusted = b0 * 1000 - amt0In * 3;
        uint256 balance1Adjusted = b1 * 1000 - amt1In * 3;
        require(balance0Adjusted * balance1Adjusted >= _r0 * _r1 * 1_000_000, "K");

        reserve0 = b0;
        reserve1 = b1;
    }
}
