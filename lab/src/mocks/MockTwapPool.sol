// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./MockERC20.sol";

/**
 * @title MockTwapPool
 * @notice VULNERABLE TWAP oracle — window is extremely short and price is
 *         recorded on every swap, so a single large swap dominates the average.
 * @dev Demonstrates twap_manipulation: flash-borrow -> swap -> oracle moves.
 */
contract MockTwapPool {
    MockERC20 public token0;
    MockERC20 public token1;

    uint256 public reserve0;
    uint256 public reserve1;

    // VULN: window too short — 60 seconds of recordable prices
    uint256 public constant WINDOW = 60;

    uint256[] internal priceHistory; // token1 price per recorded second
    uint256 internal lastRecorded;

    event Sync(uint256 r0, uint256 r1);

    constructor(address _token0, address _token1) {
        token0 = MockERC20(_token0);
        token1 = MockERC20(_token1);
    }

    function sync() external {
        reserve0 = token0.balanceOf(address(this));
        reserve1 = token1.balanceOf(address(this));
        _record(reserve1 * 1e18 / reserve0); // price of token1 in token0
    }

    // swap token0 -> token1 (attacker swaps t0 to get t1, moving the price)
    function swap0To1(uint256 amountIn) external {
        uint256 _r0 = token0.balanceOf(address(this));
        uint256 _r1 = token1.balanceOf(address(this));

        token0.transferFrom(msg.sender, address(this), amountIn);
        uint256 effectiveIn = amountIn * 997 / 1000;
        uint256 amountOut = _r1 - (_r0 * _r1) / (_r0 + effectiveIn);

        token1.transfer(msg.sender, amountOut);
        reserve0 = token0.balanceOf(address(this));
        reserve1 = token1.balanceOf(address(this));
        _record(reserve1 * 1e18 / reserve0);
    }

    // swap token1 -> token0 (inflates the price of token1 in token0)
    function swap1To0(uint256 amountIn) external {
        uint256 _r0 = token0.balanceOf(address(this));
        uint256 _r1 = token1.balanceOf(address(this));

        token1.transferFrom(msg.sender, address(this), amountIn);
        uint256 effectiveIn = amountIn * 997 / 1000;
        uint256 amountOut = _r0 - (_r0 * _r1) / (_r1 + effectiveIn);

        token0.transfer(msg.sender, amountOut);
        reserve0 = token0.balanceOf(address(this));
        reserve1 = token1.balanceOf(address(this));
        _record(reserve1 * 1e18 / reserve0);
    }

    function _record(uint256 price) internal {
        if (block.timestamp > lastRecorded) {
            priceHistory.push(price);
            lastRecorded = block.timestamp;
        } else {
            if (priceHistory.length > 0) priceHistory[priceHistory.length - 1] = price;
        }
    }

    // VULN: short-window average = manipulable
    function consult(address, uint256 amountIn) external view returns (uint256) {
        uint256 n = priceHistory.length;
        require(n > 0, "no data");
        uint256 take = n < WINDOW ? n : WINDOW;
        uint256 sum;
        for (uint256 i = n - take; i < n; i++) {
            sum += priceHistory[i];
        }
        return sum * amountIn / take / 1e18;
    }

    function getReserves() external view returns (uint256, uint256) {
        return (reserve0, reserve1);
    }
}
