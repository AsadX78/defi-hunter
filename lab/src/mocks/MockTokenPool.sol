// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./MockRebaseToken.sol";

/**
 * @title MockTokenPool
 * @notice VULNERABLE lending pool — withdraw sends tokens via an ERC777-style
 *         token whose transfer hook re-enters before the user balance is
 *         updated (Checks-Effects-Interactions violated).
 * @dev Demonstrates flash_loan_reentrancy. Matches the template IPool
 *      interface (deposit / withdraw / flashLoan).
 */
contract MockTokenPool {
    MockRebaseToken public token;
    mapping(address => uint256) public deposits;
    uint256 public totalLiquidity;

    event Deposited(address indexed user, uint256 amount);
    event Withdrawn(address indexed user, uint256 amount);
    event FlashLoan(address indexed receiver, uint256 amount);

    constructor(address _token) {
        token = MockRebaseToken(_token);
    }

    function deposit(address _token, uint256 amount) external {
        require(_token == address(token), "wrong token");
        token.transferFrom(msg.sender, address(this), amount);
        deposits[msg.sender] += amount;
        totalLiquidity += amount;
        emit Deposited(msg.sender, amount);
    }

    // VULN: external call (token transfer -> hook) BEFORE state update
    function withdraw(address _token, uint256 amount) external {
        require(_token == address(token), "wrong token");
        // NOTE: balance not decremented before the external transfer
        token.transfer(msg.sender, amount); // re-enters via tokensReceived
        // state update AFTER external call (clamped so recursion does not
        // panic on underflow — the accounting flaw is the point)
        deposits[msg.sender] = deposits[msg.sender] >= amount ? deposits[msg.sender] - amount : 0;
        totalLiquidity = totalLiquidity >= amount ? totalLiquidity - amount : 0;
        emit Withdrawn(msg.sender, amount);
    }

    // ERC777-style receiver — required so the token hook can fire on the pool
    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external pure {}

    function flashLoan(address receiver, address _token, uint256 amount, bytes calldata) external {
        require(_token == address(token), "wrong token");
        uint256 actual = amount == type(uint256).max ? token.balanceOf(address(this)) : amount;
        require(actual <= totalLiquidity, "insufficient liquidity");

        token.transfer(receiver, actual);

        bytes4 sel = bytes4(keccak256("onFlashLoan(address,uint256,bytes)"));
        (bool ok,) = receiver.call(abi.encodeWithSelector(sel, address(token), actual, ""));
        require(ok, "callback reverted");

        require(token.balanceOf(address(this)) >= actual, "not repaid");
        emit FlashLoan(receiver, actual);
    }
}
