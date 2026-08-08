// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockCrossVault
 * @notice VULNERABLE vault — cross-function reentrancy.
 * @dev withdrawBalance() sends ETH BEFORE zeroing the balance (violates
 *      Checks-Effects-Interactions), and transferBalance() is unprotected.
 *      An attacker re-enters transferBalance() from their receive() hook,
 *      moving the still-counted balance to a second account, then
 *      withdrawBalance() zeroes the original — value created from thin air.
 */
contract MockCrossVault {
    mapping(address => uint256) public balanceOf;
    uint256 public totalDeposits;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);
    event Transfer(address indexed from, address indexed to, uint256 amount);

    function deposit() external payable {
        balanceOf[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    function transferBalance(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount, "insufficient balance");
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        emit Transfer(msg.sender, to, amount);
    }

    // VULNERABLE: external call before state update
    function withdrawBalance() external {
        uint256 amount = balanceOf[msg.sender];
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balanceOf[msg.sender] = 0;
        totalDeposits -= amount;
        emit Withdrawal(msg.sender, amount);
    }

    receive() external payable {}
}
