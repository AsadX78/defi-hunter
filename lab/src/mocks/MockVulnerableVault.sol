// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockVulnerableVault
 * @notice Vault with a reentrancy vulnerability — ETH is sent BEFORE the
 *         user balance is zeroed (Checks-Effects-Interactions violated).
 * @dev Matches the template IVault interface (deposit / withdraw / balanceOf).
 */
contract MockVulnerableVault {
    mapping(address => uint256) public balances;
    uint256 public totalDeposits;

    event Deposit(address indexed user, uint256 amount);
    event Withdrawal(address indexed user, uint256 amount);

    function deposit() external payable {
        require(msg.value > 0, "must deposit");
        balances[msg.sender] += msg.value;
        totalDeposits += msg.value;
        emit Deposit(msg.sender, msg.value);
    }

    // VULN: external call BEFORE state update
    function withdraw() external {
        uint256 amount = balances[msg.sender];
        require(amount > 0, "no balance");

        (bool ok,) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");

        balances[msg.sender] = 0;
        totalDeposits -= amount;
        emit Withdrawal(msg.sender, amount);
    }

    function balanceOf(address who) external view returns (uint256) {
        return balances[who];
    }

    receive() external payable {}
}
