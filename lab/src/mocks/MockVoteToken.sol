// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockVoteToken
 * @notice VULNERABLE governance token — delegation gives IMMEDIATE voting
 *         power (no checkpointing / snapshot).
 * @dev A flash loan that temporarily moves the balance creates instant voting
 *      power, which is exactly what flash_loan_governance exploits.
 *      Matches the template IToken interface (delegate / getVotes / transfer).
 */
contract MockVoteToken {
    string public name = "Mock Governance Token";
    string public symbol = "mGOV";

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => address) public delegateeOf;
    mapping(address => uint256) public votingPower; // VULN: updated immediately

    event DelegateChanged(address indexed delegator, address indexed from, address indexed to);

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        // NOTE: for the exploit we only need delegate() to set power immediately
        return true;
    }

    // VULN: no snapshot — power is live and instant
    function delegate(address delegatee) external {
        address prev = delegateeOf[msg.sender];
        if (prev != address(0)) {
            votingPower[prev] -= balanceOf[msg.sender];
        }
        delegateeOf[msg.sender] = delegatee;
        votingPower[delegatee] += balanceOf[msg.sender];
        emit DelegateChanged(msg.sender, prev, delegatee);
    }

    function getVotes(address account) external view returns (uint256) {
        return votingPower[account];
    }
}
