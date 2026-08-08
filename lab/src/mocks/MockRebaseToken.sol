// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockRebaseToken
 * @notice ERC777-style token: every direct transfer() to a contract calls
 *         tokensReceived(...) on the recipient. The transfer hook is what
 *         makes the lending pool's withdraw() re-entrant.
 * @dev transferFrom is deliberately hook-free (keeps the lab test simple).
 */
contract MockRebaseToken {
    string public name = "Mock Rebase Token";
    string public symbol = "mRT";
    uint8 public decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;

    bytes4 internal constant TOKENS_RECEIVED = bytes4(keccak256("tokensReceived(address,address,address,uint256,bytes,bytes)"));

    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
    }

    function approve(address spender, uint256 amount) external returns (bool) {
        allowance[msg.sender][spender] = amount;
        return true;
    }

    function transfer(address to, uint256 amount) external returns (bool) {
        _transfer(msg.sender, to, amount);
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        _transfer(from, to, amount);
        return true;
    }

    function _transfer(address from, address to, uint256 amount) internal {
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        // ERC777-style hook on direct transfer (VULN: reentrancy surface)
        if (msg.sender == from && to.code.length > 0) {
            (bool ok,) = to.call(
                abi.encodeWithSelector(TOKENS_RECEIVED, msg.sender, from, to, amount, "", "")
            );
            require(ok, "tokensReceived failed");
        }
    }
}
