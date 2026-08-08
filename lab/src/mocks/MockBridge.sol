// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockBridge
 * @notice VULNERABLE bridge — mints wrapped tokens without verifying the
 *         origin-chain deposit proof (no signatures, no oracle).
 * @dev Matches the template IBridge interface (bridge_deposit_spoof).
 */
contract MockBridge {
    string public name = "Mock Wrapped";
    string public symbol = "mW";
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    uint256 public constant BRIDGE_FEE = 1 ether / 1000; // 0.1%
    mapping(bytes32 => bool) public usedProofs;

    event Mint(address indexed to, uint256 amount);
    event Burn(address indexed from, uint256 amount);

    // VULNERABLE: proof is only checked for uniqueness, NOT validity.
    // An attacker can fabricate any bytes32 and mint wrapped tokens.
    function finalizeDeposit(bytes calldata proof) external returns (uint256 minted) {
        bytes32 digest = keccak256(proof);
        require(!usedProofs[digest], "proof reused");
        usedProofs[digest] = true;

        // "decode" a made-up deposit amount from the proof
        minted = uint256(digest) % (10_000 ether) + 1 ether;
        balanceOf[msg.sender] += minted;
        totalSupply += minted;
        emit Mint(msg.sender, minted);
    }

    // VULNERABLE: mint is callable by anyone (should be bridge-only)
    function mint(address to, uint256 amount) external {
        balanceOf[to] += amount;
        totalSupply += amount;
        emit Mint(to, amount);
    }

    function burn(uint256 amount) external {
        balanceOf[msg.sender] -= amount;
        totalSupply -= amount;
        emit Burn(msg.sender, amount);
    }

    function isValidProof(bytes calldata proof) external pure returns (bool) {
        return proof.length > 0; // VULNERABLE: accepts anything non-empty
    }
}
