// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockPermitToken
 * @notice VULNERABLE EIP-2612 token — the EIP-712 domain separator OMITS
 *         chainId, so a permit signature is valid on every chain the same
 *         address holds tokens.
 * @dev Matches the template IERC20Permit interface (permit / transferFrom).
 */
contract MockPermitToken {
    string public name = "Mock Permit Token";
    string public symbol = "mPERMIT";
    uint8 public decimals = 18;

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public nonces;

    bytes32 public constant PERMIT_TYPEHASH =
        keccak256("Permit(address owner,address spender,uint256 value,uint256 nonce,uint256 deadline)");

    // VULN: no chainId in the domain — signature replayable cross-chain
    bytes32 public constant DOMAIN_SEPARATOR = keccak256(
        abi.encode(
            keccak256("EIP712Domain(string name,string version)"),
            keccak256(bytes("MockPermitToken")),
            keccak256(bytes("1"))
        )
    );

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
        return true;
    }

    function transferFrom(address from, address to, uint256 amount) external returns (bool) {
        allowance[from][msg.sender] -= amount;
        balanceOf[from] -= amount;
        balanceOf[to] += amount;
        return true;
    }

    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external {
        require(block.timestamp <= deadline, "permit expired");
        bytes32 structHash = keccak256(
            abi.encode(PERMIT_TYPEHASH, owner, spender, value, nonces[owner]++, deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", DOMAIN_SEPARATOR, structHash));
        address signer = ecrecover(digest, v, r, s);
        require(signer == owner, "invalid signature");
        allowance[owner][spender] = value;
    }

    function domainSeparator() external pure returns (bytes32) {
        return DOMAIN_SEPARATOR;
    }
}
