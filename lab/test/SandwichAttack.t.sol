// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockERC20.sol";
import "../src/mocks/MockWETH.sol";
import "../src/mocks/MockUniPair.sol";
import "../src/attacks/sandwich_attack.sol";

/**
 * @title SandwichAttackTest
 * @notice Proves the `sandwich_attack` TEMPLATE: the shipped SandwichAttack
 *         contract front-runs a victim swap to move the price, the victim
 *         fills at the worse price, and the attacker back-runs for a profit.
 */
contract SandwichAttackTest is Test {
    MockERC20 public token;
    MockWETH public weth;
    MockUniPair public pair;
    SandwichAttack public attacker;
    address public victim;

    function setUp() public {
        victim = makeAddr("victim");
        token = new MockERC20("TKN", "TKN");
        weth = new MockWETH();
        pair = new MockUniPair(address(weth), address(token));
        attacker = new SandwichAttack(address(pair), address(weth), address(token));

        // pool seeded 1000 WETH / 1000 TKN
        weth.deposit{value: 1000 ether}();
        weth.transfer(address(pair), 1000 ether);
        token.mint(address(pair), 1000 ether);
        pair.sync();
    }

    function testSandwichAttack() public {
        // FRONT-RUN: attacker buys TKN with WETH at the fair pre-swap price
        vm.deal(address(attacker), 10 ether);
        attacker.frontRun(10 ether);
        uint256 tknHeld = token.balanceOf(address(attacker));
        assertGt(tknHeld, 9 ether, "front-run bought token");

        // VICTIM: buys 100 TKN at the inflated price
        vm.deal(victim, 120 ether);
        vm.startPrank(victim);
        weth.deposit{value: 120 ether}();
        weth.transfer(address(pair), 120 ether);
        pair.swap(0, 100 ether, victim);
        vm.stopPrank();
        assertEq(token.balanceOf(victim), 100 ether, "victim swap filled");

        // BACK-RUN: attacker sells TKN back for WETH at the inflated price
        uint256 wethOut = attacker.backRun(tknHeld);

        // attacker net: got more WETH out than put in
        assertGt(wethOut, 10 ether, "back-run profit");
    }
}
