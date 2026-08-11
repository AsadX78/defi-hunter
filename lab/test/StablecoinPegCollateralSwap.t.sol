// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockERC20.sol";
import "../src/mocks/MockStable.sol";
import "../src/attacks/stablecoin_peg_collateral_swap.sol";

/**
 * @title StablecoinPegCollateralSwapTest
 * @notice Proves the `stablecoin_peg_collateral_swap` TEMPLATE: the shipped
 *         PegCollateralSwap contract inflates the collateral price, then
 *         mints more stablecoin than the deposited collateral backs.
 */
contract StablecoinPegCollateralSwapTest is Test {
    MockERC20 public stable;
    MockERC20 public colA;
    MockERC20 public colB;
    MockStable public mstable;
    PegCollateralSwap public attacker;

    function setUp() public {
        stable = new MockERC20("USDS", "USDS");
        colA = new MockERC20("COL-A", "COLA");
        colB = new MockERC20("COL-B", "COLB");
        mstable = new MockStable(address(stable), address(colA), address(colB));
        attacker = new PegCollateralSwap(address(mstable), address(stable), address(colB));

        colB.mint(address(attacker), 1000 ether);
    }

    function testPegAttack() public {
        uint256 minted = attacker.attack();

        // attacker profits 300 stable on a 1000 deposit (and keeps collateral)
        assertEq(minted, 1300 ether, "minted unbacked stablecoin");
        assertEq(stable.balanceOf(address(attacker)), 1300 ether, "attacker holds minted stable");
        assertGt(stable.balanceOf(address(attacker)), 1000 ether, "profit over deposited value");
    }
}
