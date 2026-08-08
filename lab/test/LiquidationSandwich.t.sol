// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockERC20.sol";
import "../src/mocks/MockLending.sol";
import "../src/attacks/liquidation_sandwich.sol";

/**
 * @title LiquidationSandwichTest
 * @notice Proves the `liquidation_sandwich` template: when collateral price
 *         crashes (manipulable feed), the attacker front-runs the liquidation
 *         and captures the 10% bonus.
 */
contract LiquidationSandwichTest is Test {
    MockERC20 public col;
    MockERC20 public debt;
    MockLending public lending;
    LiquidationSandwich public attacker;
    address public borrower;

    function setUp() public {
        borrower = makeAddr("borrower");
        col = new MockERC20("COL", "COL");
        debt = new MockERC20("DEBT", "DEBT");
        lending = new MockLending(address(col), address(debt));
        attacker = new LiquidationSandwich(address(lending));

        // liquidity for the lending pool
        debt.mint(address(lending), 100_000 ether);

        // borrower: 100 collateral, borrows 60 debt (health 1.67)
        vm.startPrank(borrower);
        col.mint(borrower, 100 ether);
        col.approve(address(lending), type(uint256).max);
        lending.depositCollateral(address(col), 100 ether);
        lending.borrow(address(debt), 60 ether);
        vm.stopPrank();
    }

    function testLiquidationSandwich() public {
        // collateral price crashes 70% -> health 0.5 (liquidatable)
        lending.updatePrice(0.3 ether, 1 ether);

        // attacker repays 10 debt with borrowed funds
        debt.mint(address(attacker), 10 ether);
        vm.startPrank(address(attacker));
        debt.approve(address(lending), type(uint256).max);
        vm.stopPrank();

        // run the template exploit
        attacker.liquidate(borrower, address(col), address(debt), 10 ether);

        // attacker captured collateral + 10% bonus (10 debt -> ~36.67 col at 0.3)
        assertGt(lending.collateral(address(attacker), address(col)), 36 ether, "bonus seized");
        assertLt(lending.collateral(borrower, address(col)), 64 ether, "borrower collateral seized");
    }
}
