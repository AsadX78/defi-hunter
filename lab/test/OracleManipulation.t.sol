// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockERC20.sol";
import "../src/mocks/MockLending.sol";
import "../src/attacks/oracle_manipulation.sol";

/**
 * @title OracleManipulationTest
 * @notice Proves the `oracle_manipulation` TEMPLATE: the shipped OracleAttack
 *         contract deposits collateral, inflates the single writable price,
 *         and borrows more than legitimately possible.
 */
contract OracleManipulationTest is Test {
    MockERC20 public col;
    MockERC20 public debt;
    MockLending public lending;
    OracleAttack public attacker;

    function setUp() public {
        col = new MockERC20("COL", "COL");
        debt = new MockERC20("DEBT", "DEBT");
        lending = new MockLending(address(col), address(debt));
        attacker = new OracleAttack(address(lending), address(col), address(debt));

        debt.mint(address(lending), 100_000 ether);
        col.mint(address(attacker), 100 ether);
    }

    function testOracleManipulation() public {
        // legitimate max borrow at 150% collateral ratio
        uint256 legitMax = uint256(100 ether) * 2 / 3;

        attacker.attack();

        // template borrowed 100 — impossible without the manipulated price
        assertEq(lending.debt(address(attacker)), 100 ether, "over-borrowed");
        assertGt(100 ether, legitMax, "borrowed more than legitimately possible");
        assertEq(lending.collateral(address(attacker), address(col)), 100 ether);
    }
}
