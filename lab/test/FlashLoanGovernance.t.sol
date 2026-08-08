// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";
import "../src/mocks/MockVoteToken.sol";
import "../src/mocks/MockGovernor.sol";
import "../src/mocks/MockFlashLender.sol";
import "../src/attacks/flash_loan_governance.sol";

/**
 * @title FlashLoanGovernanceTest
 * @notice Proves the `flash_loan_governance` template: a flash loan of the
 *         entire token supply gives instant voting power (no snapshots), so
 *         the attacker passes and executes a proposal in one transaction.
 */
contract FlashLoanGovernanceTest is Test {
    MockVoteToken public token;
    MockFlashLender public lender;
    MockGovernor public gov;
    GovernanceAttack public attacker;

    function setUp() public {
        token = new MockVoteToken();
        lender = new MockFlashLender(address(token));
        gov = new MockGovernor(address(token));
        attacker = new GovernanceAttack(address(lender), address(gov), address(token));

        // the protocol treasury holds all voting tokens
        token.mint(address(lender), 1_000_000 ether);
    }

    function testFlashLoanGovernance() public {
        attacker.attack();

        // proposal was executed using borrowed voting power
        assertEq(gov.executedCount(), 1, "malicious proposal executed");
        // flash loan repaid in the same transaction
        assertEq(token.balanceOf(address(lender)), 1_000_000 ether, "loan repaid");
    }
}
