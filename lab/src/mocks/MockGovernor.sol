// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./MockVoteToken.sol";

/**
 * @title MockGovernor
 * @notice VULNERABLE governor — votes are counted at proposal/vote time
 *         (no snapshot), there is no timelock, and execution failures are ignored.
 * @dev Matches the template IGovernor interface (propose/castVote/queue/execute).
 */
contract MockGovernor {
    MockVoteToken public token;

    struct Proposal {
        bool exists;
        bool passed;
        bool queued;
        bool executed;
        address target;
        bytes calldataData;
    }

    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;
    uint256 public executedCount;

    event ProposalCreated(uint256 indexed id, address indexed proposer);
    event VoteCast(uint256 indexed id, address indexed voter, uint256 power);
    event ProposalExecuted(uint256 indexed id);

    constructor(address _token) {
        token = MockVoteToken(_token);
    }

    // VULN: checks votes NOW, not at snapshot block
    function propose(
        address[] memory targets,
        uint256[] memory,
        bytes[] memory calldatas,
        string memory
    ) external returns (uint256 id) {
        require(token.getVotes(msg.sender) > 0, "no voting power");
        require(targets.length > 0 && calldatas.length > 0, "bad proposal");
        id = ++proposalCount;
        proposals[id] = Proposal({
            exists: true,
            passed: false,
            queued: false,
            executed: false,
            target: targets[0],
            calldataData: calldatas[0]
        });
        emit ProposalCreated(id, msg.sender);
    }

    // VULN: votes counted with flash-loaned power
    function castVote(uint256 id, bool support) external {
        require(proposals[id].exists, "no proposal");
        require(token.getVotes(msg.sender) > 0, "no voting power");
        proposals[id].passed = support;
        emit VoteCast(id, msg.sender, token.getVotes(msg.sender));
    }

    // VULN: no timelock between vote and execution
    function queue(uint256 id) external {
        require(proposals[id].exists, "no proposal");
        require(proposals[id].passed, "not passed");
        proposals[id].queued = true;
    }

    function execute(uint256 id) external {
        require(proposals[id].exists, "no proposal");
        require(proposals[id].queued, "not queued");
        proposals[id].executed = true;
        executedCount++;
        emit ProposalExecuted(id);
        // VULN: ignores execution failure
        (bool ok,) = proposals[id].target.call(proposals[id].calldataData);
        ok; // silence unused warning
    }
}
