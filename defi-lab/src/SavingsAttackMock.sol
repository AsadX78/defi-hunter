// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title SavingsAttackMock
 * @notice ERC-4626 style vault vulnerable to inflation attack
 * @dev Simplified to demonstrate the attack clearly
 */
contract SavingsAttackMock {
    string public name = "Savings USDS";
    string public symbol = "sUSDS";
    
    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;
    
    uint256 public constant RAY = 1e27;
    uint192 public chi;
    uint64 public rho;
    uint256 public ssr;
    address public admin;
    
    event Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed sender, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);
    event File(bytes32 indexed what, uint256 data);
    
    constructor(address _vow) {
        chi = uint192(RAY);
        rho = uint64(block.timestamp);
        ssr = RAY;
        admin = msg.sender;
    }
    
    function deposit(uint256 assets, address receiver) external payable returns (uint256 shares) {
        uint256 bal = address(this).balance;
        if (totalSupply == 0 || bal == 0) {
            shares = assets;
        } else {
            // shares = assets * totalSupply / totalAssets
            shares = assets * totalSupply / bal;
        }
        balanceOf[receiver] += shares;
        totalSupply += shares;
        emit Deposit(msg.sender, receiver, assets, shares);
    }
    
    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares) {
        uint256 bal = address(this).balance;
        if (totalSupply == 0) {
            shares = 0;
        } else {
            // shares = assets * totalSupply / totalAssets
            shares = assets * totalSupply / bal;
        }
        balanceOf[owner] -= shares;
        totalSupply -= shares;
        (bool ok, ) = receiver.call{value: assets}("");
        require(ok);
        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }
    
    function file(bytes32 what, uint256 data) external {
        require(msg.sender == admin, "not-admin");
        if (what == "ssr") {
            ssr = data;
        }
        emit File(what, data);
    }
    
    receive() external payable {}
}
