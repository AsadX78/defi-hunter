// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title FlashLoanPool
 * @notice A lending pool with flash loan and price oracle vulnerabilities
 */
contract FlashLoanPool {
    mapping(address => uint256) public deposits;
    mapping(address => uint256) public borrows;
    mapping(address => mapping(address => uint256)) public collateral;
    
    // VULNERABLE: Single-asset price oracle (spot price)
    address public tokenA;
    address public tokenB;
    uint256 public rateA = 1 ether;  // 1:1 initial rate
    uint256 public rateB = 1 ether;
    
    uint256 public constant COLLATERAL_RATIO = 1.5 ether; // 150%
    uint256 public totalLiquidity;

    event Deposited(address indexed user, uint256 amount);
    event Borrowed(address indexed user, address token, uint256 amount);
    event FlashLoan(address indexed receiver, address token, uint256 amount, uint256 fee);

    constructor(address _tokenA, address _tokenB) {
        tokenA = _tokenA;
        tokenB = _tokenB;
    }

    function deposit() external payable {
        require(msg.value > 0);
        deposits[msg.sender] += msg.value;
        totalLiquidity += msg.value;
        emit Deposited(msg.sender, msg.value);
    }

    // VULNERABLE: Flash loan with no callback validation
    function flashLoan(address token, uint256 amount, address receiver) external {
        require(amount <= totalLiquidity, "Insufficient liquidity");
        uint256 fee = amount * 5 / 1000; // 0.5% fee
        
        // Send tokens first
        totalLiquidity -= amount;
        payable(receiver).transfer(amount);
        
        // ❌ VULNERABILITY: No validation that receiver pays back!
        // In real protocol, receiver would be a contract with onFlashLoan()
        
        // Check repayment (but receiver could be EOA that just keeps it)
        require(totalLiquidity + amount + fee >= totalLiquidity, "Not repaid");
        
        emit FlashLoan(receiver, token, amount, fee);
    }

    // VULNERABLE: Price can be manipulated via large swap
    function updatePrice(uint256 newRateA, uint256 newRateB) external {
        // ❌ VULNERABILITY: No access control, anyone can set price
        rateA = newRateA;
        rateB = newRateB;
    }

    // VULNERABLE: Borrow against manipulated collateral
    function borrow(address token, uint256 amount) external {
        uint256 collateralValue = collateral[msg.sender][token] * rateA / 1e18;
        uint256 borrowValue = amount * rateB / 1e18;
        
        // ❌ VULNERABILITY: Uses manipulatable price
        require(collateralValue * 100 >= borrowValue * 150, "Insufficient collateral");
        
        borrows[msg.sender] += amount;
        totalLiquidity -= amount;
        payable(msg.sender).transfer(amount);
        
        emit Borrowed(msg.sender, token, amount);
    }

    function addCollateral(address token, uint256 amount) external payable {
        collateral[msg.sender][token] += msg.value;
    }

    receive() external payable {}
}
