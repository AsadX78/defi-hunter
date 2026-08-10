// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "forge-std/Test.sol";

interface IERC20 {
    function totalSupply() external view returns (uint256);
    function balanceOf(address) external view returns (uint256);
    function symbol() external view returns (string memory);
    function decimals() external view returns (uint8);
    function transfer(address to, uint256 amount) external returns (bool);
}

contract SkyMoneyForkTest is Test {
    IERC20 public constant USDS = IERC20(0xdC035D45d973E3EC169d2276DDab16f1e407384F);
    IERC20 public constant SKY  = IERC20(0x56072C95FAA701256059aa122697B133aDEd9279);
    IERC20 public constant sDAI = IERC20(0x83F20F44975D03b1b09e64809B757c47f942BEeA);
    
    address public constant ATTACKER = address(0xBAD);
    address public constant VICTIM = address(0xF00);
    
    event Result(string name, uint256 value);
    
    function setUp() public {
        vm.deal(ATTACKER, 1000 ether);
        vm.deal(VICTIM, 1000 ether);
    }
    
    function testForkIsLive() public {
        assertGt(block.number, 20000000);
    }
    
    function testReadAllTokens() public {
        emit Result("USDS totalSupply", USDS.totalSupply());
        emit Result("SKY totalSupply", SKY.totalSupply());
        emit Result("sDAI totalSupply", sDAI.totalSupply());
        
        assertGt(USDS.totalSupply(), 0);
        assertGt(SKY.totalSupply(), 0);
    }
    
    function testUSDSInfo() public {
        string memory sym = USDS.symbol();
        uint8 dec = USDS.decimals();
        emit Result("USDS decimals", uint256(dec));
        assertEq(dec, 18);
    }
}
