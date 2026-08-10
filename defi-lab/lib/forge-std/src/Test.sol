// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "./StdAssertions.sol";
import "./StdCheats.sol";
import "./StdError.sol";
import "./StdStorage.sol";
import "./StdStyle.sol";
import "./Vm.sol";

abstract contract Test {
    address private constant VM_ADDRESS = address(uint160(uint256(keccak256("hevm cheat code"))));
    Vm internal constant vm = Vm(VM_ADDRESS);
    
    // Assertions
    function assertEq(uint256 a, uint256 b) internal pure {
        if (a != b) revert("assertion failed");
    }
    
    function assertGt(uint256 a, uint256 b) internal pure {
        if (a <= b) revert("assertion failed");
    }
    
    function assertLt(uint256 a, uint256 b) internal pure {
        if (a >= b) revert("assertion failed");
    }
    
    function assertTrue(bool condition) internal pure {
        if (!condition) revert("assertion failed");
    }
}
