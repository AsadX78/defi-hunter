// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockDelegateProxy
 * @notice VULNERABLE proxy — unauthenticated setImplementation().
 * @dev The fallback delegatecalls the implementation with the caller's
 *      calldata. Anyone can repoint the implementation, so an attacker can
 *      execute arbitrary code in the proxy's storage and ETH context.
 */
contract MockDelegateProxy {
    address public implementation;

    // VULNERABLE: no access control
    function setImplementation(address impl) external {
        implementation = impl;
    }

    function getBalance() external view returns (uint256) {
        return address(this).balance;
    }

    fallback() external payable {
        address impl = implementation;
        require(impl != address(0), "no implementation");
        (bool ok, ) = impl.delegatecall(msg.data);
        require(ok, "delegatecall failed");
    }

    receive() external payable {}
}
