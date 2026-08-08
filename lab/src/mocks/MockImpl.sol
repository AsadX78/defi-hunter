// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockImpl
 * @notice Innocent-looking implementation used as the malicious upgrade target.
 */
contract MockImpl {
    uint256 public value;
    address public owner;

    function initialize(address _owner) external {
        owner = _owner;
    }

    function setValue(uint256 v) external {
        require(msg.sender == owner, "not owner");
        value = v;
    }
}
