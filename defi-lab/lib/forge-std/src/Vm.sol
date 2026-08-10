// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

interface Vm {
    function deal(address, uint256) external;
    function prank(address) external;
    function startPrank(address) external;
    function stopPrank() external;
    function warp(uint256) external;
    function roll(uint256) external;
    function fee(uint256) external;
    function chainId(uint256) external;
    function coinbase(address) external;
    function load(address, bytes32) external view returns (bytes32);
    function store(address, bytes32, bytes32) external;
    function sign(uint256, bytes32) external pure returns (uint8, bytes32, bytes32);
    function addr(uint256) external pure returns (address);
    function assume(bool) external;
    function ffi(string[] calldata) external returns (bytes memory);
    function rpc(string calldata, string calldata) external returns (bytes memory);
    function createSelectFork(string calldata) external returns (uint256);
    function selectFork(uint256) external;
    function activeFork() external view returns (uint256);
    function makeAddr(string calldata) external returns (address);
    function broadcast() external;
    function broadcast(address) external;
    function startBroadcast() external;
    function startBroadcast(address) external;
    function stopBroadcast() external;
    function getCode(string calldata) external view returns (bytes memory);
    function getDeployedCode(string calldata) external view returns (bytes memory);
    function readFile(string calldata) external view returns (string memory);
    function readLine(string calldata) external returns (string memory);
    function writeFile(string calldata, string calldata) external;
    function toString(address) external pure returns (string memory);
    function toString(bytes32) external pure returns (string memory);
    function toString(uint256) external pure returns (string memory);
    function toString(int256) external pure returns (string memory);
    function toString(bool) external pure returns (string memory);
    function toString(bytes calldata) external pure returns (string memory);
}
