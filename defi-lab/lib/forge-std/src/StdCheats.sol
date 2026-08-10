// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract StdCheats {
    function deal(address token, address to, uint256 amount) internal {}
    function prank(address msgSender) internal {}
    function startPrank(address msgSender) internal {}
    function stopPrank() internal {}
    function warp(uint256) internal {}
    function roll(uint256) internal {}
    function fee(uint256) internal {}
    function deal(address to, uint256 amount) internal {}
    function deal(address token, address to, uint256 amount, bool) internal {}
    function load(address account, bytes32 slot) internal view returns (bytes32) {}
    function store(address account, bytes32 slot, bytes32 value) internal {}
    function sign(uint256 privateKey, bytes32 digest) internal pure returns (uint8, bytes32, bytes32) {}
    function addr(uint256 privateKey) internal pure returns (address) {}
    function label(address account, string memory label) internal {}
    function assume(bool) internal {}
    function ffi(string[] memory) internal returns (bytes memory) {}
    function rpc(string memory, string memory) internal returns (bytes memory) {}
    function createSelectFork(string memory) internal returns (uint256) {}
    function createSelectFork(string memory, uint256) internal returns (uint256) {}
    function createSelectFork(string memory, bytes32) internal returns (uint256) {}
    function selectFork(uint256) internal {}
    function activeFork() internal view returns (uint256) {}
    function makeAddr(string memory) internal returns (address) {}
    function makeAddrAndKey(string memory) internal returns (address, uint256) {}
    function broadcast() internal {}
    function broadcast(address) internal {}
    function broadcast(uint256) internal {}
    function startBroadcast() internal {}
    function startBroadcast(address) internal {}
    function startBroadcast(uint256) internal {}
    function stopBroadcast() internal {}
    function chainId(uint256) internal {}
    function coinbase(address) internal {}
    function difficutly(uint256) internal {}
    function prevrandao(bytes32) internal {}
    function rollFork(uint256) internal {}
    function rollFork(uint256, uint256) internal {}
    function rollFork(uint256, bytes32) internal {}
    function getBlockNumber() internal view returns (uint256) {}
    function getBlockTimestamp() internal view returns (uint256) {}
    function readFile(string memory) internal view returns (string memory) {}
    function readLine(string memory) internal returns (string memory) {}
    function writeFile(string memory, string memory) internal {}
    function writeFileLine(string memory, string memory) internal {}
    function closeFile(string memory) internal {}
    function removeFile(string memory) internal returns (bool) {}
    function fsMetadata(string memory) internal view returns (bool, bool, uint256, uint256, uint256, uint256) {}
    function getCode(string memory) internal view returns (bytes memory) {}
    function getDeployedCode(string memory) internal view returns (bytes memory) {}
    function rememberKey(uint256) internal returns (address) {}
    function toString(address) internal pure returns (string memory) {}
    function toString(bytes32) internal pure returns (string memory) {}
    function toString(uint256) internal pure returns (string memory) {}
    function toString(int256) internal pure returns (string memory) {}
    function toString(bool) internal pure returns (string memory) {}
    function toString(bytes memory) internal pure returns (string memory) {}
    function parseBytes(string memory) internal pure returns (bytes memory) {}
    function parseBytes32(string memory) internal pure returns (bytes32) {}
    function parseInt(string memory) internal pure returns (int256) {}
    function parseJson(string memory, string memory) internal pure returns (bytes memory) {}
    function parseJson(string memory) internal pure returns (bytes memory) {}
    function parseJsonKeys(string memory, string memory) internal pure returns (string[] memory) {}
    function serializeBool(string memory, string memory, bool) internal returns (string memory) {}
    function serializeUint(string memory, string memory, uint256) internal returns (string memory) {}
    function serializeInt(string memory, string memory, int256) internal returns (string memory) {}
    function serializeAddress(string memory, string memory, address) internal returns (string memory) {}
    function serializeBytes32(string memory, string memory, bytes32) internal returns (string memory) {}
    function serializeString(string memory, string memory, string memory) internal returns (string memory) {}
    function serializeBytes(string memory, string memory, bytes memory) internal returns (string memory) {}
    function writeJson(string memory, string memory) internal {}
    function writeJson(string memory, string memory, string memory) internal {}
    function readJson(string memory, string memory) internal view returns (bytes memory) {}
    function keyExists(string memory, string memory) internal view returns (bool) {}
    function rpcUrl(string memory) internal view returns (string memory) {}
    function rpcUrls() internal view returns (string[2][] memory) {}
    function rpcUrlStructs() internal view returns (string[2][] memory) {}
    function sleep(uint256) internal {}
    function startMappingRecording() internal {}
    function stopMappingRecording() internal {}
    function isMappingRecorded() internal view returns (bool) {}
}

library console {
    address constant CONSOLE_ADDRESS = address(0x000000000000000000636F6e736F6c652e6c6f67);
    function log(string memory p0) internal view {
        (bool ignored,) = CONSOLE_ADDRESS.staticcall(abi.encodeWithSignature("log(string)", p0));
        ignored;
    }
    function logUint(uint256 p0) internal view {
        (bool ignored,) = CONSOLE_ADDRESS.staticcall(abi.encodeWithSignature("log(uint256)", p0));
        ignored;
    }
}
