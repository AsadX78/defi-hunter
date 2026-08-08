// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

import "./MockERC20.sol";

/**
 * @title MockStable
 * @notice VULNERABLE stablecoin protocol — collateral price is writable by
 *         anyone and collateral swaps use that price, allowing an attacker to
 *         mint unbacked stablecoin.
 * @dev Demonstrates stablecoin_peg_collateral_swap.
 *      Matches the template IStable interface
 *      (openVault / depositCollateral / swapCollateral / mint).
 */
contract MockStable {
    address public stable;      // the stablecoin asset
    address public collateralA; // expensive collateral
    address public collateralB; // cheap collateral

    // VULN: single writable price feed
    uint256 public rateA = 1 ether; // price of collateralA in stable
    uint256 public rateB = 1 ether; // price of collateralB in stable
    uint256 public constant MAX_LTV = 66; // %

    uint256 public vaultCount;
    mapping(uint256 => address) public vaultOwner;
    mapping(uint256 => mapping(address => uint256)) public vaultCollateral;

    event VaultOpened(uint256 indexed id, address indexed owner);
    event Minted(uint256 indexed id, address indexed minter, uint256 amount);

    constructor(address _stable, address _collateralA, address _collateralB) {
        stable = _stable;
        collateralA = _collateralA;
        collateralB = _collateralB;
    }

    // VULN: no access control on the price feed
    function updatePrice(uint256 newRateA, uint256 newRateB) external {
        rateA = newRateA;
        rateB = newRateB;
    }

    function openVault() external returns (uint256 id) {
        id = ++vaultCount;
        vaultOwner[id] = msg.sender;
        emit VaultOpened(id, msg.sender);
    }

    modifier onlyOwner(uint256 id) {
        require(vaultOwner[id] == msg.sender, "not owner");
        _;
    }

    function depositCollateral(uint256 id, address token, uint256 amount) external onlyOwner(id) {
        MockERC20(token).transferFrom(msg.sender, address(this), amount);
        vaultCollateral[id][token] += amount;
    }

    function collateralValue(uint256 id) public view returns (uint256) {
        return vaultCollateral[id][collateralA] * rateA / 1e18
             + vaultCollateral[id][collateralB] * rateB / 1e18;
    }

    // VULN: swaps collateral at the manipulable price
    function swapCollateral(uint256 id, address fromToken, address toToken, uint256 amount) external onlyOwner(id) {
        uint256 value = amount * (fromToken == collateralA ? rateA : rateB) / 1e18;
        uint256 out = value * 1e18 / (toToken == collateralA ? rateA : rateB);
        vaultCollateral[id][fromToken] -= amount;
        vaultCollateral[id][toToken] += out;
    }

    function mint(uint256 id, uint256 amount) external onlyOwner(id) {
        require(collateralValue(id) * 100 >= amount * MAX_LTV, "undercollateralized");
        MockERC20(stable).mint(msg.sender, amount);
        emit Minted(id, msg.sender, amount);
    }

    function withdrawCollateral(uint256 id, address token, uint256 amount) external onlyOwner(id) {
        require(collateralValue(id) * 100 >= vaultCollateral[id][token] * MAX_LTV, "would undercollateralize");
        vaultCollateral[id][token] -= amount;
        MockERC20(token).transfer(msg.sender, amount);
    }
}
