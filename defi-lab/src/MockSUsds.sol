// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockSUsds
 * @notice Simplified version of SUsds for local testing
 */
contract MockSUsds {
    string  public constant name     = "Savings USDS";
    string  public constant symbol   = "sUSDS";
    uint8   public constant decimals = 18;
    uint256 public totalSupply;
    uint192 public chi;
    uint64  public rho;
    uint256 public ssr;
    
    mapping(address => uint256) public balanceOf;
    mapping(address => mapping(address => uint256)) public allowance;
    mapping(address => uint256) public wards;
    
    address public vow;
    uint256 private constant RAY = 10 ** 27;
    
    constructor(address _vow) {
        chi = uint192(RAY);
        rho = uint64(block.timestamp);
        ssr = RAY;
        vow = _vow;
        wards[msg.sender] = 1;
    }
    
    function _rpow(uint256 x, uint256 n) internal pure returns (uint256 z) {
        assembly {
            switch x case 0 {switch n case 0 {z := RAY} default {z := 0}}
            default {
                switch mod(n, 2) case 0 { z := RAY } default { z := x }
                let half := div(RAY, 2)
                for { n := div(n, 2) } n { n := div(n,2) } {
                    let xx := mul(x, x)
                    if iszero(eq(div(xx, x), x)) { revert(0,0) }
                    let xxRound := add(xx, half)
                    if lt(xxRound, xx) { revert(0,0) }
                    x := div(xxRound, RAY)
                    if mod(n,2) {
                        let zx := mul(z, x)
                        if and(iszero(iszero(x)), iszero(eq(div(zx, x), z))) { revert(0,0) }
                        let zxRound := add(zx, half)
                        if lt(zxRound, zx) { revert(0,0) }
                        z := div(zxRound, RAY)
                    }
                }
            }
        }
    }
    
    function _divup(uint256 x, uint256 y) internal pure returns (uint256 z) {
        unchecked { z = x != 0 ? ((x - 1) / y) + 1 : 0; }
    }
    
    function convertToShares(uint256 assets) public view returns (uint256) {
        uint256 chi_ = (block.timestamp > rho) ? _rpow(ssr, block.timestamp - rho) * chi / RAY : chi;
        return assets * RAY / chi_;
    }
    
    function convertToAssets(uint256 shares) public view returns (uint256) {
        uint256 chi_ = (block.timestamp > rho) ? _rpow(ssr, block.timestamp - rho) * chi / RAY : chi;
        return shares * chi_ / RAY;
    }
    
    function deposit(uint256 assets, address receiver) public returns (uint256 shares) {
        uint256 chi_ = (block.timestamp > rho) ? drip() : chi;
        shares = assets * RAY / chi_;
        balanceOf[receiver] += shares;
        totalSupply += shares;
    }
    
    function withdraw(uint256 assets, address receiver, address owner) public returns (uint256 shares) {
        uint256 chi_ = (block.timestamp > rho) ? drip() : chi;
        shares = _divup(assets * RAY, chi_);
        balanceOf[owner] -= shares;
        totalSupply -= shares;
    }
    
    function drip() public returns (uint256 nChi) {
        (uint256 chi_, uint256 rho_) = (chi, rho);
        uint256 diff;
        if (block.timestamp > rho_) {
            nChi = _rpow(ssr, block.timestamp - rho_) * chi_ / RAY;
            uint256 totalSupply_ = totalSupply;
            diff = totalSupply_ * nChi / RAY - totalSupply_ * chi_ / RAY;
            chi = uint192(nChi);
            rho = uint64(block.timestamp);
        } else {
            nChi = chi_;
        }
    }
    
    function file(bytes32 what, uint256 data) external {
        require(wards[msg.sender] == 1, "not-authorized");
        if (what == "ssr") {
            require(data >= RAY, "wrong-ssr-value");
            require(rho == block.timestamp, "chi-not-up-to-date");
            ssr = data;
        } else revert("unrecognized-param");
    }
    
    function rely(address usr) external {
        require(wards[msg.sender] == 1, "not-authorized");
        wards[usr] = 1;
    }
}
