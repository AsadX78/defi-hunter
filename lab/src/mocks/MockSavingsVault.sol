// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

/**
 * @title MockSavingsVault
 * @notice VULNERABLE savings vault — balance-based share accounting.
 * @dev Demonstrates three template classes:
 *  - inflation_attack (first depositor donates to inflate share price)
 *  - admin_ssr_manipulation (admin can file() extreme rate + drip())
 *  - force_send_break (totalAssets reads address(this).balance, so a
 *    forced ETH send inflates the share price)
 *
 * Interface matches the templates' IVault / ISUSDS definitions.
 */
contract MockSavingsVault {
    string public name = "Mock sUSDS";
    string public symbol = "msUSDS";

    uint256 public totalSupply;
    mapping(address => uint256) public balanceOf;

    uint256 public constant RAY = 1e27;
    uint256 public chi = RAY;
    uint256 public ssr = RAY;
    address public vow;       // yield recipient (attacker-controlled in exploit)
    mapping(address => uint256) public wards; // admin set

    event Deposit(address indexed sender, address indexed owner, uint256 assets, uint256 shares);
    event Withdraw(address indexed sender, address indexed receiver, address indexed owner, uint256 assets, uint256 shares);
    event File(bytes32 indexed what, uint256 data);

    constructor(address _vow) {
        vow = _vow;
        wards[msg.sender] = 1;
    }

    // --- ERC-4626-like, balance-based (VULNERABLE) ---

    function deposit(uint256 assets, address receiver) external payable returns (uint256 shares) {
        uint256 bal = address(this).balance;
        if (totalSupply == 0 || bal == 0) {
            shares = assets;
        } else {
            shares = assets * totalSupply / bal; // donation inflates this
        }
        balanceOf[receiver] += shares;
        totalSupply += shares;
        emit Deposit(msg.sender, receiver, assets, shares);
    }

    function withdraw(uint256 assets, address receiver, address owner) external returns (uint256 shares) {
        uint256 bal = address(this).balance;
        shares = bal == 0 ? 0 : assets * totalSupply / bal;
        balanceOf[owner] -= shares;
        totalSupply -= shares;
        (bool ok, ) = receiver.call{value: assets}("");
        require(ok, "transfer failed");
        emit Withdraw(msg.sender, receiver, owner, assets, shares);
    }

    function redeem(uint256 shares, address receiver, address owner) external returns (uint256 assets) {
        assets = shares * address(this).balance / totalSupply;
        balanceOf[owner] -= shares;
        totalSupply -= shares;
        (bool ok, ) = receiver.call{value: assets}("");
        require(ok, "transfer failed");
    }

    function convertToAssets(uint256 shares) external view returns (uint256) {
        return totalSupply == 0 ? shares : shares * address(this).balance / totalSupply;
    }

    function totalAssets() external view returns (uint256) {
        return address(this).balance; // VULNERABLE: uses balance, not internal accounting
    }

    // --- Admin SSR (VULNERABLE: no timelock) ---

    modifier auth() {
        require(wards[msg.sender] == 1, "not-admin");
        _;
    }

    function rely(address usr) external auth {
        wards[usr] = 1;
    }

    function deny(address usr) external auth {
        wards[usr] = 0;
    }

    function file(bytes32 what, uint256 data) external auth {
        if (what == "ssr") {
            ssr = data;
        } else if (what == "vow") {
            vow = address(uint160(data));
        }
        emit File(what, data);
    }

    function drip() external auth returns (uint256 yield_) {
        uint256 bal = address(this).balance;
        uint256 computed = bal * ssr / RAY;
        yield_ = computed > bal ? bal : computed - bal;
        (bool ok, ) = vow.call{value: yield_}("");
        require(ok, "drip failed");
    }

    receive() external payable {}
}
