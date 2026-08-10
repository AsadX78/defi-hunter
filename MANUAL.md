# DeFi Hunter — User Manual

> ⚡ WORLD RECORD DeFi ATTACK TOOLKIT 🥵
> the only toolkit that fork-proves every HIGH finding on a live mainnet clone

---

## Table of Contents

1. [Installation](#installation)
2. [Quick Start](#quick-start)
3. [Commands](#commands)
4. [Attack Types](#attack-types)
5. [Examples](#examples)
6. [Configuration](#configuration)
7. [Troubleshooting](#troubleshooting)

---

## Installation

### Prerequisites

- Python 3.8+
- pip
- (Optional) Foundry for running exploits

### Install

```bash
# Clone the repo
git clone https://github.com/AsadX78/defi-hunter.git
cd defi-hunter

# Install in development mode
pip install -e .

# Or install from PyPI (when published)
pip install defi-hunter
```

### Verify Installation

```bash
defihunter --version
# Output: defi-hunter, version 1.4.0
```

---

## Quick Start

### 1. Scan a Protocol (Interactive Wizard)

```bash
defihunter
```

The wizard will:
1. Ask for a protocol name, GitHub repo, or contract address
2. Resolve contracts via DefiLlama
3. Scan GitHub repos for deployed addresses
4. Run static analysis + fork verification
5. Generate a professional HTML report

### 2. Scan a Contract (Direct)

```bash
defihunter scan --target 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 --chain ethereum
```

### 3. Generate Exploit Scripts

```bash
defihunter exploit --target 0x... --attack reentrancy
```

### 4. Generate Flash Loan Exploit

```bash
defihunter flashloan --loan-token USDC --loan-amount 10000000
```

---

## Commands

### `defihunter` (Interactive Wizard)

Launch the interactive wizard that guides you through:
- Protocol discovery (DefiLlama)
- Contract extraction (GitHub repos)
- Static analysis
- Fork verification
- Report generation

```bash
defihunter
```

**Wizard Steps:**
1. **Protocol Source** — paste a GitHub repo, addresses, or protocol name
2. **RPC Endpoint** — enter your Alchemy/Infura RPC URL
3. **Wallet Config** — attacker EOA + profit wallet (for simulation)
4. **Vulnerability Check** — static, simulate, or both
5. **Attack Menu** — pick which attacks to test

---

### `defihunter scan`

Scan a single target (contract address or GitHub repo).

```bash
defihunter scan --target 0x... --chain ethereum --format html
```

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `--target, -t` | Contract address or repo URL | (required) |
| `--chain, -c` | Target chain | ethereum |
| `--rpc, -r` | RPC URL (overrides chain default) | (from config) |
| `--format, -f` | Report format: html, pdf, markdown, json | html |
| `--output, -o` | Output file path | output/ |
| `--no-fork` | Skip fork verification | false |

**Supported Chains:**
ethereum, bsc, polygon, arbitrum, optimism, base, avalanche, fantom, gnosis, linea, zksync, scroll, mantle, celo, moonbeam

---

### `defihunter exploit`

Generate ready-to-run Foundry exploit scripts.

```bash
# Single attack type
defihunter exploit --target 0x... --attack reentrancy

# All attack types
defihunter exploit --target 0x... --all
```

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `--target, -t` | Target contract address | (required) |
| `--attack, -a` | Attack type | (required or --all) |
| `--output, -o` | Output directory | ./exploit |
| `--all` | Generate all attack types | false |

**Output:**
```
exploit/
├── contracts/
│   └── ExploitReentrancy.sol    ← attacker contract
├── scripts/
│   └── run-exploit.s.sol        ← Foundry script
├── .env                         ← environment variables
├── foundry.toml                 ← Foundry config
└── README.md                    ← usage instructions
```

**Run the exploit:**
```bash
cd exploit/
forge install foundry-rs/forge-std --no-commit
# Edit .env with your values
forge script scripts/run-exploit.s.sol --rpc-url $RPC --private-key $KEY --broadcast
```

---

### `defihunter flashloan`

Generate flash loan exploit scripts (Aave/Uniswap/Balancer).

```bash
defihunter flashloan --loan-token USDC --loan-amount 10000000
```

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `--output, -o` | Output directory | ./flashloan-exploit |
| `--loan-token` | Token to borrow | USDC |
| `--loan-amount` | Amount to borrow (in token units) | 10000000 |
| `--pool` | Flash loan provider: aave, uniswap, balancer | aave |

**Output:**
```
flashloan-exploit/
├── contracts/
│   └── FlashLoanExploit.sol     ← flash loan contract
├── scripts/
│   └── run-flashloan.s.sol      ← Foundry script
├── .env
└── foundry.toml
```

**How it works:**
1. Borrows millions via flash loan
2. Executes exploit steps (swap, manipulate, drain)
3. Repays loan + fee (0.09% for Aave)
4. Sweeps profit to your wallet

---

### `defihunter mev`

Generate MEV tools — Flashbots bundle submission + anti-sandwich protection.

```bash
defihunter mev
```

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `--output, -o` | Output directory | ./mev-tools |
| `--relay` | MEV relay: flashbots, bloxroute, eden | flashbots |

**Output:**
```
mev-tools/
├── contracts/
│   ├── SendBundle.sol            ← submit exploits privately
│   └── MEVProtection.sol        ← protect users from sandwiches
└── foundry.toml
```

**Features:**
- **SendBundle.sol** — submit exploit transactions via Flashbots (no mempool exposure)
- **MEVProtection.sol** — protect users from sandwich attacks

---

### `defihunter chain`

Generate cross-protocol exploit chains.

```bash
defihunter chain --protocols "aave:0x87870Bca...:flash_loan,uniswap:0x88e6A0c...:dex,victim:0x...:vault"
```

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `--protocols, -p` | Comma-separated: name:address:type | (required) |
| `--output, -o` | Output directory | ./chain-exploit |

**Protocol Types:**
- `flash_loan` — Aave, Balancer, Uniswap
- `dex` — Uniswap, SushiSwap, Curve
- `vault` — Yearn, Beefy, victims
- `lending` — Aave, Compound, Venus
- `bridge` — Wormhole, LayerZero
- `governance` — Compound, MakerDAO

**Output:**
```
chain-exploit/
├── contracts/
│   └── ExploitChain.sol          ← cross-protocol exploit
├── scripts/
│   └── run-chain.s.sol           ← Foundry script
├── CHAIN.md                      ← Mermaid diagram
└── foundry.toml
```

**Example:**
```bash
# Chain: Flash loan → DEX swap → Drain vault
defihunter chain -p "aave:0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2:flash_loan,uniswap:0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640:dex,victim:0x1234...:vault"
```

---

### `defihunter monitor`

Real-time vulnerability monitoring — watch 24/7, alert on new vulns.

```bash
defihunter monitor --address 0x... --alert telegram
```

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `--address, -a` | Address to monitor (can repeat) | (required) |
| `--chain, -c` | Chain to monitor | ethereum |
| `--interval, -i` | Poll interval in seconds | 12 |
| `--alert` | Alert destination: console, telegram, discord | console |
| `--output, -o` | Output directory | ./monitor |

**Output:**
```
monitor/
├── telegram_bot.py               ← Telegram alert bot
├── discord_webhook.py            ← Discord webhook
└── config.json                   ← configuration
```

**Start monitoring:**
```bash
cd monitor/

# Telegram
python telegram_bot.py

# Discord
python discord_webhook.py
```

---

### `defihunter batch`

Batch scan multiple targets.

```bash
defihunter batch --targets 0x...,0x...,0x... --chain ethereum --format html
```

**Options:**
| Flag | Description | Default |
|------|-------------|---------|
| `--targets, -t` | Comma-separated addresses | (required) |
| `--chain, -c` | Target chain | ethereum |
| `--attacks, -a` | Attack types (or "all") | all |
| `--format, -f` | Report format | html |
| `--output-dir, -o` | Output directory | output/batch |

---

### `defihunter chains`

Manage chain configurations.

```bash
# List all supported chains
defihunter chains list

# Detect chain from RPC URL
defihunter chains detect https://eth-mainnet.g.alchemy.com/v2/...
```

---

### `defihunter report`

Generate reports from scan results.

```bash
defihunter report --input results.json --format html --output report.html
```

---

## Attack Types

### Core Attacks (20 types)

| # | Attack | Description | Severity |
|---|--------|-------------|----------|
| 1 | `reentrancy` | Drain via re-entrant callback | CRITICAL |
| 2 | `mint` | Permissionless token inflation | CRITICAL |
| 3 | `initialize` | Ownership takeover via unprotected init | CRITICAL |
| 4 | `delegatecall` | Proxy upgrade to attacker logic | CRITICAL |
| 5 | `approve` | Spending allowance grant | HIGH |
| 6 | `selfdestruct` | Kill switch / balance sweep | HIGH |
| 7 | `arbitrarycall` | Calldata forwarder hijack | HIGH |
| 8 | `oracle` | DEX spot price manipulation | CRITICAL |
| 9 | `flashloan` | Single-tx drain with borrowed capital | CRITICAL |
| 10 | `governance` | Flash loan voting power attack | CRITICAL |
| 11 | `bridge` | Deposit spoof without proof | CRITICAL |
| 12 | `twap` | Short TWAP window exploitation | HIGH |
| 13 | `crossfunc` | Cross-function reentrancy | HIGH |
| 14 | `permit` | Cross-chain signature replay | HIGH |
| 15 | `liquidation` | Permissionless front-running | HIGH |
| 16 | `forcesend` | Selfdestruct accounting inflation | MEDIUM |
| 17 | `peg` | Stablecoin collateral swap | HIGH |
| 18 | `sandwich` | Swap vulnerable to sandwich MEV | HIGH |
| 19 | `frontrun` | Time-sensitive function without commit-reveal | HIGH |
| 20 | `mev` | Comprehensive MEV surface analysis | HIGH |

---

## Examples

### Example 1: Scan Aave V3 Pool

```bash
# Interactive wizard
defihunter
# Paste: aave
# Pick: 3 (Both)
# Pick: all

# Or direct scan
defihunter scan --target 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 --chain ethereum --format html
```

### Example 2: Generate Reentrancy Exploit

```bash
defihunter exploit --target 0x1234567890123456789012345678901234567890 --attack reentrancy

# Output:
# exploit/contracts/ExploitReentrancy.sol
# exploit/scripts/run-exploit.s.sol
# exploit/.env

# Run it:
cd exploit/
forge install foundry-rs/forge-std --no-commit
# Edit .env: TARGET=0x..., PROFIT=0x..., PRIVATE_KEY=0x...
forge script scripts/run-exploit.s.sol --rpc-url https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY --private-key $PRIVATE_KEY --broadcast
```

### Example 3: Flash Loan Exploit

```bash
# Borrow 10M USDC from Aave, exploit, repay
defihunter flashloan --loan-token USDC --loan-amount 10000000 --pool aave

# Output:
# flashloan-exploit/contracts/FlashLoanExploit.sol
# flashloan-exploit/scripts/run-flashloan.s.sol

# Run it:
cd flashloan-exploit/
forge install foundry-rs/forge-std --no-commit
# Edit .env
forge script scripts/run-flashloan.s.sol --rpc-url $RPC --private-key $KEY --broadcast
```

### Example 4: Cross-Protocol Chain

```bash
# Chain: Aave flash loan → Uniswap swap → Drain victim vault
defihunter chain \
  --protocols "aave:0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2:flash_loan,uniswap:0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640:dex,victim:0x1234...:vault"

# Output includes CHAIN.md with Mermaid diagram
```

### Example 5: MEV Bundle Submission

```bash
# Generate Flashbots bundle sender
defihunter mev

# Submit exploit privately (no mempool)
cd mev-tools/
# Use SendBundle.sol to submit via Flashbots
```

### Example 6: Real-Time Monitoring

```bash
# Monitor Aave Pool for suspicious activity
defihunter monitor \
  --address 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2 \
  --alert telegram

# Start the bot
cd monitor/
python telegram_bot.py
```

### Example 7: Batch Scan

```bash
# Scan multiple DeFi protocols
defihunter batch \
  --targets 0x87870Bca3F3fD6335C3F4ce8392D69350B4fA4E2,0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640 \
  --chain ethereum \
  --format html
```

---

## Configuration

### RPC URLs

Save your RPC URL to avoid re-entering it:

```bash
# The wizard saves your RPC to config.local.yaml
# Default: https://eth-mainnet.g.alchemy.com/v2/alch_k2RDgkHiEB4wpC8-0HrBa

# Free RPCs:
# - Alchemy: https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
# - Infura: https://mainnet.infura.io/v3/YOUR_KEY
# - PublicNode: https://ethereum-rpc.publicnode.com
```

### Wallet Configuration

For simulation (not real exploits):
- **Attacker EOA**: Signs fork proof txs (default: 0x3C44...)
- **Profit Wallet**: Where drained ETH is swept (default: 0x3C44...)

⚠️ These are for simulation only. Real exploits use your own wallets.

### Environment Variables

```bash
# Optional
export RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
export PRIVATE_KEY=0x...
```

---

## Troubleshooting

### "No RPC URL" Error

```bash
# Set your RPC URL
export RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY

# Or enter it when prompted in the wizard
```

### "ForkSimulator does not support attack X"

Update to the latest version — the wizard now uses correct attack names:
```bash
pip install -e . --upgrade
```

### "GitHub token expired"

```bash
# Set a new GitHub token
export GITHUB_TOKEN=ghp_...
```

### "No contracts found"

The tool needs deployed contracts to scan. Try:
1. Use a known contract address (0x...)
2. Use a GitHub repo with Solidity source
3. Use a protocol name (e.g., "aave", "uniswap")

### Report not generating

```bash
# Install report dependencies
pip install xhtml2pdf

# Try a different format
defihunter scan --target 0x... --format markdown
```

---

## Supported Chains (15)

| Chain | Native Token | RPC Example |
|-------|--------------|-------------|
| Ethereum | ETH | ethereum-rpc.publicnode.com |
| BSC | BNB | bsc-dataseed.binance.org |
| Polygon | MATIC | polygon-rpc.com |
| Arbitrum | ETH | arb1.arbitrum.io/rpc |
| Optimism | ETH | mainnet.optimism.io |
| Base | ETH | mainnet.base.org |
| Avalanche | AVAX | api.avax.network/ext/bc/C/rpc |
| Fantom | FTM | rpc.ftm.tools |
| Gnosis | xDAI | rpc.gnosischain.com |
| Linea | ETH | rpc.linea.build |
| zkSync | ETH | mainnet.era.zksync.io |
| Scroll | ETH | rpc.scroll.io |
| Mantle | MNT | rpc.mantle.xyz |
| CELO | CELO | forno.celo.org |
| Moonbeam | GLMR | rpc.api.moonbeam.network |

---

## Legal Disclaimer

⚠️ **This tool is for authorized security testing only.**

- Use only on contracts you own or have written permission to test
- Unauthorized exploitation of smart contracts is illegal
- Always obtain written authorization before testing
- The authors are not responsible for misuse

---

## Support

- GitHub: https://github.com/AsadX78/defi-hunter
- Issues: https://github.com/AsadX78/defi-hunter/issues

---

*Built with ❤️ by DeFi Hunter*
