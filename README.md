# 🛡️ DeFi Hunter

> Open Source DeFi Security Analysis Toolkit

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![CI](https://github.com/defi-hunter/defi-hunter/workflows/CI/badge.svg)](https://github.com/defi-hunter/defi-hunter/actions)

## What Is DeFi Hunter?

DeFi Hunter is a comprehensive security analysis toolkit for DeFi protocols. It automates:

- 🔍 **Reconnaissance** — Discovers contracts from dApps and scans for attack surface
- 🔬 **Analysis** — Detects vulnerabilities using static analysis and pattern matching
- 🧪 **Simulation** — Runs attack simulations on forked mainnet state
- 📊 **Reporting** — Generates professional HTML/JSON/Markdown reports

## ✨ v1.1 — Rich Terminal UI

The CLI now renders through a centralized `rich` UI layer (`defihunter/ui.py`):

- 🎨 **ASCII banner + themed colors** (cyan/green/yellow/red severity palette)
- 📋 **Tables** — contracts, findings (color-coded severity), and template library
- ⏳ **Spinners & progress bars** for long-running scan/simulate/report operations
- 🧾 **Result panels** — big success/failure panels for attack simulations
- 🖥️ **Terminal-aware** — the banner is skipped when piping output (CI-friendly)

All command names and options are unchanged from v1.0.

## 🪄 Interactive Wizard (v1.2)

Just run `defihunter` with no arguments (or `defihunter wizard`) and it walks
you through the whole hunt with prompts:

```
$ defihunter

  1. GitHub repo URL of the protocol
     → e.g. https://github.com/Layr-Labs/eigenlayer-contracts
  2. RPC URL (Enter = your saved RPC or eth.drpc.org, or type 'skip')
     → clones the repo, extracts every 0x…40 address, verifies which
       ones actually have deployed code on-chain
     → a custom URL you enter can be saved for all future hunts
       (see "Save your RPC once" below)
  3. Vulnerability check type
     → 1 = static analysis, 2 = attack simulation, 3 = both (recommended)
  4. Attack selection (for simulation) — pick from the 18 built-in attacks
  5. Runs the checks with progress bars, then offers an HTML report
```

You can skip prompts with flags for scripting:

```bash
defihunter wizard --repo https://github.com/Layr-Labs/eigenlayer-contracts \
                  --check both \
                  --attacks initialize,admin,mint,withdraw
```

A local folder also works as the "repo" for testing repos that aren't public.

### No GitHub link? No problem (v1.3)

Three ways to hunt a protocol that has no public repo:

1. **Just a protocol name?** Let DefiLlama find the addresses (v1.3.4):
   ```bash
   defihunter wizard -r llama:spark -c both
   ```
   Or type the name straight into the wizard prompt (`spark`, `aave`, `lido`…).
   It resolves the anchor contract(s), website, chains, and GitHub org, then
   runs the normal flow. The anchor is often just the token — the wizard will
   offer to go deeper by scanning a repo from the protocol's GitHub org
   (v1.3.5). Repos are **auto-ranked** by how likely they are to contain the
   deployed contract addresses (✓ badge for `deployments/`, `broadcast/`,
   `script/output/`, `addresses.json` layouts — v1.3.6), so you don't have to
   guess which repo holds the real contracts.

   The org-repo menu uses the unauthenticated GitHub API (60 req/hr). For
   heavy use, set a token to lift the cap to 5,000 req/hr:
   ```bash
   export GITHUB_TOKEN=ghp_xxx   # or GH_TOKEN
   defihunter wizard -r llama:spark
   ```

2. **Paste 0x addresses directly** — skip the repo entirely:
   ```bash
   defihunter wizard -r "0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2,0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2" -c both
   ```
   (the wizard prompt accepts the same — comma/space separated). Addresses come
   from anywhere: a DEX UI, a block explorer, `cast`, or step 4 below.

3. **Use a local folder** — if you have a private/unlisted copy of the repo:
   ```bash
   defihunter wizard -r /path/to/private-protocol-repo
   ```

4. **Scrape a website** — no addresses either? Let recon find them on the
   protocol's site, then paste the results into the wizard:
   ```bash
   defihunter recon scan --target sky.money --rpc "$DEFIHUNTER_RPC"
   ```

The rest of the flow (verify → preview → static/simulation → HTML report) is
identical for all four sources.

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH ONLY.**

Only use DeFi Hunter on protocols you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal. The maintainers are not responsible for any misuse of this tool.

## Quick Start

### Install

```bash
# Clone
git clone git@github.com:AsadX78/defi-hunter.git
cd defi-hunter

# One command — creates a venv, installs, and links `defihunter`
# into ~/.local/bin so it's on your PATH (no activation needed):
make install

# Then just run it — it boots the interactive wizard:
defihunter
```

> **Why no `source .venv/bin/activate`?** `make install` writes a tiny wrapper
> (`~/.local/bin/defihunter`) that execs the venv CLI. If your shell doesn't
> already include `~/.local/bin`, add `export PATH="$HOME/.local/bin:$PATH"`
> to your `~/.zshrc` / `~/.bashrc`.

If you prefer to manage the environment yourself:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"
```

> **Note:** if you already have the repo cloned, just run `make install` inside
> it — no need to clone again.

### Dependencies

- [Foundry](https://book.getfoundry.xyz/) (for `cast`, `forge`, `anvil`)
- Python 3.8+

### Basic Usage

```bash
# Scan a protocol for contracts
defihunter recon scan --target sky.money --rpc $RPC_URL

# Analyze a specific contract
defihunter analyze contract --address 0x1234... --rpc $RPC_URL

# Run attack simulation
defihunter simulate run --attack inflation --target 0x1234... --rpc $RPC_URL

# Generate report
defihunter report --input findings.json --output report.html --format html

# List attack templates
defihunter templates list --type all

# Prove every template exploit against the Foundry lab (needs forge + lab/)
defihunter templates verify
```

### Save your RPC once, reuse forever (v1.3)

Instead of pasting your RPC URL on every hunt, save it once — the wizard
pre-fills it from then on:

```bash
# Save (stored in ~/.config/defi-hunter/config.yaml — outside the repo,
# never committed; a legacy ./config.local.yaml in your CWD also works)
defihunter config set-rpc "https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"

# Check what's saved (keys are masked)
defihunter config show

# Remove it (falls back to the free https://eth.drpc.org default)
defihunter config clear-rpc
```

The RPC default resolution is:

1. `DEFIHUNTER_RPC` env var
2. `./config.local.yaml` in your working directory (legacy, repo-local)
3. `~/.config/defi-hunter/config.yaml` (created by `set-rpc`)
4. `RPC_URL` env var
5. built-in `https://eth.drpc.org`

Free RPC options for the key you save: [Alchemy](https://dashboard.alchemy.com)
(free tier, `https://eth-mainnet.g.alchemy.com/v2/<key>`),
[Infura](https://infura.io), [dRPC](https://drpc.org), or per-chain public
endpoints from [Chainlist](https://chainlist.org).

### Environment Variables

```bash
export DEFIHUNTER_RPC="https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY"
export RPC_URL="https://eth-mainnet.galchemy.com/v2/YOUR_KEY"
export ETHERSCAN_API_KEY="your_key"
export ALCHEMY_KEY="your_key"
```

## Attack Templates

| Template | Type | Severity | Description |
|----------|------|----------|-------------|
| `inflation_attack` | Vault | HIGH | First deposit inflation via donation |
| `admin_ssr_manipulation` | Vault | CRITICAL | Admin key compromise drains vault |
| `flash_loan_governance` | Governance | CRITICAL | Flash loan voting power |
| `oracle_manipulation` | AMM | CRITICAL | Spot price oracle manipulation |
| `reentrancy_attack` | Lending | CRITICAL | External call reentrancy |
| `bridge_deposit_spoof` | Bridge | CRITICAL | Forged deposit proof mints wrapped tokens |
| `sandwich_attack` | AMM | HIGH | Front-run + back-run victim swaps |
| `twap_manipulation` | AMM | HIGH | Time-weighted average price distortion |
| `flash_loan_reentrancy` | Lending | CRITICAL | Flash loan funds recursive exploit |
| `withdraw_frontrun` | Vault | HIGH | Mid-transaction rate manipulation + rounding theft |
| `proxy_initialization` | Proxy | CRITICAL | Uninitialized proxy taken over |
| `permit_replay` | Token | HIGH | ChainId-less permit replayed cross-chain |
| `liquidation_sandwich` | Lending | HIGH | Liquidate healthy position for profit |
| `force_send_break` | Vault | HIGH | Forced ETH send inflates share price |
| `stablecoin_peg_collateral_swap` | Stablecoin | CRITICAL | Swap collateral at distorted price to mint unbacked stablecoin |
| `cross_function_reentrancy` | Vault | CRITICAL | Re-enter a second function to double-credit funds |
| `arbitrary_delegatecall` | Proxy | CRITICAL | Unauthenticated proxy upgrade = full takeover |
| `permissionless_mint` | Token | HIGH | mint() without access control inflates supply |

## Architecture

```
defihunter/
├── cli.py              # Click-based CLI (renders via ui.py; bare run = wizard)
├── ui.py               # Rich UI layer — banner, tables, panels, spinners, theme
├── wizard.py           # Interactive guided hunt (repo URL → contracts → checks)
├── core/
│   ├── github.py       # Clone protocol repo + extract/verify contract addresses
│   ├── recon.py        # Contract discovery
│   ├── analyzer.py     # Vulnerability detection
│   ├── simulator.py    # Fork simulation
│   ├── reporter.py     # Report generation
│   └── config.py       # Configuration
├── templates/
│   └── __init__.py     # Attack templates
└── tests/              # Test suite
```

## Example: Full Scan

```python
from defihunter.core.recon import ReconScanner
from defihunter.core.analyzer import ContractAnalyzer
from defihunter.core.reporter import ReportGenerator

# Step 1: Recon
scanner = ReconScanner(rpc_url="https://...")
results = scanner.scan("sky.money", deep=True)

# Step 2: Analyze
analyzer = ContractAnalyzer(rpc_url="https://...")
findings = []
for addr in results["contracts"]:
    findings.extend(analyzer.analyze(addr))

# Step 3: Report
gen = ReportGenerator()
gen.generate({"contracts": results["contracts"], "vulnerabilities": findings}, format="html")
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing`)
3. Commit your changes (`git commit -m 'Add amazing feature'`)
4. Push to the branch (`git push origin feature/amazing`)
5. Open a Pull Request

## License

MIT License — see [LICENSE](LICENSE) for details.

## Credits

Built by the DeFi security research community. Inspired by Slither, Mythril, echidna, and Trail of Bits tools.

---

**Remember:** With great power comes great responsibility. Use DeFi Hunter to make DeFi safer, not to exploit innocent users.
