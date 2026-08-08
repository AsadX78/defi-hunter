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

## ⚠️ Legal Disclaimer

**FOR AUTHORIZED SECURITY RESEARCH ONLY.**

Only use DeFi Hunter on protocols you own or have explicit written authorization to test. Unauthorized access to computer systems is illegal. The maintainers are not responsible for any misuse of this tool.

## Quick Start

### Install

```bash
# Clone
git clone https://github.com/defi-hunter/defi-hunter.git
cd defi-hunter

# Install (auto-creates .venv on PEP-668 systems like Kali)
make install

# Or manually with a virtual environment:
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Or, if you prefer system-wide (not on PEP-668 systems):
pip install -e ".[dev]"
```

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

### Environment Variables

```bash
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
├── cli.py              # Click-based CLI
├── core/
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
