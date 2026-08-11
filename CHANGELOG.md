# Changelog

All notable changes to **DeFi Hunter** are documented here.
The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.6.1] — 2026-08-11

### Fixed
- **Critical packaging bug**: `defihunter/core/` was missing `__init__.py`,
  which caused `find_packages()` to silently exclude the entire engine
  (analyzer, simulator, live_fork, attacker, slither, sync, recon, config)
  from published wheels. Previous wheels shipped a hollow shell with no core
  modules. Added the missing package file plus a regression test
  (`test_core_package_has_init`) so a hollow build can never ship again.
- **Stale template**: the `flash_loan_reentrancy` attack template was missing
  the ERC-777 `tokensReceived` hook, so the reentrancy could never actually
  fire with the shipped code. Added the missing hook.
- **Dead RPC**: removed `eth.llamarpc.com` (returned HTTP 521).
  Ethereum default RPC is now `https://ethereum-rpc.publicnode.com` with a
  live-probed fallback chain (`eth.drpc.org`, blastapi, cloudflare-eth.com,
  `rpc.ankr.com/eth`); `resolve_rpc()` live-probes endpoints before use.

### Changed
- **Honesty sweep**: deleted the stale `defi-lab/` directory whose bundled
  `forge-std` was a 3-line stub (`contract StdAssertions {}`). The maintained
  Foundry lab lives in `lab/` with a genuine forge-std v1.16.2.
- **Templates**: rewrote 6 attack templates (`oracle_manipulation`,
  `sandwich_attack`, `stablecoin_peg_collateral_swap`, `twap_manipulation`,
  `withdraw_frontrun`, `flash_loan_reentrancy`) so all 18 exported templates
  are runnable and are actually exercised by the test suite (19/19 Foundry
  tests pass).
- **CI**: the test job now installs `foundry-rs/foundry-toolchain` and
  `slither-analyzer` on the full Python matrix (3.8–3.13). A new guard step
  fails the build if any toolchain integration test is skipped — all 13
  previously-skipped tests now run.

### Security
- Template library is now verified end-to-end: every exported attack
  contract is imported and executed by tests, closing the gap between
  shipped code and tested code.

## [1.6.0] — 2026-08-10

### Added
- Interactive wizard (`defihunter wizard`) for guided scan setup.
- Rich terminal UI layer (`defihunter/ui.py`) with ASCII banner, severity
  color palette, tables, spinners and result panels.
- GitHub Actions CI across Python 3.8–3.13.

### Changed
- Centralized `rich`-based UI; banner is skipped when piping output
  (CI-friendly).

## [1.0.0] — 2026-08-09

### Added
- Initial release. Reconnaissance, static analysis, attack simulation on
  forked mainnet state, and HTML/JSON/Markdown reporting.
