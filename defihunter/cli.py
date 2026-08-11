#!/usr/bin/env python3
"""DeFi Hunter — CLI Entry Point (beautified with rich UI layer)."""

import click
import json
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))

from defihunter.core.recon import ReconScanner
from defihunter.core.analyzer import ContractAnalyzer
from defihunter.core.simulator import AttackSimulator
from defihunter.core.reporter import ReportGenerator
from defihunter.core.config import load_config
from defihunter import ui

__version__ = "1.6.0"


def _banner():
    """Show the banner only on real terminals (keeps pipes/tests clean)."""
    if ui.console.is_terminal:
        ui.mega_banner(__version__)


@click.group(invoke_without_command=True)
@click.version_option(__version__)
@click.option('--config', '-c', type=click.Path(), help='Config file')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.option('--no-intro', is_flag=True, help='Skip the animated boot intro')
@click.pass_context
def cli(ctx, config, verbose, no_intro):
    """DeFi Hunter — Open Source DeFi Security Toolkit"""
    ctx.ensure_object(dict)
    ctx.obj['config'] = load_config(config)
    ctx.obj['verbose'] = verbose
    if no_intro:
        os.environ['DEFIHUNTER_NO_INTRO'] = '1'
    # Bare `defihunter` (no subcommand) boots the interactive wizard.
    if ctx.invoked_subcommand is None:
        from defihunter.wizard import run_wizard
        run_wizard(verbose=verbose, version=__version__)
        ctx.exit(0)
    _banner()


@cli.command()
@click.option('--repo', '-r', default=None, help='GitHub repo URL, local folder, 0x addresses, or llama:<protocol-name> (skips the repo prompt)')
@click.option('--check', '-c', type=click.Choice(['static', 'simulate', 'both']), default=None, help='Vulnerability check type (skips the prompt)')
@click.option('--attacks', '-a', default=None, help='Comma-separated attack names for simulation (e.g. initialize,admin)')
@click.option('--attacker', help='EOA that signs the fork proof txs '
              '(prompted if missing, default anvil dev account 0x3C44…)')
@click.option('--profit-wallet', help='Wallet the attacker-contract drain is '
              'swept to (prompted if missing, default: the attacker EOA)')
@click.option('--format', '-f', 'report_format', type=click.Choice(['html', 'pdf', 'markdown', 'json']),
              default=None, help='Report format (skips the prompt)')
@click.option('--full-scan', is_flag=True,
              help='Full pipeline: static + simulate + exploit gen + report (no prompts)')
@click.option('--no-exploit', is_flag=True, help='Skip exploit script generation')
def wizard(repo, check, attacks, attacker, profit_wallet, report_format, full_scan, no_exploit):
    """Interactive guided hunt: GitHub repo → contracts → vulnerability checks

    Full pipeline (no prompts):
      defihunter wizard --repo 0x... --full-scan
      defihunter wizard --repo https://github.com/... --full-scan --format pdf

    Interactive (guided prompts):
      defihunter wizard
      defihunter wizard --repo 0x...
    """
    from defihunter.wizard import run_wizard, is_eoa
    for name, val in (("attacker", attacker), ("profit-wallet", profit_wallet)):
        if val and not is_eoa(val):
            raise click.ClickException(
                f"Invalid --{name} value {val!r} — need an Ethereum address "
                f"(0x + 40 hex chars)")
    attack_list = [a.strip() for a in attacks.split(',') if a.strip()] if attacks else None
    run_wizard(verbose=False, repo_url=repo, check=check, attacks=attack_list,
               version=__version__, attacker=attacker,
               profit_wallet=profit_wallet, report_format=report_format,
               full_scan=full_scan, no_exploit=no_exploit)


@cli.group()
def config():
    """Save/clear your personal RPC URL (pre-fills the wizard prompt)"""


@config.command('set-rpc')
@click.argument('url')
def config_set_rpc(url):
    """Save an RPC URL for all future hunts (stored in config.local.yaml, gitignored)"""
    from defihunter.core.config import save_rpc
    path = save_rpc(url)
    ui.rule("CONFIG")
    ui.ok(f"Saved RPC → {path}")
    ui.info("It will pre-fill the wizard's RPC prompt from now on.")


@config.command('show')
def config_show():
    """Show the current saved RPC (API keys are masked)"""
    from defihunter.core import config as cfg
    ui.rule("CONFIG")
    rpc = cfg.get_default_rpc()
    if rpc == cfg.DEFAULT_RPC:
        ui.info(f"Using built-in default: {rpc}")
        ui.info("No personal RPC saved yet. Save one with: defihunter config set-rpc <url>")
        return
    ui.info(f"Saved RPC: {_mask_rpc(rpc)}")


@config.command('clear-rpc')
def config_clear_rpc():
    """Remove your saved RPC (falls back to the public default)"""
    from defihunter.core.config import clear_rpc
    clear_rpc()
    ui.rule("CONFIG")
    ui.ok("Cleared saved RPC. The wizard will use https://eth.drpc.org again.")


def _mask_rpc(url: str) -> str:
    """Show scheme + host, mask the path tail if it looks like a secret."""
    import re
    m = re.match(r'(https?://[^/]+/)(.+)$', url)
    if not m:
        return url
    scheme_host, tail = m.group(1), m.group(2)
    if len(tail) >= 8:
        return f"{scheme_host}{tail[:4]}{'*' * min(8, len(tail) - 4)}"
    return url


@cli.group()
@click.pass_context
def recon(ctx):
    """Discover contracts and map attack surface"""
    pass


@recon.command()
@click.option('--target', '-t', required=True, help='Target domain (e.g., sky.money)')
@click.option('--rpc', '-r', envvar='RPC_URL', help='RPC URL')
@click.option('--deep', '-d', is_flag=True, help='Deep scan (scan JS files)')
@click.option('--output', '-o', type=click.Path(), help='Output file')
@click.pass_context
def scan(ctx, target, rpc, deep, output):
    """Scan target for contracts"""
    scanner = ReconScanner(rpc_url=rpc, verbose=ctx.obj['verbose'])

    ui.rule("RECON")
    ui.step("Scanning", target)
    with ui.spinner(f"Scraping {target} for 0x addresses"):
        results = scanner.scan(target, deep=deep)

    contracts = results.get('contracts', {})
    total = results.get('total_addresses', 0)

    ui.ok(f"Found {len(contracts)} contracts (from {total} raw addresses)")
    if contracts:
        ui.console.print(ui.contracts_table(contracts))
    else:
        ui.warn("No contracts found — the target may be a marketing/dapp site.")

    if output:
        Path(output).write_text(json.dumps(results, indent=2))
        ui.ok(f"Results saved to {output}")

    # Compact summary for scripting/CI
    ui.console.print()
    ui.console.print(ui.summary_panel([
        ("target", results.get('target', target)),
        ("url", results.get('url', '')),
        ("raw addresses", str(total)),
        ("contracts", str(len(contracts))),
        ("rpc", rpc or "(not provided — code check skipped)"),
    ]))


@cli.group()
@click.pass_context
def analyze(ctx):
    """Analyze contract source code for vulnerabilities"""
    pass


@analyze.command()
@click.option('--address', '-a', required=True, help='Contract address')
@click.option('--rpc', '-r', envvar='RPC_URL', help='RPC URL')
@click.pass_context
def contract(ctx, address, rpc):
    """Analyze a specific contract"""
    analyzer = ContractAnalyzer(rpc_url=rpc)

    ui.rule("ANALYZE")
    ui.step("Analyzing", address)
    with ui.spinner("Running vulnerability checks"):
        findings = analyzer.analyze(address)

    if findings:
        ui.warn(f"Found {len(findings)} issue(s):")
        ui.console.print(ui.findings_table(findings))
    else:
        ui.ok("No obvious vulnerabilities found")


@analyze.command()
@click.option('--target', '-t', required=True, help='Target protocol name')
@click.option('--addresses', '-a', required=True, help='Comma-separated addresses')
@click.option('--rpc', '-r', envvar='RPC_URL', help='RPC URL')
@click.pass_context
def batch(ctx, target, addresses, rpc):
    """Analyze multiple contracts"""
    addrs = [a.strip() for a in addresses.split(',')]
    analyzer = ContractAnalyzer(rpc_url=rpc)

    ui.rule("ANALYZE BATCH")
    ui.step(f"Target protocol", target)
    all_findings = []

    progress, task = ui.progress_bar(len(addrs), "Analyzing contracts")
    with progress:
        for addr in addrs:
            findings = analyzer.analyze(addr)
            all_findings.extend(findings)
            progress.advance(task)

    if all_findings:
        ui.warn(f"Total findings: {len(all_findings)}")
        ui.console.print(ui.findings_table(all_findings))
    else:
        ui.ok(f"Total findings: 0 — {len(addrs)} contract(s) clean")


@analyze.command()
@click.option('--target', '-t', required=True, help='GitHub repo URL of the protocol (e.g. https://github.com/Layr-Labs/eigenlayer-contracts)')
@click.option('--rpc', '-r', envvar='RPC_URL', help='RPC URL (for optional fork verification)')
@click.option('--json', 'as_json', is_flag=True, help='Write findings to output/analyze_<ts>.json')
@click.option('--no-fork', is_flag=True, help='Skip anvil fork verification')
@click.pass_context
def repo(ctx, target, rpc, as_json, no_fork):
    """Analyze a cloned GitHub repo's Solidity source (no Etherscan key needed).

    Clones the repo, scans every protocol-owned .sol file line-by-line
    (selfdestruct, tx.origin auth, delegatecall, unguarded mint/initialize,
    spot oracles, hardcoded secrets) and optionally proves the callable
    findings on a real anvil mainnet fork.
    """
    from defihunter.core.analyzer import analyze_repo_dir
    from defihunter.core.github import clone
    from defihunter.wizard import _run_fork_verify

    ui.rule("ANALYZE REPO")
    ui.step("Target repo", target)

    with ui.spinner("Cloning repo"):
        repo_dir = clone(target)
    ui.info(f"Cloned to {repo_dir}")

    with ui.spinner("Scanning Solidity source"):
        findings = analyze_repo_dir(str(repo_dir), repo_label=target)
    ui.info(f"Analyzed {len({f['file'] for f in findings})} source file(s) "
            f"({len(findings)} finding(s))")

    if findings:
        ui.console.print(ui.findings_table(findings))
    else:
        ui.ok("No obvious vulnerabilities found in source.")

    fork_results = []
    if findings and not no_fork:
        # Minimal contract map for file->address resolution (best effort).
        from defihunter.core.github import extract_addresses
        contracts = {addr: info for addr, info in extract_addresses(Path(repo_dir)).items()}
        fork_results = _run_fork_verify(findings, contracts, rpc, repo_dir=repo_dir)

    if as_json and findings:
        import json as _json
        from datetime import datetime as _dt
        out_dir = Path("output")
        out_dir.mkdir(exist_ok=True)
        path = out_dir / f"analyze_{_dt.now().strftime('%Y%m%d_%H%M%S')}.json"
        path.write_text(_json.dumps({
            "target": target,
            "vulnerabilities": findings,
            "fork_verified": fork_results,
        }, indent=2))
        ui.ok(f"Findings saved: {path}")

    fork_ok = sum(1 for r in fork_results if r.get("success"))
    all_findings = list(findings) + [{
        "severity": "CRITICAL" if r.get("success") else "MEDIUM",
        "title": f"fork-confirmed {r.get('attack', '')} on {r.get('target', '')[:12]}…",
        "endpoint": r.get("target", ""),
    } for r in fork_results if r.get("success")]
    ui.console.print()
    ui.console.print(ui.attack_surface_gauge(all_findings, analyzed=True))
    ui.console.print(ui.severity_chart(all_findings, analyzed=True))
    ui.hunt_complete([
        ("repo", target),
        ("files analyzed", str(len({f['file'] for f in findings}))),
        ("findings", str(len(findings))),
        ("fork-verified", f"{len(fork_results)} run, {fork_ok} exploitable"),
    ], level=ui.threat_level(all_findings, analyzed=True))


@cli.command()
@click.option('--target', '-t', required=True,
              help='Contract address (0x…) or GitHub repo URL')
@click.option('--rpc', '-r', envvar='RPC_URL', help='Mainnet RPC URL for fork verification')
@click.option('--chain', '-c', default=None,
              help='Target chain (ethereum, bsc, polygon, arbitrum, etc.)')
@click.option('--output', '-o', default='defihunter-scan.json',
              help='JSON report path (default defihunter-scan.json)')
@click.option('--format', '-f', type=click.Choice(['json', 'html', 'markdown', 'pdf']),
              default='json', help='Report format (default: json)')
@click.option('--no-fork', is_flag=True, help='Skip fork verification')
@click.option('--attacker', help='EOA that signs the fork proof txs '
              '(prompted at scan start if missing; default anvil dev 0x3C44…)')
@click.option('--profit-wallet', help='Wallet the attacker-contract drain is '
              'swept to (prompted at scan start if missing; default: the attacker EOA)')
@click.option('--fail-on', type=click.Choice(['none', 'high', 'critical']),
              default='high', show_default=True,
              help='Exit code threshold: none=never fail, high=fail on any '
                   'CONFIRMED high/critical, critical=fail only on CONFIRMED critical')
@click.option('--full-scan', is_flag=True,
              help='Full pipeline: static -> fork -> exploit generation -> report')
@click.option('--exploit-output', default='./exploit',
              help='Output directory for exploit scripts (used with --full-scan)')
def scan(target, rpc, chain, output, format, no_fork, fail_on, attacker, profit_wallet,
         full_scan, exploit_output):
    """CI-friendly one-shot scan: static analysis + ABI-aware fork proof.

    Every finding gets a verdict after fork verification:
      CONFIRMED  — an arbitrary account actually executed the function on a
                   live mainnet fork and the state changed (evidence shown)
      REFUTED    — the function exists (from the real ABI) but every call
                   reverted → NOT callable, removed from the confirmed set
      UNVERIFIED — no ABI/address to prove either way (stays as static only)

    Exits 0 when no confirmed finding meets --fail-on, 1 otherwise. Report
    written to --output in --format. This is the command to wire into CI.
    """
    from defihunter.core.analyzer import analyze_repo_dir
    from defihunter.core.github import clone, extract_addresses
    from defihunter.wizard import _run_fork_verify, resolve_wallets, is_eoa
    from defihunter.core.chains import get_chain, detect_chain_from_rpc
    from datetime import datetime as _dt

    # Resolve chain/RPC
    if chain:
        chain_info = get_chain(chain)
        rpc_url = rpc or chain_info.rpc_url
    elif rpc:
        detected = detect_chain_from_rpc(rpc)
        chain_info = get_chain(detected or "ethereum")
        rpc_url = rpc
    else:
        chain_info = get_chain("ethereum")
        rpc_url = rpc or chain_info.rpc_url

    ui.rule("SCAN")
    ui.step("Target", target)
    ui.step("Chain", chain_info.name)

    # wallet config: validate flags, then prompt for anything missing at the
    # START of the session (silently skipped on non-TTY / --no-fork)
    for name, val in (("attacker", attacker), ("profit-wallet", profit_wallet)):
        if val and not is_eoa(val):
            raise click.ClickException(
                f"Invalid --{name} value {val!r} — need an Ethereum address "
                f"(0x + 40 hex chars)")
    attacker, profit_wallet = resolve_wallets(attacker, profit_wallet,
                                              no_fork=no_fork)

    # 1) static analysis: address scan or repo scan
    is_addr = target.lower().startswith("0x")
    findings = []
    repo_dir = None
    contracts: dict = {}
    if is_addr:
        ui.info("Target is an address — fetching verified source + ABI from Etherscan")
        analyzer = ContractAnalyzer(rpc_url=rpc_url)
        with ui.spinner("Fetching + analyzing verified source"):
            findings = analyzer.analyze(target)
        if not findings:
            ui.ok("No findings in source.")
        else:
            ui.console.print(ui.findings_table(findings))
    else:
        with ui.spinner("Cloning repo"):
            repo_dir = clone(target)
        ui.info(f"Cloned to {repo_dir}")
        with ui.spinner("Scanning Solidity source"):
            findings = analyze_repo_dir(str(repo_dir), repo_label=target)
        ui.info(f"Analyzed {len({f['file'] for f in findings})} source file(s) "
                f"({len(findings)} finding(s))")
        contracts = {addr: info for addr, info
                     in extract_addresses(Path(repo_dir)).items()}
        if findings:
            ui.console.print(ui.findings_table(findings))

    # 2) ABI-aware fork verification (self-correcting verdicts)
    fork_results = []
    if findings and not no_fork:
        if is_addr:
            contracts = {target: {"address": target, "sources": []}}
        fork_results = _run_fork_verify(findings, contracts, rpc_url,
                                        repo_dir=repo_dir,
                                        attacker=attacker,
                                        profit_wallet=profit_wallet)

    # 3) verdicts: CONFIRMED → real; REFUTED → drop from confirmed set;
    #    UNVERIFIED stays as static-only
    confirmed = [r for r in fork_results if r.get("verdict") == "CONFIRMED"]
    refuted = [r for r in fork_results if r.get("verdict") == "REFUTED"]
    report = {
        "tool": "defihunter",
        "version": __version__,
        "generated_at": _dt.utcnow().isoformat() + "Z",
        "target": target,
        "chain": chain_info.name,
        "chain_id": chain_info.chain_id,
        "static_findings": findings,
        "fork_proofs": fork_results,
        "verdicts": {
            "confirmed": len(confirmed),
            "refuted": len(refuted),
            "unverified": sum(1 for r in fork_results
                              if r.get("verdict") == "UNVERIFIED"),
        },
        "summary": {
            "static": len(findings),
            "fork_confirmed": len(confirmed),
            "fork_refuted": len(refuted),
        },
    }
    Path(output).write_text(json.dumps(report, indent=2))
    ui.ok(f"Report written: {output}")

    # Generate professional report if requested
    if format != "json":
        from defihunter.core.reporter import ReportGenerator
        gen = ReportGenerator()
        report_file = output.rsplit(".", 1)[0] + ("." + format if format != "markdown" else ".md")
        gen.generate(report, format=format, output=report_file)
        ui.ok(f"Professional report: {report_file}")

    if not fork_results:
        ui.info("No fork verification ran (--no-fork, no RPC, or no attack "
                "routes) — static findings only, not self-corrected.")

    # 4) exit code for CI: fail on CONFIRMED findings meeting the threshold
    if fail_on != "none" and confirmed:
        threshold = "CRITICAL" if fail_on == "critical" else "HIGH"
        bad = [r for r in confirmed
               if (r.get("source_finding") or {}).get("severity")
               in ("HIGH", "CRITICAL")
               and (r.get("source_finding") or {}).get("severity")
               in (threshold, "CRITICAL")]
        if bad:
            ui.warn(f"{len(bad)} CONFIRMED {threshold}+ fork-proof(s) — "
                    f"exit code 1 (--fail-on={fail_on})")
            raise SystemExit(1)

    # 5) full-scan pipeline: generate exploits + final report
    if full_scan and confirmed:
        from defihunter.core.exploit_generator import ExploitGenerator

        ui.rule("FULL SCAN -- EXPLOIT GENERATION")
        gen = ExploitGenerator(output_dir=exploit_output)
        exploits_generated = 0

        for proof in confirmed:
            src = proof.get("source_finding") or {}
            attack = src.get("attack") or src.get("type", "")
            if not attack:
                continue
            try:
                result = gen.generate(attack, target)
                if result and result.get("contracts"):
                    exploits_generated += 1
                    ui.ok(f"Generated exploit for {attack}")
            except Exception as e:
                ui.warn(f"Could not generate exploit for {attack}: {e}")

        ui.step("Exploits generated", str(exploits_generated))

        # Final consolidated report
        report["exploit_scripts"] = exploits_generated
        report["exploit_dir"] = str(Path(exploit_output).resolve())
        Path(output).write_text(json.dumps(report, indent=2))

        # Generate final professional report
        final_format = format if format != "json" else "html"
        from defihunter.core.reporter import ReportGenerator
        final_gen = ReportGenerator()
        final_file = output.rsplit(".", 1)[0] + ("." + final_format if final_format != "markdown" else ".md")
        final_gen.generate(report, format=final_format, output=final_file)
        ui.ok(f"Final report: {final_file}")

    ui.ok(f"Scan complete: {len(confirmed)} confirmed, {len(refuted)} refuted "
          f"— exit 0")


@cli.command()
@click.option('--json', 'as_json', is_flag=True, help='Emit machine-readable JSON for CI')
def benchmark(as_json):
    """Score the analyzer against historical exploits (DAO, Parity, OZ…).

    Analyzes a built-in corpus of real vulnerability classes and reports
    how many the static engine detects — plus false positives on a clean,
    properly-guarded vault. No network or RPC needed.
    """
    from defihunter.core.benchmark import run_benchmark, summarize
    ui.rule("HISTORICAL-EXPLOIT BENCHMARK")
    with ui.spinner("Analyzing exploit corpus"):
        results = run_benchmark()

    if as_json:
        print(json.dumps([{k: r[k] for k in
                           ("id", "ref", "control", "detected", "missed")}
                          for r in results], indent=2))
        return

    from rich.table import Table
    from rich.panel import Panel
    from rich import box as _box
    table = Table(box=_box.ROUNDED, border_style="cyan",
                  header_style="bold cyan", expand=True)
    table.add_column("CASE", style="bold white", max_width=28, overflow="fold")
    table.add_column("HISTORICAL REFERENCE", style="dim", overflow="fold")
    table.add_column("RESULT", justify="center")
    for r in results:
        tag = "control" if r["control"] else "exploit"
        verdict = ("✅ DETECTED" if r["detected"]
                   else "❌ MISSED" if not r["control"]
                   else "❌ FALSE POSITIVE")
        table.add_row(f"{r['id']}  ({tag})", r["ref"], verdict)
    ui.console.print(table)
    ui.console.print()

    s = summarize(results)
    title = (f"Detected {s['detected']}/{s['total']} benchmark cases "
             f"({s['pct']}%) — {s['false_positives']} false "
             f"positive(s) on {s['control_count']} clean control(s)")
    ui.console.print(Panel(title, border_style="bright_green"
                           if s["detected"] == s["total"] else "bright_red",
                           box=_box.DOUBLE, expand=False))


@cli.group()
@click.pass_context
def simulate(ctx):
    """Simulate attacks on fork"""
    pass


@simulate.command()
@click.option('--attack', '-a', type=click.Choice([
    'inflation', 'admin', 'governance', 'oracle', 'reentrancy', 'bridge',
    'sandwich', 'twap', 'flashloan', 'withdraw', 'initialize', 'permit',
    'liquidation', 'forcesend', 'peg', 'crossfunc', 'delegatecall', 'mint',
    'arbitrarycall', 'selfdestruct', 'approve', 'frontrun', 'mev',
]), required=True)
@click.option('--target', '-t', required=True, help='Target contract address')
@click.option('--rpc', '-r', envvar='RPC_URL', help='RPC URL')
@click.option('--chain', '-c', default=None, help='Chain (auto-detects RPC if not set)')
@click.option('--block', '-b', type=int, help='Fork block number')
@click.option('--format', '-f', type=click.Choice(['json', 'text']), default='text',
              help='Output format')
@click.option('--mint-pct', type=int, default=10,
              help='Percentage of total supply to mint for mint attack (default: 10%%)')
@click.pass_context
def run(ctx, attack, target, rpc, chain, block, format, mint_pct):
    """Run attack simulation on a real fork"""
    from defihunter.core.chains import get_chain, detect_chain_from_rpc
    from defihunter.core.simulator import ForkSimulator

    # Resolve chain/RPC
    if chain:
        chain_info = get_chain(chain)
        rpc_url = rpc or chain_info.rpc_url
    elif rpc:
        detected = detect_chain_from_rpc(rpc)
        chain_info = get_chain(detected or "ethereum")
        rpc_url = rpc
    else:
        chain_info = get_chain("ethereum")
        rpc_url = chain_info.rpc_url

    ui.rule("SIMULATE")
    ui.step("Attack", attack)
    ui.step("Target", target)
    ui.step("Chain", chain_info.name)

    # Try ForkSimulator first (real fork verification)
    with ui.spinner(f"Running {attack} on {chain_info.name} fork"):
        try:
            with ForkSimulator(rpc_url=rpc_url, block=block) as fork:
                if fork.available:
                    fork._mint_pct = mint_pct  # configure mint percentage
                    result = fork.run(attack, target)
                else:
                    # Fallback to AttackSimulator (static analysis)
                    simulator = AttackSimulator(rpc_url=rpc_url, block=block)
                    result = simulator.run(attack, target)
        except Exception:
            simulator = AttackSimulator(rpc_url=rpc_url, block=block)
            result = simulator.run(attack, target)

    if format == "json":
        print(json.dumps(result, indent=2))
    else:
        ui.console.print(ui.attack_summary(result, attack, target))


@cli.command()
@click.option('--input', '-i', required=True, help='Input findings JSON')
@click.option('--output', '-o', required=True, help='Output file')
@click.option('--format', '-f', type=click.Choice(['html', 'json', 'markdown', 'sarif', 'pdf']), default='html')
@click.option('--diagram', '-d', multiple=True,
              type=click.Choice(['attack_flow', 'call_graph', 'storage_layout']),
              help='Embed Mermaid diagram(s) in the report (repeatable)')
@click.option('--template', '-t', default=None,
              help='Custom Jinja2 HTML template path')
@click.option('--sync', '-s', type=click.Choice(['github', 'jira']), default=None,
              help='Push findings to an issue tracker after rendering')
@click.option('--repo', default=None, help='GitHub repo (owner/name) for --sync github')
@click.option('--project', default=None, help='Jira project key for --sync jira')
@click.option('--dry-run', is_flag=True, help='Print tickets instead of creating them')
def report(input, output, format, diagram, template, sync, repo, project, dry_run):
    """Generate professional security assessment report"""
    gen = ReportGenerator()

    findings = json.loads(Path(input).read_text())
    ui.rule("REPORT")
    ui.step("Generating", f"{format} → {output}")
    with ui.spinner("Rendering report"):
        report_path = gen.generate(findings, format=format, output=output,
                                   diagrams=list(diagram) or None,
                                   template=template)

    ui.ok(f"Report saved to {report_path}")

    if sync:
        from defihunter.core.sync import sync_github, sync_jira
        vulns = findings.get("vulnerabilities", [])
        if sync == "github":
            if not repo:
                ui.warn("--repo owner/name required for GitHub sync — skipped")
                return
            ui.step("Syncing", f"{len(vulns)} finding(s) → GitHub {repo}")
            res = sync_github(vulns, *repo.split("/", 1), dry_run=dry_run)
        else:
            if not project:
                ui.warn("--project KEY required for Jira sync — skipped")
                return
            ui.step("Syncing", f"{len(vulns)} finding(s) → Jira {project}")
            res = sync_jira(vulns, os.getenv("JIRA_BASE_URL", ""), project,
                            dry_run=dry_run)
        if dry_run:
            ui.info(f"DRY-RUN: would create {len(res.get('created', []))} ticket(s)")
        else:
            ui.ok(f"Created {len(res.get('created', []))} ticket(s), "
                  f"skipped {res.get('skipped', 0)}")


@cli.group()
def chains():
    """List and manage supported blockchain networks"""
    pass


@chains.command('list')
def chains_list():
    """Show all supported chains with RPC endpoints"""
    from defihunter.core.chains import CHAINS, list_chains
    from rich.table import Table
    from rich import box as _box

    ui.rule("SUPPORTED CHAINS")
    table = Table(box=_box.ROUNDED, border_style="cyan",
                  header_style="bold cyan", expand=True)
    table.add_column("Chain", style="bold white")
    table.add_column("ID", justify="right")
    table.add_column("Native", justify="center")
    table.add_column("Block Time", justify="center")
    table.add_column("Explorer", overflow="fold")

    for name in list_chains():
        info = CHAINS[name]
        table.add_row(
            info.name,
            str(info.chain_id),
            info.native_token,
            f"{info.block_time}s",
            info.explorer_url,
        )
    ui.console.print(table)
    ui.console.print()
    ui.ok(f"{len(CHAINS)} chains supported")


@chains.command('detect')
@click.argument('rpc_url')
def chains_detect(rpc_url):
    """Detect which chain an RPC URL points to"""
    from defihunter.core.chains import detect_chain_from_rpc, get_chain

    chain_name = detect_chain_from_rpc(rpc_url)
    if chain_name:
        info = get_chain(chain_name)
        ui.ok(f"Detected: {info.name} (chain_id={info.chain_id})")
    else:
        ui.warn("Could not detect chain from RPC URL")


@cli.command()
@click.option('--targets', '-t', required=True,
              help='Comma-separated contract addresses or repo URLs')
@click.option('--chain', '-c', default='ethereum',
              help='Target chain (ethereum, bsc, polygon, arbitrum, etc.)')
@click.option('--rpc', '-r', envvar='RPC_URL', help='RPC URL (overrides chain default)')
@click.option('--attacks', '-a', default='all',
              help='Comma-separated attack types, or "all" (default: all)')
@click.option('--output-dir', '-o', default='output/batch',
              help='Output directory for reports')
@click.option('--format', '-f', type=click.Choice(['html', 'json', 'markdown']),
              default='html', help='Report format (default: html)')
@click.option('--no-fork', is_flag=True, help='Skip fork verification')
def batch(targets, chain, rpc, attacks, output_dir, format, no_fork):
    """Batch scan multiple targets with professional reports"""
    from defihunter.core.chains import get_chain
    from defihunter.core.simulator import ForkSimulator
    from defihunter.core.analyzer import ContractAnalyzer
    from defihunter.core.reporter import ReportGenerator
    from datetime import datetime as _dt

    target_list = [t.strip() for t in targets.split(',') if t.strip()]
    chain_info = get_chain(chain)
    rpc_url = rpc or chain_info.rpc_url

    ui.rule("BATCH SCAN")
    ui.step("Targets", str(len(target_list)))
    ui.step("Chain", chain_info.name)
    ui.step("Format", format)

    out_dir = Path(output_dir)
    out_dir.mkdir(parents=True, exist_ok=True)

    all_results = []
    progress, task = ui.progress_bar(len(target_list), "Scanning targets")
    with progress:
        for target in target_list:
            ui.info(f"Scanning: {target}")
            result = {"target": target, "chain": chain, "vulnerabilities": [],
                      "contracts": {}, "scan_time": _dt.now().isoformat(),
                      "tool_version": __version__}

            # Static analysis
            is_addr = target.lower().startswith("0x")
            findings = []
            if is_addr:
                analyzer = ContractAnalyzer(rpc_url=rpc_url)
                findings = analyzer.analyze(target)
                result["contracts"][target] = {"name": "Unknown", "code_size": 0}
            else:
                try:
                    from defihunter.core.analyzer import analyze_repo_dir
                    from defihunter.core.github import clone, extract_addresses
                    repo_dir = clone(target)
                    findings = analyze_repo_dir(str(repo_dir), repo_label=target)
                    contracts = {addr: info for addr, info
                                 in extract_addresses(repo_dir).items()}
                    result["contracts"] = contracts
                except Exception as e:
                    ui.warn(f"Failed to clone/analyze {target}: {e}")

            result["vulnerabilities"] = findings

            # Fork verification
            if not no_fork and is_addr and rpc_url:
                try:
                    with ForkSimulator(rpc_url=rpc_url) as fork:
                        if fork.available:
                            attack_types = (["mint", "initialize", "reentrancy",
                                            "approve", "delegatecall", "selfdestruct",
                                            "oracle", "flashloan", "governance",
                                            "bridge", "twap", "crossfunc", "permit",
                                            "liquidation", "forcesend", "peg",
                                            "sandwich", "frontrun", "mev"]
                                           if attacks == "all"
                                           else [a.strip() for a in attacks.split(",")])
                            for atype in attack_types:
                                r = fork.run(atype, target)
                                if r.get("success"):
                                    result["vulnerabilities"].append({
                                        "severity": "CRITICAL",
                                        "title": f"Fork-confirmed {atype}",
                                        "attack": atype,
                                        "evidence": r.get("evidence", ""),
                                        "steps": r.get("steps", []),
                                        "description": r.get("profit", ""),
                                    })
                except Exception as e:
                    ui.warn(f"Fork verification failed for {target}: {e}")

            all_results.append(result)

            # Generate individual report
            report_file = out_dir / f"{target[:20]}_{_dt.now().strftime('%Y%m%d_%H%M%S')}.{format if format != 'markdown' else 'md'}"
            gen = ReportGenerator()
            gen.generate(result, format=format, output=str(report_file))
            ui.ok(f"Report: {report_file}")

            progress.advance(task)

    # Summary
    total_vulns = sum(len(r.get("vulnerabilities", [])) for r in all_results)
    critical = sum(1 for r in all_results
                   for v in r.get("vulnerabilities", [])
                   if v.get("severity") == "CRITICAL")
    high = sum(1 for r in all_results
               for v in r.get("vulnerabilities", [])
               if v.get("severity") == "HIGH")

    ui.console.print()
    ui.console.print(ui.summary_panel([
        ("targets scanned", str(len(target_list))),
        ("total findings", str(total_vulns)),
        ("critical", str(critical)),
        ("high", str(high)),
        ("reports", str(out_dir)),
    ]))
    ui.ok(f"Batch scan complete: {len(target_list)} targets, {total_vulns} findings")


@cli.command()
@click.option('--target', '-t', required=True, help='Target contract address (0x...)')
@click.option('--attack', '-a', default=None,
              type=click.Choice(['reentrancy', 'mint', 'initialize', 'flashloan', 'permit',
                                 'delegatecall', 'oracle', 'selfdestruct', 'arbitrarycall',
                                 'approve', 'governance']),
              help='Attack type to generate exploit for')
@click.option('--rpc', '-r', envvar='RPC_URL', help='RPC URL (for auto-detection)')
@click.option('--output', '-o', default='./exploit', help='Output directory (default: ./exploit)')
@click.option('--all', 'all_attacks', is_flag=True, help='Generate exploits for all attack types')
@click.option('--execute', '-x', is_flag=True,
              help='Execute exploit against live fork (real proof)')
@click.option('--attacker', default=None, help='Attacker EOA address (default: 0x3C44...293BC)')
@click.option('--token', default=None, help='ERC20 token address for balance tracking')
def exploit(target, attack, rpc, output, all_attacks, execute, attacker, token):
    """Generate ready-to-run Foundry exploit scripts.

    With --execute: deploys and executes against a live mainnet fork,
    capturing real balance changes as proof.

    Produces:
      - contracts/Exploit*.sol  -- attacker contract
      - scripts/run-exploit.s.sol -- Foundry script
      - .env -- environment variables
    """
    from defihunter.core.exploit_generator import ExploitGenerator
    from rich import box

    if not all_attacks and not attack:
        raise click.UsageError("Either --attack or --all is required")

    ui.rule("EXPLOIT GENERATOR")
    ui.step("Target", target)
    ui.step("Output", output)
    if execute:
        ui.step("Mode", "LIVE EXECUTION")
    if rpc:
        ui.step("RPC", rpc[:60] + "..." if len(rpc) > 60 else rpc)

    gen = ExploitGenerator(output_dir=output)

    if all_attacks:
        ui.info("Generating exploits for ALL attack types...")
        results = gen.generate_all(target)
        for r in results:
            ui.ok(f"Generated: {r['attack_type']}")
    else:
        ui.info(f"Generating exploit for: {attack}")
        results = [gen.generate(attack, target)]

    # Summary
    ui.console.print()
    ui.console.print(ui.summary_panel([
        ("target", target),
        ("exploits generated", str(len(results))),
        ("output directory", output),
        ("attack types", ", ".join(r.get("attack_type", attack) for r in results)),
    ]))

    # LIVE EXECUTION
    if execute and rpc:
        from defihunter.core.exploit_executor import ExploitExecutor, format_proof

        ui.console.print()
        ui.rule("LIVE EXPLOIT EXECUTION")

        executor = ExploitExecutor(
            rpc_url=rpc,
            attacker=attacker,
            profit_wallet=attacker,
        )

        for r in results:
            atk = r.get("attack_type", attack)
            ui.step(f"Executing", atk)

            extra = {}
            if token:
                extra["token"] = token

            with ui.spinner(f"Running {atk} against {target[:10]}..."):
                proof = executor.execute(
                    attack_type=atk,
                    target=target,
                    exploit_dir=output,
                    extra=extra,
                )

            # Display proof
            ui.console.print()
            if proof.get("success"):
                ui.console.print(ui.Panel(
                    format_proof(proof),
                    title=f"[bold green][+] {atk.upper()} -- EXPLOIT PROVEN[/]",
                    border_style="green",
                    box=box.HEAVY,
                ))
            else:
                ui.console.print(ui.Panel(
                    format_proof(proof),
                    title=f"[bold red][-] {atk.upper()} -- REFUTED[/]",
                    border_style="red",
                    box=box.HEAVY,
                ))

        ui.console.print()
        ui.ok("Live execution complete.")
    elif execute and not rpc:
        ui.console.print()
        ui.warning_box("--execute requires --rpc. Using default RPC from config.")
        ui.info("Set RPC: defihunter config set-rpc <url>")

    # Instructions (only if not executing)
    if not execute:
        ui.console.print()
        ui.info("To run the exploit:")
        ui.console.print(f"  cd {output}")
        ui.console.print("  forge install foundry-rs/forge-std --no-commit")
        ui.console.print("  # Edit .env with your values")
        ui.console.print("  forge script scripts/run-exploit.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast")
        ui.console.print()
        ui.info("Or execute live with --execute --rpc <url>")

    ui.ok(f"Exploit scripts ready in {output}/")


@cli.command()
@click.option('--output', '-o', default='./flashloan-exploit', help='Output directory')
@click.option('--loan-token', default='USDC', help='Token to borrow (USDC, USDT, DAI, WETH)')
@click.option('--loan-amount', default='10000000', help='Amount to borrow (in token units, e.g. 10M USDC)')
@click.option('--pool', default='aave', type=click.Choice(['aave', 'uniswap', 'balancer']),
              help='Flash loan provider')
def flashloan(output, loan_token, loan_amount, pool):
    """Generate flash loan exploit scripts (Aave/Uniswap/Balancer).

    Produces a ready-to-run Foundry project that:
    1. Borrows millions via flash loan
    2. Executes exploit steps
    3. Repays loan + fee
    4. Sweeps profit
    """
    from defihunter.core.flashloan import FlashLoanExploit, AAVE_V3_POOL, TOKENS

    ui.rule("FLASH LOAN EXPLOIT GENERATOR")
    ui.step("Pool", pool)
    ui.step("Loan Token", loan_token)
    ui.step("Loan Amount", loan_amount)
    ui.step("Output", output)

    exploit = FlashLoanExploit()

    # Set pool
    if pool == "aave":
        exploit.pool = AAVE_V3_POOL
    elif pool == "uniswap":
        exploit.pool = "0x88e6A0c2dDD26FEEb64F039a2c41296FcB3f5640"  # USDC/WETH pool
    elif pool == "balancer":
        exploit.pool = "0xBA12222222228d8Ba445958a75a0704d566BF2C8"

    exploit.loan_token = loan_token
    exploit.loanAmount = int(loan_amount) * (10 ** 6 if loan_token in ("USDC", "USDT") else 10 ** 18)

    files = exploit.save(output)

    ui.console.print()
    ui.info("Files generated:")
    for name, path in files.items():
        ui.step(name, path)

    ui.console.print()
    ui.info("To run:")
    ui.console.print(f"  cd {output}")
    ui.console.print("  forge install foundry-rs/forge-std --no-commit")
    ui.console.print("  forge script scripts/run-flashloan.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast")

    ui.ok(f"Flash loan exploit ready in {output}/")


@cli.command()
@click.option('--output', '-o', default='./mev-tools', help='Output directory')
@click.option('--relay', default='flashbots', type=click.Choice(['flashbots', 'bloxroute', 'eden']),
              help='MEV relay to use')
def mev(output, relay):
    """Generate MEV tools — Flashbots bundle submission + anti-sandwich protection.

    Produces:
      - SendBundle.sol — submit exploits privately via Flashbots
      - MEVProtection.sol — protect users from sandwich attacks
    """
    from defihunter.core.mev import MEVBundle

    ui.rule("MEV TOOLS GENERATOR")
    ui.step("Relay", relay)
    ui.step("Output", output)

    bundle = MEVBundle()
    files = bundle.save(output)

    ui.console.print()
    ui.info("Files generated:")
    for name, path in files.items():
        ui.step(name, path)

    ui.console.print()
    ui.info("Usage:")
    ui.console.print("  SendBundle.sol — submit exploit txs privately (no mempool)")
    ui.console.print("  MEVProtection.sol — protect users from sandwich attacks")

    ui.ok(f"MEV tools ready in {output}/")


@cli.command()
@click.option('--protocols', '-p', required=True,
              help='Comma-separated protocols: name:address:type,... '
                   '(type: flash_loan, dex, vault, lending, bridge, governance)')
@click.option('--output', '-o', default='./chain-exploit', help='Output directory')
def chain(protocols, output):
    """Generate cross-protocol exploit chains.

    Chain multiple protocols: Aave → Uniswap → Victim Vault → Profit

    Example:
      defihunter chain -p "aave:0x87870Bca...:flash_loan,uniswap:0x88e6A0c...:dex,victim:0x...:vault"
    """
    from defihunter.core.chaining import ExploitChain

    ui.rule("CROSS-PROTOCOL EXPLOIT CHAIN")
    ui.step("Output", output)

    exploit_chain = ExploitChain()

    # Parse protocols
    for proto_str in protocols.split(","):
        parts = proto_str.strip().split(":")
        if len(parts) != 3:
            ui.warn(f"Invalid protocol format: {proto_str} (expected name:address:type)")
            continue
        name, address, proto_type = parts
        exploit_chain.add_protocol(name.strip(), address.strip(), proto_type.strip())
        ui.step(f"Protocol: {name.strip()}", f"{proto_type.strip()} @ {address.strip()}")

    files = exploit_chain.save(output)

    ui.console.print()
    ui.info("Files generated:")
    for name, path in files.items():
        ui.step(name, path)

    ui.console.print()
    ui.info("To run:")
    ui.console.print(f"  cd {output}")
    ui.console.print("  forge install foundry-rs/forge-std --no-commit")
    ui.console.print("  forge script scripts/run-chain.s.sol --rpc-url $RPC_URL --private-key $PRIVATE_KEY --broadcast")

    ui.ok(f"Cross-protocol exploit chain ready in {output}/")


@cli.command()
@click.option('--address', '-a', multiple=True, help='Address to monitor (can repeat)')
@click.option('--chain', '-c', default='ethereum', help='Chain to monitor')
@click.option('--interval', '-i', default=12, help='Poll interval in seconds')
@click.option('--alert', default='console', type=click.Choice(['console', 'telegram', 'discord']),
              help='Alert destination')
@click.option('--output', '-o', default='./monitor', help='Output directory')
def monitor(address, chain, interval, alert, output):
    """Real-time vulnerability monitoring — watch 24/7, alert on new vulns.

    Monitors:
      - New contract deployments
      - Suspicious transactions
      - Vulnerability patterns
      - Flash loan attacks in progress
    """
    from defihunter.core.monitor import VulnerabilityMonitor

    ui.rule("VULNERABILITY MONITOR")
    ui.step("Chain", chain)
    ui.step("Poll Interval", f"{interval}s")
    ui.step("Alerts", alert)
    ui.step("Output", output)

    mon = VulnerabilityMonitor(chain=chain, poll_interval=interval)

    for addr in address:
        mon.watch_address(addr)
        ui.step("Watching", addr)

    files = mon.save(output)

    ui.console.print()
    ui.info("Files generated:")
    for name, path in files.items():
        ui.step(name, path)

    ui.console.print()
    ui.info(f"Start monitoring:")
    ui.console.print(f"  cd {output}")
    if alert == "telegram":
        ui.console.print("  python telegram_bot.py")
    elif alert == "discord":
        ui.console.print("  python discord_webhook.py")
    else:
        ui.console.print("  python -c 'from monitor import VulnerabilityMonitor; ...'")

    ui.ok(f"Monitor tools ready in {output}/")


@cli.group()
@click.pass_context
def templates(ctx):
    """Explore and verify attack templates"""
    pass


@templates.command('list')
@click.option('--type', '-t', type=click.Choice(['vault', 'amm', 'lending', 'bridge', 'governance', 'stablecoin', 'token', 'proxy', 'all']), default='all')
def templates_list(type):
    """List available attack templates"""
    from defihunter.templates import TEMPLATES

    selected = {name: tpl for name, tpl in TEMPLATES.items()
                if type == 'all' or tpl.get('type') == type}

    ui.rule("TEMPLATES")
    ui.console.print(ui.templates_table(selected))
    ui.console.print()
    ui.ok(f"{len(selected)} template(s) available"
          + ("" if type == 'all' else f" (type: {type})"))


@templates.command('verify')
@click.option('--lab-dir', '-l', type=click.Path(), help='Path to the Foundry lab (defaults to <package root>/../lab)')
def templates_verify(lab_dir):
    """Run the Foundry lab suite, proving every template exploit"""
    import subprocess
    from defihunter.templates import TEMPLATES
    root = Path(__file__).resolve().parent.parent
    lab = Path(lab_dir) if lab_dir else root / 'lab'
    if not (lab / 'foundry.toml').exists():
        raise click.ClickException(
            f"No Foundry lab found at {lab}. Run scripts/export_templates.py then forge build first."
        )
    ui.rule("VERIFY")
    ui.step("Foundry lab", str(lab))
    ui.info(f"Verifying {len(TEMPLATES)} templates — this runs `forge test`")
    with ui.spinner("forge test"):
        proc = subprocess.run(['forge', 'test'], cwd=str(lab))
    if proc.returncode != 0:
        raise click.ClickException("Template verification FAILED (see forge output above)")
    ui.ok("All template exploits verified")


# ---------------------------------------------------------------------------
# Sentinel commands
# ---------------------------------------------------------------------------

@cli.group()
def sentinel():
    """Sentinel -- continuous DeFi protocol monitoring and threat detection."""
    pass


@sentinel.command("add")
@click.option('--name', '-n', required=True, help='Protocol name')
@click.option('--chain', '-c', default='ethereum', help='Chain')
@click.option('--address', '-a', multiple=True, help='Contract address (can repeat)')
@click.option('--website', '-w', default=None, help='Protocol website')
def sentinel_add(name, chain, address, website):
    """Add a protocol to the Sentinel monitoring list."""
    from defihunter.sentinel.database import SentinelDB

    db = SentinelDB()
    db.connect()

    pid = db.add_protocol(
        name=name,
        chain=chain,
        addresses=list(address),
        website=website,
    )
    db.close()

    ui.ok(f"Added {name} ({chain}) to Sentinel monitoring (id={pid})")
    ui.info(f"Run: defihunter sentinel scan --name {name}")


@sentinel.command("list")
def sentinel_list():
    """List all monitored protocols."""
    from defihunter.sentinel.database import SentinelDB
    from rich.table import Table as RichTable
    from rich import box

    db = SentinelDB()
    db.connect()
    protocols = db.list_protocols()
    db.close()

    if not protocols:
        ui.info("No protocols monitored. Add one with: defihunter sentinel add -n <name>")
        return

    table = RichTable(title="Monitored Protocols", box=box.SIMPLE_HEAVY,
                      border_style="green", header_style="bold green")
    table.add_column("#", style="muted", justify="right")
    table.add_column("Name", style="bold white")
    table.add_column("Chain", style="accent")
    table.add_column("Addresses", style="addr")
    table.add_column("Last Scan", style="muted")
    table.add_column("Status", style="bold")

    for i, p in enumerate(protocols, 1):
        addrs = json.loads(p.get("addresses", "[]"))
        last_scan = p.get("last_scan")
        if last_scan:
            import time as _t
            age = _t.time() - last_scan
            if age < 3600:
                scan_str = f"{int(age / 60)}m ago"
            elif age < 86400:
                scan_str = f"{int(age / 3600)}h ago"
            else:
                scan_str = f"{int(age / 86400)}d ago"
        else:
            scan_str = "never"

        table.add_row(
            str(i),
            p["name"],
            p.get("chain", "ethereum"),
            ", ".join(a[:10] + "..." for a in addrs[:3]) + (f" +{len(addrs)-3}" if len(addrs) > 3 else ""),
            scan_str,
            p.get("status", "active"),
        )

    ui.console.print(table)


@sentinel.command("scan")
@click.option('--name', '-n', required=True, help='Protocol name to scan')
@click.option('--rpc', '-r', envvar='RPC_URL', help='RPC URL')
def sentinel_scan(name, rpc):
    """Immediately scan a protocol."""
    from defihunter.sentinel.database import SentinelDB

    db = SentinelDB()
    db.connect()

    protocol = db.get_protocol_by_name(name)
    if not protocol:
        db.close()
        ui.error(f"Protocol '{name}' not found. Add it first: defihunter sentinel add -n {name}")
        return

    db.close()

    from defihunter.sentinel.service import SentinelService
    service = SentinelService(rpc_url=rpc)
    result = service.scan_now(protocol["id"])

    if result:
        score = result.get("score", 0)
        findings = result.get("findings_count", 0)
        verdict = result.get("verdict", "UNKNOWN")
        ui.console.print()
        ui.console.print(ui.summary_panel([
            ("protocol", name),
            ("score", f"{score:.0f}/100"),
            ("verdict", verdict),
            ("findings", str(findings)),
            ("critical", str(result.get("critical", 0))),
            ("high", str(result.get("high", 0))),
            ("medium", str(result.get("medium", 0))),
            ("low", str(result.get("low", 0))),
        ], title="Scan Result"))
    else:
        ui.warn("Scan completed but no results recorded.")


@sentinel.command("status")
def sentinel_status():
    """Show Sentinel monitoring status and statistics."""
    from defihunter.sentinel.database import SentinelDB
    import time as _t

    db = SentinelDB()
    db.connect()
    stats = db.get_stats()
    protocols = db.list_protocols()
    recent_alerts = db.get_alert_history(limit=5)
    db.close()

    ui.console.print()
    ui.console.print(ui.summary_panel([
        ("monitored protocols", str(stats["protocols"])),
        ("total scans", str(stats["total_scans"])),
        ("total findings", str(stats["total_findings"])),
        ("pending alerts", str(stats["pending_alerts"])),
        ("CRITICAL findings", str(stats["critical_total"])),
        ("HIGH findings", str(stats["high_total"])),
        ("MEDIUM findings", str(stats["medium_total"])),
    ], title="Sentinel Status"))

    if recent_alerts:
        ui.console.print()
        ui.info("Recent alerts:")
        for a in recent_alerts:
            sent = a.get("sent_at")
            if sent:
                age = _t.time() - sent
                if age < 3600:
                    age_str = f"{int(age / 60)}m ago"
                else:
                    age_str = f"{int(age / 3600)}h ago"
            else:
                age_str = "pending"
            sev = a.get("severity", "?")
            proto = a.get("protocol_name", "?")
            msg = a.get("message", "")[:60]
            ui.console.print(f"  [{sev}] {proto} -- {msg} ({age_str})")


@sentinel.command("start")
@click.option('--rpc', '-r', envvar='RPC_URL', help='RPC URL')
@click.option('--scan-interval', '-s', default=3600, help='Re-scan interval in seconds (ignored if --cron set)')
@click.option('--watch-interval', '-w', default=300, help='Deployment check interval in seconds')
@click.option('--cron', default=None,
              help='Cron expression for scan scheduling (e.g. "*/30 * * * *" = every 30 min, '
                   '"0 */6 * * *" = every 6 hours). Overrides --scan-interval.')
@click.option('--telegram-token', default=None, help='Telegram bot token')
@click.option('--telegram-chat', default=None, help='Telegram chat ID')
@click.option('--discord-webhook', default=None, help='Discord webhook URL')
def sentinel_start(rpc, scan_interval, watch_interval, cron, telegram_token, telegram_chat, discord_webhook):
    """Start the Sentinel monitoring daemon.

    Runs continuously, watching for new deployments and protocol changes.

    Scheduling:
      --cron "*/30 * * * *"   scan every 30 minutes
      --cron "0 */6 * * *"    scan every 6 hours (recommended)
      --cron "0 9 * * 1-5"    scan at 9am on weekdays
      --scan-interval 3600    fallback: scan every N seconds
    """
    from defihunter.sentinel.service import SentinelService
    from defihunter.sentinel.alerts import TelegramAlert, DiscordAlert

    service = SentinelService(
        rpc_url=rpc,
        scan_interval=scan_interval,
        watch_interval=watch_interval,
        scan_schedule=cron,
    )

    # Configure alert channels
    if telegram_token and telegram_chat:
        service.alerts.add_channel(TelegramAlert(telegram_token, telegram_chat))
        ui.ok("Telegram alerts configured")
    if discord_webhook:
        service.alerts.add_channel(DiscordAlert(discord_webhook))
        ui.ok("Discord alerts configured")

    ui.rule("SENTINEL STARTED")
    ui.info("Press Ctrl+C to stop")

    try:
        service.start()
    except KeyboardInterrupt:
        service.stop()
        ui.ok("Sentinel stopped.")


@sentinel.command("history")
@click.option('--name', '-n', required=True, help='Protocol name')
@click.option('--limit', '-l', default=10, help='Number of scans to show')
def sentinel_history(name, limit):
    """Show scan history for a protocol."""
    from defihunter.sentinel.database import SentinelDB
    from rich.table import Table as RichTable
    from rich import box
    from rich.text import Text
    import time as _t

    db = SentinelDB()
    db.connect()
    protocol = db.get_protocol_by_name(name)
    if not protocol:
        db.close()
        ui.error(f"Protocol '{name}' not found.")
        return

    history = db.get_scan_history(protocol["id"], limit=limit)
    db.close()

    if not history:
        ui.info(f"No scan history for {name}.")
        return

    table = RichTable(title=f"Scan History: {name}", box=box.SIMPLE_HEAVY,
                      border_style="green", header_style="bold green")
    table.add_column("Date", style="muted")
    table.add_column("Score", style="bold")
    table.add_column("Verdict", style="bold")
    table.add_column("Findings", justify="right")
    table.add_column("CRIT", justify="right", style="red")
    table.add_column("HIGH", justify="right", style="red")
    table.add_column("MED", justify="right", style="yellow")
    table.add_column("LOW", justify="right", style="green")
    table.add_column("Duration", justify="right", style="muted")

    for s in history:
        ts = s.get("timestamp", 0)
        date_str = _t.strftime("%Y-%m-%d %H:%M", _t.localtime(ts))
        score = s.get("score", 0)
        score_style = "green" if score >= 80 else "yellow" if score >= 50 else "red"
        table.add_row(
            date_str,
            Text(f"{score:.0f}", style=score_style),
            s.get("verdict", "?"),
            str(s.get("findings_count", 0)),
            str(s.get("critical", 0)),
            str(s.get("high", 0)),
            str(s.get("medium", 0)),
            str(s.get("low", 0)),
            f"{s.get('duration_s', 0):.1f}s",
        )

    ui.console.print(table)


@sentinel.command("threats")
@click.option('--limit', '-l', default=10, help='Number of threats to show')
def sentinel_threats(limit):
    """Show recent threat intelligence."""
    from defihunter.sentinel.database import SentinelDB
    from rich.table import Table as RichTable
    from rich import box

    db = SentinelDB()
    db.connect()
    threats = db.get_recent_threats(limit=limit)
    db.close()

    if not threats:
        ui.info("No threat intelligence yet.")
        return

    table = RichTable(title="Threat Intelligence", box=box.SIMPLE_HEAVY,
                      border_style="red", header_style="bold red")
    table.add_column("Type", style="bold white")
    table.add_column("Chain", style="accent")
    table.add_column("Loss", style="red")
    table.add_column("Source", style="muted")
    table.add_column("Pattern", overflow="fold", max_width=50)

    for t in threats:
        table.add_row(
            t.get("attack_type", "?"),
            t.get("chain", "?"),
            t.get("loss_amount", "?"),
            t.get("source", "?"),
            t.get("pattern", "")[:50],
        )

    ui.console.print(table)


# ---------------------------------------------------------------------------
# Advanced feature commands — fuzz, diagrams, sarif, sync
# ---------------------------------------------------------------------------


@cli.group()
def fuzz():
    """Foundry fuzz/invariant testing integration"""
    pass


@fuzz.command("generate")
@click.option('--attacks', '-a', multiple=True, required=True,
              help='Attack types to fuzz-test (repeatable)')
@click.option('--target', '-t', default="0x0000000000000000000000000000000000000000",
              help='Target contract address')
@click.option('--output', '-o', default="fuzz", help='Output directory')
def fuzz_generate(attacks, target, output):
    """Generate a Foundry fuzz test suite from attack types"""
    from defihunter.core.fuzz import generate_fuzz_suite
    ui.rule("FUZZ SUITE GENERATION")
    path = generate_fuzz_suite(list(attacks), target_addr=target, out_dir=output)
    if not path:
        ui.warn(f"No fuzz template matches: {', '.join(attacks)}")
        return
    ui.ok(f"Fuzz suite written to {path}")
    ui.info("Run with: forge test --match-contract Fuzz --fuzz-runs 1000")


@fuzz.command("run")
@click.option('--file', '-f', required=True, help='Path to generated .t.sol file')
@click.option('--runs', '-r', default=500, help='Number of fuzz runs per test')
@click.option('--timeout', default=180, help='Max seconds for the fuzz run')
def fuzz_run(file, runs, timeout):
    """Run the generated fuzz suite with forge"""
    from defihunter.core.fuzz import run_fuzz_suite
    ui.rule("FUZZ RUN")
    with ui.spinner(f"Running {runs} fuzz runs/test"):
        result = run_fuzz_suite(file, fuzz_runs=runs, timeout=timeout)
    if not result.get("ran"):
        ui.warn(f"Fuzz did not run: {result.get('reason', 'unknown')}")
        return
    if result.get("ok"):
        ui.ok(f"All fuzz tests passed ({result['passed']} PASS)")
    else:
        ui.warn(f"Fuzz failed: {result['failed']} FAIL, {result['passed']} PASS")
        if result.get("stdout"):
            for line in result["stdout"].splitlines():
                if "[FAIL]" in line or "Failing" in line:
                    ui.console.print(line)


@cli.command()
@click.option('--kind', '-k', required=True,
              type=click.Choice(['attack_flow', 'call_graph', 'storage_layout']),
              help='Diagram kind')
@click.option('--input', '-i', required=True, help='Findings JSON')
@click.option('--output', '-o', required=True, help='Output .mmd file')
def diagram(kind, input, output):
    """Generate a Mermaid diagram (.mmd) from findings JSON"""
    from defihunter.core.diagrams import attack_flow, call_graph, storage_layout
    findings = json.loads(Path(input).read_text())
    vulns = findings.get("vulnerabilities", [])
    target = findings.get("target", "target")
    contracts = findings.get("contracts", {})

    if kind == "attack_flow":
        mmd = attack_flow(vulns, target)
    elif kind == "call_graph":
        mmd = call_graph(contracts, vulns, target)
    else:
        mmd = storage_layout(
            [c.get("source", "") for c in contracts.values()
             if isinstance(c, dict) and c.get("source")], target)

    if not mmd:
        ui.warn("No diagram content generated (no data to render)")
        return
    Path(output).write_text(mmd, encoding="utf-8")
    ui.ok(f"Diagram saved to {output}")


@cli.command()
@click.option('--input', '-i', required=True, help='Findings JSON')
@click.option('--output', '-o', required=True, help='Output .sarif file')
@click.option('--repo-uri', default=None, help='Base URI for source artifacts')
def sarif(input, output, repo_uri):
    """Export findings as SARIF 2.1.0 (CodeQL/GHAS compatible)"""
    from defihunter.core.sarif import export_sarif
    findings = json.loads(Path(input).read_text())
    vulns = findings.get("vulnerabilities", [])
    ui.rule("SARIF EXPORT")
    with ui.spinner(f"Exporting {len(vulns)} finding(s) → SARIF"):
        export_sarif(vulns, output,
                     tool_version=findings.get("tool_version", "unknown"),
                     target=findings.get("target", "target"),
                     repo_uri=repo_uri)
    ui.ok(f"SARIF log saved to {output}")


@cli.command()
@click.option('--input', '-i', required=True, help='Findings JSON')
@click.option('--target', '-t', type=click.Choice(['github', 'jira']), required=True,
              help='Where to push findings')
@click.option('--repo', default=None, help='GitHub repo (owner/name)')
@click.option('--project', default=None, help='Jira project key')
@click.option('--floor', default='MEDIUM', help='Minimum severity to sync')
@click.option('--dry-run', is_flag=True, help='Print tickets instead of creating')
def sync(input, target, repo, project, floor, dry_run):
    """Push findings to GitHub Issues or Jira"""
    from defihunter.core.sync import sync_github, sync_jira
    findings = json.loads(Path(input).read_text())
    vulns = findings.get("vulnerabilities", [])
    ui.rule("ISSUE SYNC")

    if target == "github":
        if not repo:
            ui.warn("--repo owner/name required")
            return
        owner, name = repo.split("/", 1)
        with ui.spinner(f"Syncing {len(vulns)} finding(s) → GitHub"):
            res = sync_github(vulns, owner, name, floor=floor, dry_run=dry_run)
    else:
        if not project:
            ui.warn("--project KEY required")
            return
        base = os.getenv("JIRA_BASE_URL", "")
        if not base:
            ui.warn("JIRA_BASE_URL env var required")
            return
        with ui.spinner(f"Syncing {len(vulns)} finding(s) → Jira"):
            res = sync_jira(vulns, base, project, floor=floor, dry_run=dry_run)

    created = res.get("created", [])
    if dry_run:
        ui.info(f"DRY-RUN: {len(created)} ticket(s) would be created")
        for c in created[:5]:
            ui.console.print(f"  - {c.get('title', c.get('summary', '?'))}")
    else:
        ui.ok(f"Created {len(created)} ticket(s), skipped {res.get('skipped', 0)}")
        for c in created[:5]:
            ui.console.print(f"  - {c.get('url') or c.get('key')}")


if __name__ == '__main__':
    cli()
