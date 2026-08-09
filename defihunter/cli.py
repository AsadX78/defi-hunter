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

__version__ = "1.3.22"


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
def wizard(repo, check, attacks):
    """Interactive guided hunt: GitHub repo → contracts → vulnerability checks"""
    from defihunter.wizard import run_wizard
    attack_list = [a.strip() for a in attacks.split(',') if a.strip()] if attacks else None
    run_wizard(verbose=False, repo_url=repo, check=check, attacks=attack_list,
               version=__version__)


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


@cli.group()
@click.pass_context
def simulate(ctx):
    """Simulate attacks on fork"""
    pass


@simulate.command()
@click.option('--attack', '-a', type=click.Choice(['inflation', 'admin', 'governance', 'oracle', 'reentrancy', 'bridge', 'sandwich', 'twap', 'flashloan', 'withdraw', 'initialize', 'permit', 'liquidation', 'forcesend', 'peg', 'crossfunc', 'delegatecall', 'mint']), required=True)
@click.option('--target', '-t', required=True, help='Target contract address')
@click.option('--rpc', '-r', envvar='RPC_URL', help='RPC URL')
@click.option('--block', '-b', type=int, help='Fork block number')
@click.pass_context
def run(ctx, attack, target, rpc, block):
    """Run attack simulation"""
    simulator = AttackSimulator(rpc_url=rpc, block=block)

    ui.rule("SIMULATE")
    ui.step(f"Attack {attack}", target)
    with ui.spinner(f"Simulating {attack} attack"):
        result = simulator.run(attack, target)

    ui.console.print(ui.attack_summary(result, attack, target))


@cli.command()
@click.option('--input', '-i', required=True, help='Input findings JSON')
@click.option('--output', '-o', required=True, help='Output file')
@click.option('--format', '-f', type=click.Choice(['html', 'json', 'markdown']), default='html')
def report(input, output, format):
    """Generate report from findings"""
    gen = ReportGenerator()

    findings = json.loads(Path(input).read_text())
    ui.rule("REPORT")
    ui.step("Generating", f"{format} → {output}")
    with ui.spinner("Rendering report"):
        report_path = gen.generate(findings, format=format, output=output)

    ui.ok(f"Report saved to {report_path}")


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


if __name__ == '__main__':
    cli()
