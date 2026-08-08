#!/usr/bin/env python3
"""DeFi Hunter — CLI Entry Point"""

import click
import json
import sys
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))

from defihunter.core.recon import ReconScanner
from defihunter.core.analyzer import ContractAnalyzer
from defihunter.core.simulator import AttackSimulator
from defihunter.core.reporter import ReportGenerator
from defihunter.core.config import load_config

__version__ = "1.0.0"

@click.group()
@click.version_option(__version__)
@click.option('--config', '-c', type=click.Path(), help='Config file')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
@click.pass_context
def cli(ctx, config, verbose):
    """DeFi Hunter — Open Source DeFi Security Toolkit"""
    ctx.ensure_object(dict)
    ctx.obj['config'] = load_config(config)
    ctx.obj['verbose'] = verbose

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
    
    click.echo(f"[*] Scanning {target}...")
    results = scanner.scan(target, deep=deep)
    
    click.echo(f"[+] Found {len(results.get('contracts', {}))} contracts")
    
    for addr, info in results.get('contracts', {}).items():
        name = info.get('name', 'Unknown')
        size = info.get('code_size', 0)
        click.echo(f"  {addr}: {name} ({size} bytes)")
    
    if output:
        Path(output).write_text(json.dumps(results, indent=2))
        click.echo(f"[+] Results saved to {output}")

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
    
    click.echo(f"[*] Analyzing {address}...")
    findings = analyzer.analyze(address)
    
    if findings:
        click.echo(f"[!] Found {len(findings)} issues:")
        for f in findings:
            sev = f.get('severity', 'UNKNOWN')
            title = f.get('title', 'Unknown')
            click.echo(f"  [{sev}] {title}")
    else:
        click.echo("[+] No obvious vulnerabilities found")

@analyze.command()
@click.option('--target', '-t', required=True, help='Target protocol name')
@click.option('--addresses', '-a', required=True, help='Comma-separated addresses')
@click.option('--rpc', '-r', envvar='RPC_URL', help='RPC URL')
@click.pass_context
def batch(ctx, target, addresses, rpc):
    """Analyze multiple contracts"""
    addrs = [a.strip() for a in addresses.split(',')]
    analyzer = ContractAnalyzer(rpc_url=rpc)
    
    all_findings = []
    for addr in addrs:
        click.echo(f"[*] Analyzing {addr}...")
        findings = analyzer.analyze(addr)
        all_findings.extend(findings)
    
    click.echo(f"[!] Total findings: {len(all_findings)}")

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
    
    click.echo(f"[*] Simulating {attack} attack on {target}...")
    result = simulator.run(attack, target)
    
    if result.get('success'):
        click.echo(f"[+] Attack successful!")
        click.echo(f"    Profit: {result.get('profit', 'N/A')}")
    else:
        click.echo(f"[-] Attack failed: {result.get('error', 'Unknown')}")

@cli.command()
@click.option('--input', '-i', required=True, help='Input findings JSON')
@click.option('--output', '-o', required=True, help='Output file')
@click.option('--format', '-f', type=click.Choice(['html', 'json', 'markdown']), default='html')
def report(input, output, format):
    """Generate report from findings"""
    gen = ReportGenerator()
    
    findings = json.loads(Path(input).read_text())
    report_path = gen.generate(findings, format=format, output=output)
    
    click.echo(f"[+] Report saved to {report_path}")

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
    
    click.echo("Available attack templates:\n")
    for name, template in TEMPLATES.items():
        if type == 'all' or template.get('type') == type:
            click.echo(f"  {name}")
            click.echo(f"    Type: {template.get('type')}")
            click.echo(f"    Severity: {template.get('severity')}")
            click.echo(f"    Description: {template.get('description')}")
            click.echo()

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
    click.echo(f"[*] Verifying {len(TEMPLATES)} templates against lab {lab}...")
    proc = subprocess.run(['forge', 'test'], cwd=str(lab))
    if proc.returncode != 0:
        raise click.ClickException("Template verification FAILED (see forge output above)")
    click.echo("[+] All template exploits verified")

if __name__ == '__main__':
    cli()
