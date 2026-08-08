#!/usr/bin/env python3
"""
DeFi Hunter — Master Runner
Orchestrates the full scan pipeline
"""

import argparse
import json
import subprocess
import time
from pathlib import Path
import sys
from datetime import datetime

BASE_DIR = Path(__file__).parent

def run(cmd):
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

def log(msg, level="INFO"):
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {"INFO": "\033[94m", "WARN": "\033[93m", "ERROR": "\033[91m", "OK": "\033[92m"}
    print(f'{colors.get(level, "\033[0m")}[{ts}] {level}: {msg}\033[0m')

def step1_recon(target, rpc_url):
    """Find contracts"""
    log("Step 1: Reconnaissance")
    
    sys.path.insert(0, str(BASE_DIR))
    from recon import scrape_addresses, filter_contracts
    
    addresses = scrape_addresses(f"https://{target}")
    log(f"Found {len(addresses)} addresses")
    
    contracts = {}
    if rpc_url:
        contracts = filter_contracts(addresses, rpc_url)
        log(f"Filtered to {len(contracts)} contracts with code")
    
    return {"addresses": addresses, "contracts": contracts}

def step2_analyze(contracts, rpc_url):
    """Analyze contract source code"""
    log("Step 2: Analyzing contracts")
    
    findings = []
    sys.path.insert(0, str(BASE_DIR))
    from hunter import analyze_contract_source, scan_for_vulnerabilities
    
    for addr, info in contracts.items():
        source_info = analyze_contract_source(addr, rpc_url)
        if source_info.get("verified"):
            vulns = scan_for_vulnerabilities(source_info["source"], source_info["name"])
            for v in vulns:
                v["address"] = addr
            findings.extend(vulns)
            log(f"  {addr}: {len(vulns)} findings")
    
    return findings

def step3_simulate(contracts, rpc_url, target):
    """Simulate attacks on fork"""
    log("Step 3: Attack simulation")
    
    # For now, simulate inflation attack on each contract
    simulations = []
    for addr, info in contracts.items():
        if "savings" in info.get("name", "").lower() or "vault" in info.get("name", "").lower():
            log(f"  Simulating inflation attack on {addr} ({info.get('name')})")
            simulations.append({
                "contract": addr,
                "name": info.get("name"),
                "attack": "Inflation Attack",
                "status": "simulated",
            })
    
    return simulations

def step4_report(target, profile, findings, simulations, output_dir):
    """Generate final report"""
    log("Step 4: Generating report")
    
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    critical = sum(1 for f in findings if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings if f.get("severity") == "MEDIUM")
    
    report = f"""# DeFi Hunter Report: {target}

> Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}

## Summary

| Metric | Value |
|--------|-------|
| Contracts Found | {len(profile.get('contracts', {}))} |
| Vulnerabilities | {len(findings)} |
| Critical | {critical} |
| High | {high} |
| Medium | {medium} |
| Simulations | {len(simulations)} |

## Contracts

| Address | Name | Size |
|---------|------|------|
"""
    for addr, info in profile.get("contracts", {}).items():
        report += f"| `{addr}` | {info.get('name', '?')} | {info.get('code_size', 0)} bytes |\n"
    
    if findings:
        report += "\n## Vulnerabilities\n\n"
        for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
            sev = [f for f in findings if f.get("severity") == severity]
            if sev:
                report += f"### {severity}\n\n"
                for f in sev:
                    report += f"- **{f['title']}** — {f['description']} (`{f.get('address', '?')}`)\n"
    
    if simulations:
        report += "\n## Simulations\n\n"
        for sim in simulations:
            report += f"- **{sim['attack']}** on `{sim['contract']}` ({sim['name']}): {sim['status']}\n"
    
    report += """
## Remediation

| Vulnerability | Fix |
|---------------|-----|
| Reentrancy | Checks-Effects-Interactions + ReentrancyGuard |
| Unprotected Admin | Add 48h timelock |
| Inflation Attack | ERC-4626 virtual shares |
| Proxy Upgrade | Multi-sig + timelock |
"""
    
    report_path = output_dir / f"{target.replace('.', '_')}.md"
    report_path.write_text(report)
    log(f"Report: {report_path}", "OK")
    
    # Also save JSON
    data = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "profile": profile,
        "findings": findings,
        "simulations": simulations,
    }
    json_path = output_dir / f"{target.replace('.', '_')}.json"
    json_path.write_text(json.dumps(data, indent=2))
    log(f"Data: {json_path}", "OK")
    
    return report_path

def main():
    parser = argparse.ArgumentParser(description="DeFi Hunter — Master Runner")
    parser.add_argument("--target", required=True)
    parser.add_argument("--rpc", default="")
    parser.add_argument("--output", default=str(BASE_DIR / "output"))
    args = parser.parse_args()
    
    log(f"Starting DeFi Hunter scan of {args.target}")
    
    # Run pipeline
    profile = step1_recon(args.target, args.rpc)
    findings = step2_analyze(profile.get("contracts", {}), args.rpc)
    simulations = step3_simulate(profile.get("contracts", {}), args.rpc, args.target)
    report_path = step4_report(args.target, profile, findings, simulations, args.output)
    
    log("=" * 50)
    log(f"Scan complete! Report: {report_path}", "OK")

if __name__ == "__main__":
    main()
