#!/usr/bin/env python3
"""
DeFi Hunter — Main Entry Point
Automated DeFi security analysis framework
"""

import argparse
import json
import os
import sys
import subprocess
import re
from datetime import datetime
from pathlib import Path

BASE_DIR = Path(__file__).parent
PROFILES_DIR = BASE_DIR / "profiles"
FINDINGS_DIR = BASE_DIR / "findings"
REPORTS_DIR = BASE_DIR / "reports"

def run(cmd, capture=True):
    """Run shell command and return output"""
    result = subprocess.run(cmd, shell=True, capture_output=capture, text=True)
    return result.stdout.strip()

def log(msg, level="INFO"):
    """Print formatted log message"""
    ts = datetime.now().strftime("%H:%M:%S")
    colors = {"INFO": "\033[94m", "WARN": "\033[93m", "ERROR": "\033[91m", "OK": "\033[92m"}
    color = colors.get(level, "\033[0m")
    print(f"{color}[{ts}] {level}: {msg}\033[0m")

def find_contract_addresses(url, rpc_url=None):
    """Find contract addresses from a dApp"""
    log(f"Scanning {url} for contract addresses...")
    
    addresses = set()
    
    # Method 1: Scrape HTML
    html = run(f'curl -sL "{url}" --connect-timeout 10 --max-time 30')
    found = re.findall(r'0x[a-fA-F0-9]{40}', html)
    addresses.update(found)
    
    # Method 2: Find and scan JS files
    js_files = re.findall(r'(?:src|href)="([^"]*\.js)"', html)
    for js in js_files[:20]:
        if js.startswith("/"):
            js = f"{url.rstrip('/')}{js}"
        elif not js.startswith("http"):
            continue
        try:
            js_content = run(f'curl -sL "{js}" --connect-timeout 10 --max-time 30')
            found = re.findall(r'0x[a-fA-F0-9]{40}', js_content)
            addresses.update(found)
        except:
            continue
    
    # Method 3: If RPC provided, filter to contracts only
    if rpc_url:
        contracts = {}
        for addr in addresses:
            code = run(f'cast code {addr} --rpc-url {rpc_url} 2>/dev/null')
            if code and code != "0x" and len(code) > 10:
                name = run(f'cast call {addr} "name()(string)" --rpc-url {rpc_url} 2>/dev/null')
                name = name.strip('"') if name and name != "0x" else "Unknown"
                contracts[addr] = {
                    "name": name,
                    "code_size": len(code),
                    "has_code": True
                }
        return contracts
    
    return {addr: {"name": "Unknown", "has_code": False} for addr in addresses}

def analyze_contract_source(address, rpc_url):
    """Fetch and analyze verified contract source"""
    log(f"Analyzing contract {address}...")
    
    etherscan_key = os.getenv("ETHERSCAN_API_KEY", "")
    if etherscan_key:
        url = f"https://api.etherscan.io/v2/api?chainid=1&module=contract&action=getsourcecode&address={address}&apikey={etherscan_key}"
        result = run(f'curl -sL "{url}"')
        try:
            data = json.loads(result)
            if data.get("status") == "1":
                source = data["result"][0]
                return {
                    "name": source.get("ContractName", ""),
                    "compiler": source.get("CompilerVersion", ""),
                    "verified": bool(source.get("SourceCode")),
                    "source": source.get("SourceCode", ""),
                    "abi": source.get("ABI", ""),
                }
        except:
            pass
    
    return {"name": "", "verified": False, "source": "", "abi": ""}

def scan_for_vulnerabilities(source_code, contract_name):
    """Scan source code for common DeFi vulnerabilities"""
    findings = []
    
    if not source_code:
        return findings
    
    patterns = {
        "Reentrancy": {
            "patterns": [
                r'\.call\{value:',
                r'external\s+call',
            ],
            "severity": "CRITICAL",
            "description": "External call before state update — reentrancy risk"
        },
        "Unprotected Admin": {
            "patterns": [
                r'function\s+file\s*\(',
                r'mapping.*wards',
                r'auth\s*\(',
            ],
            "severity": "HIGH",
            "description": "Admin function with no timelock"
        },
        "Inflation Attack": {
            "patterns": [
                r'shares\s*=.*totalSupply.*balance',
                r'shares\s*=.*totalSupply.*totalAssets',
            ],
            "severity": "HIGH",
            "description": "First depositor inflation attack possible"
        },
        "Proxy Upgrade": {
            "patterns": [
                r'upgradeTo',
                r'_authorizeUpgrade',
                r'UUPS',
            ],
            "severity": "HIGH",
            "description": "Upgradeable proxy — admin can change logic"
        },
    }
    
    for vuln_name, vuln_info in patterns.items():
        for pattern in vuln_info["patterns"]:
            if re.search(pattern, source_code, re.IGNORECASE | re.MULTILINE):
                findings.append({
                    "title": vuln_name,
                    "severity": vuln_info["severity"],
                    "description": vuln_info["description"],
                    "contract": contract_name,
                })
                break
    
    return findings

def generate_report(target, profile, findings_list, output_dir):
    """Generate markdown report"""
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    
    critical = sum(1 for f in findings_list if f.get("severity") == "CRITICAL")
    high = sum(1 for f in findings_list if f.get("severity") == "HIGH")
    medium = sum(1 for f in findings_list if f.get("severity") == "MEDIUM")
    low = sum(1 for f in findings_list if f.get("severity") == "LOW")
    
    report = f"""# Security Analysis Report: {target}

> Generated: {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
> Tool: DeFi Hunter v1.0

## Executive Summary

| Metric | Value |
|--------|-------|
| Contracts Analyzed | {len(profile.get('contracts', {}))} |
| Critical Findings | {critical} |
| High Findings | {high} |
| Medium Findings | {medium} |
| Low Findings | {low} |

## Contracts

| Address | Name | Verified | Code Size |
|---------|------|----------|-----------|
"""
    
    for addr, info in profile.get("contracts", {}).items():
        verified = "✅" if info.get("verified") else "❌"
        report += f"| `{addr}` | {info.get('name', '?')} | {verified} | {info.get('code_size', 0)} |\n"
    
    report += "\n## Findings\n\n"
    
    for severity in ["CRITICAL", "HIGH", "MEDIUM", "LOW"]:
        sev_findings = [f for f in findings_list if f.get("severity") == severity]
        if sev_findings:
            report += f"### {severity}\n\n"
            for f in sev_findings:
                report += f"- **[{f['severity']}] {f['title']}** — {f['description']} (in `{f.get('contract', '?')}`)\n"
            report += "\n"
    
    report += "\n## Remediation\n\n"
    report += "| Finding | Fix |\n|---------|-----|\n"
    report += "| Reentrancy | Use Checks-Effects-Interactions pattern |\n"
    report += "| Unprotected Admin | Add timelock to admin functions |\n"
    report += "| Inflation Attack | Use virtual shares (ERC-4626) |\n"
    report += "| Proxy Upgrade | Add timelock to upgrades |\n"
    
    report_path = output_dir / f"{target.replace('.', '_')}.md"
    report_path.write_text(report)
    log(f"Report saved to {report_path}", "OK")
    return str(report_path)

def main():
    parser = argparse.ArgumentParser(description="DeFi Hunter — Automated Security Analysis")
    parser.add_argument("--target", required=True, help="Target domain (e.g., sky.money)")
    parser.add_argument("--rpc", default=os.getenv("RPC_URL", ""), help="RPC URL for fork")
    parser.add_argument("--deep", action="store_true", help="Deep scan with simulation")
    parser.add_argument("--output", default=str(FINDINGS_DIR), help="Output directory")
    
    args = parser.parse_args()
    
    target = args.target
    rpc_url = args.rpc
    
    PROFILES_DIR.mkdir(parents=True, exist_ok=True)
    FINDINGS_DIR.mkdir(parents=True, exist_ok=True)
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    
    log(f"Starting analysis of {target}")
    
    # Phase 1: Recon
    log("Phase 1: Reconnaissance")
    contracts = find_contract_addresses(f"https://{target}", rpc_url)
    log(f"Found {len(contracts)} contracts")
    
    profile = {
        "target": target,
        "timestamp": datetime.now().isoformat(),
        "contracts": contracts,
    }
    
    profile_path = PROFILES_DIR / f"{target.replace('.', '_')}.json"
    profile_path.write_text(json.dumps(profile, indent=2))
    log(f"Profile saved to {profile_path}", "OK")
    
    # Phase 2: Analyze
    log("Phase 2: Analyzing contracts")
    all_findings = []
    
    for addr, info in contracts.items():
        source_info = analyze_contract_source(addr, rpc_url)
        if source_info.get("verified"):
            findings = scan_for_vulnerabilities(source_info["source"], source_info["name"])
            all_findings.extend(findings)
            for f in findings:
                f["address"] = addr
    
    findings_path = FINDINGS_DIR / f"{target.replace('.', '_')}.json"
    findings_path.write_text(json.dumps(all_findings, indent=2))
    log(f"Found {len(all_findings)} potential vulnerabilities", "OK")
    
    # Phase 3: Report
    log("Phase 3: Generating report")
    report_path = generate_report(target, profile, all_findings, REPORTS_DIR)
    
    # Summary
    log("=" * 50)
    log(f"Analysis complete for {target}", "OK")
    log(f"Profile: {profile_path}")
    log(f"Findings: {findings_path}")
    log(f"Report: {report_path}")
    
    critical = [f for f in all_findings if f.get("severity") == "CRITICAL"]
    high = [f for f in all_findings if f.get("severity") == "HIGH"]
    if critical:
        log(f"CRITICAL: {len(critical)} findings!", "ERROR")
    if high:
        log(f"HIGH: {len(high)} findings!", "WARN")

if __name__ == "__main__":
    main()
