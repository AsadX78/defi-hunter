#!/usr/bin/env python3
"""
DeFi Hunter — Recon Module
Discovers contracts, reads source code, maps attack surface
"""

import json
import re
import subprocess
from pathlib import Path

def run(cmd):
    """Run shell command"""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
    return result.stdout.strip()

def scrape_addresses(url):
    """Scrape website for Ethereum addresses"""
    html = run(f'curl -sL "{url}" --connect-timeout 10 --max-time 30')
    addresses = set(re.findall(r'0x[a-fA-F0-9]{40}', html))
    
    # Also check JS files
    js_files = re.findall(r'(?:src|href)="([^"]*\.js)"', html)
    for js in js_files[:20]:
        if js.startswith("/"):
            js_url = f"{url.rstrip('/')}{js}"
        elif js.startswith("http"):
            js_url = js
        else:
            continue
        try:
            js_content = run(f'curl -sL "{js_url}" --connect-timeout 10 --max-time 30')
            addresses.update(re.findall(r'0x[a-fA-F0-9]{40}', js_content))
        except:
            continue
    
    return list(addresses)

def filter_contracts(addresses, rpc_url):
    """Filter addresses to only those with contract code"""
    contracts = {}
    for addr in addresses:
        code = run(f'cast code {addr} --rpc-url {rpc_url} 2>/dev/null')
        if code and code != "0x" and len(code) > 10:
            name = run(f'cast call {addr} "name()(string)" --rpc-url {rpc_url} 2>/dev/null')
            name = name.strip('"') if name and name != "0x" else "Unknown"
            contracts[addr] = {
                "name": name,
                "code_size": len(code),
            }
    return contracts

def get_contract_info(address, rpc_url):
    """Get detailed contract info"""
    info = {"address": address}
    
    # Try common function calls
    for func in ["name()(string)", "symbol()(string)", "totalSupply()(uint256)", "decimals()(uint8)"]:
        result = run(f'cast call {address} "{func}" --rpc-url {rpc_url} 2>/dev/null')
        if result and result != "0x":
            key = func.split("(")[0]
            info[key] = result.strip('"')
    
    # Check for admin functions
    for func in ["wards(address)(uint256)", "owner()(address)", "admin()(address)"]:
        result = run(f'cast call {address} "{func}" --rpc-url {rpc_url} --args 0x0000000000000000000000000000000000000001 2>/dev/null')
        if result and result != "0x":
            info["has_admin"] = True
            break
    
    return info

def scan_tvl(address, rpc_url):
    """Get total value locked in a contract"""
    balance = run(f'cast balance {address} --rpc-url {rpc_url} 2>/dev/null')
    try:
        return int(balance)
    except:
        return 0

if __name__ == "__main__":
    import sys
    target = sys.argv[1] if len(sys.argv) > 1 else "sky.money"
    rpc = sys.argv[2] if len(sys.argv) > 2 else ""
    
    print(f"Scanning {target}...")
    addresses = scrape_addresses(f"https://{target}")
    print(f"Found {len(addresses)} addresses")
    
    if rpc:
        contracts = filter_contracts(addresses, rpc)
        print(f"Found {len(contracts)} contracts")
        for addr, info in contracts.items():
            print(f"  {addr}: {info.get('name', '?')} ({info.get('code_size', 0)} bytes)")
