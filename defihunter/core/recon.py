"""Reconnaissance module — discover contracts and map attack surface"""
import re
import subprocess
import time
from typing import Dict, List, Optional, Set
from pathlib import Path

def run(cmd: str, timeout: int = 30) -> str:
    """Run shell command"""
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return result.stdout.strip()

class ReconScanner:
    def __init__(self, rpc_url: Optional[str] = None, verbose: bool = False):
        self.rpc_url = rpc_url or ''
        self.verbose = verbose
        self._found_addresses: Set[str] = set()
        self._contracts: Dict = {}
    
    def log(self, msg: str):
        if self.verbose:
            print(f"  [debug] {msg}")
    
    def scan(self, target: str, deep: bool = False) -> Dict:
        """Full scan of target"""
        # Normalize URL
        if not target.startswith('http'):
            url = f"https://{target}"
        else:
            url = target
        
        # Scrape addresses
        self.log(f"Scraping {url}")
        addresses = self._scrape_addresses(url, deep=deep)
        self.log(f"Found {len(addresses)} addresses")
        
        # Filter to contracts
        if self.rpc_url:
            self.log("Filtering to contracts only")
            contracts = self._filter_contracts(addresses)
        else:
            contracts = {addr: {"name": "Unknown", "has_code": False} for addr in addresses}
        
        return {
            "target": target,
            "url": url,
            "total_addresses": len(addresses),
            "contracts": contracts,
        }
    
    def _scrape_addresses(self, url: str, deep: bool = False) -> List[str]:
        """Scrape addresses from HTML and JS"""
        addresses = set()
        
        # Get HTML
        html = run(f'curl -sL "{url}" --connect-timeout 10 --max-time 30')
        addresses.update(re.findall(r'0x[a-fA-F0-9]{40}', html))
        
        if deep:
            # Find JS files
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
        
        return sorted(addresses)
    
    def _filter_contracts(self, addresses: List[str]) -> Dict:
        """Filter addresses to only contracts"""
        contracts = {}
        for addr in addresses:
            code = self._code_with_retry(addr)
            if code:
                name = run(f'cast call {addr} "name()(string)" --rpc-url {self.rpc_url} 2>/dev/null')
                name = name.strip('"') if name and name != "0x" else "Unknown"
                contracts[addr] = {
                    "name": name,
                    "code_size": len(code),
                    "has_code": True,
                }
        return contracts

    def _code_with_retry(self, addr: str, attempts: int = 3, backoff: float = 1.0) -> str:
        """eth_getCode via `cast code`, retrying on transient network/DNS
        failures so flaky RPCs don't turn real contracts into 'no code'.

        - a clean "0x" answer means "no code here" and stops immediately
        - an empty/errored result is a transient failure → backoff + retry
        """
        for i in range(attempts):
            try:
                code = run(f'cast code {addr} --rpc-url {self.rpc_url} 2>/dev/null')
            except Exception:
                code = ""  # subprocess timeout etc. — retryable
            if code and code != "0x" and len(code) > 10:
                return code
            if code == "0x":
                return ""  # definitive: address has no code
            if i < attempts - 1:
                time.sleep(backoff * (i + 1))  # 1s, 2s, 3s between retries
        return ""
    
    def get_contract_functions(self, address: str) -> List[str]:
        """Detect function signatures from bytecode"""
        if not self.rpc_url:
            return []
        
        code = run(f'cast code {address} --rpc-url {self.rpc_url} 2>/dev/null')
        if not code:
            return []
        
        # Common function selectors
        selectors = {
            "0x6e553f65": "deposit(uint256,address)",
            "0xb6b55f25": "deposit(uint256)",
            "0x2e1a7d4d": "withdraw(uint256)",
            "0x00f714ce": "withdraw(uint256,address)",
            "0xc23a4d79": "withdraw(uint256,address,address)",
            "0x3ccfd60b": "withdraw()",
            "0xd370ff70": "drip()",
            "0x4c929902": "file(bytes32,uint256)",
            "0xbf353dbb": "wards(address)",
            "0x65fae35e": "rely(address)",
            "0x9c52a7f1": "deny(address)",
            "0x70a08231": "balanceOf(address)",
            "0x18160ddd": "totalSupply()",
            "0x06fdde03": "name()",
            "0x95d89b41": "symbol()",
            "0x313ce567": "decimals()",
            "0xa9059cbb": "transfer(address,uint256)",
            "0x23b872dd": "transferFrom(address,address,uint256)",
            "0xdd62ed3e": "allowance(address,address)",
            "0x095ea7b3": "approve(address,uint256)",
        }
        
        found = []
        for selector, func in selectors.items():
            if selector[2:] in code:
                found.append(func)
        
        return found
