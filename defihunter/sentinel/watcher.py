"""Deployment Watcher -- monitor new contract deployments across chains.

Watches block explorers (Etherscan, BSCScan, etc.) for new DeFi contract
deployments. When a new contract appears, it triggers an auto-scan.

Three modes:
    1. Explorer API -- poll Etherscan/etc for new contracts (reliable, rate-limited)
    2. Factory monitor -- watch known factory contracts for Deploy events
    3. RPC polling -- watch new blocks for contract creation txs
"""
from __future__ import annotations

import json
import subprocess
from typing import Dict, List, Optional

# Explorer API endpoints per chain
EXPLORER_APIS = {
    "ethereum": "https://api.etherscan.io/api",
    "bsc": "https://api.bscscan.com/api",
    "polygon": "https://api.polygonscan.com/api",
    "arbitrum": "https://api.arbiscan.io/api",
    "optimism": "https://api-optimistic.etherscan.io/api",
    "base": "https://api.basescan.org/api",
    "avalanche": "https://api.snowtrace.io/api",
    "fantom": "https://api.ftmscan.com/api",
    "gnosis": "https://api.gnosisscan.io/api",
}

# Known DeFi factory contracts to watch
DEFI_FACTORIES = {
    "ethereum": [
        {"address": "0x5C69bEe701ef814a2B6a3EDD4B1652CB9cc5aA6f", "name": "Uniswap V2 Factory"},
        {"address": "0x1F98431c8aD98523631AE4a59f267346ea31F984", "name": "Uniswap V3 Factory"},
        {"address": "0xc35DADB65012eC5796536bD9864eD8773aBc74C4", "name": "PancakeSwap Factory"},
    ],
    "bsc": [
        {"address": "0xcA143Ce32Fe78f1f7019d7d551a6402fC5350c73", "name": "PancakeSwap V2 Factory"},
    ],
    "polygon": [
        {"address": "0x575737141434Fc753745F2fEb426976B122064A4", "name": "QuickSwap Factory"},
    ],
}


class DeploymentWatcher:
    """Watch for new DeFi contract deployments.

    Usage:
        watcher = DeploymentWatcher(explorer_api_key="your_key")
        new_contracts = watcher.check_new_deployments("ethereum", last_block=20000000)
    """

    def __init__(self, explorer_api_key: Optional[str] = None):
        self.api_key = explorer_api_key or ""
        self._last_blocks: Dict[str, int] = {}

    def check_new_deployments(
        self,
        chain: str = "ethereum",
        last_block: Optional[int] = None,
    ) -> List[Dict]:
        """Check for new contract deployments since last_block.

        Returns list of deployment dicts:
            {"address": "0x...", "deployer": "0x...", "block": 20000001,
             "factory": "0x...", "factory_name": "Uniswap V3 Factory"}
        """
        deployments = []

        # Mode 1: Explorer API
        explorer_deps = self._check_explorer(chain, last_block)
        deployments.extend(explorer_deps)

        # Mode 2: Factory events
        factory_deps = self._check_factories(chain, last_block)
        deployments.extend(factory_deps)

        # Deduplicate by address
        seen = set()
        unique = []
        for d in deployments:
            addr = d["address"].lower()
            if addr not in seen:
                seen.add(addr)
                unique.append(d)

        return unique

    def _check_explorer(self, chain: str, last_block: Optional[int]) -> List[Dict]:
        """Check block explorer API for new contract deployments."""
        api_url = EXPLORER_APIS.get(chain)
        if not api_url or not self.api_key:
            return []

        try:
            params = {
                "chainid": self._chain_id(chain),
                "module": "account",
                "action": "txlist",
                "startblock": str(last_block or 0),
                "endblock": "99999999",
                "sort": "asc",
                "apikey": self.api_key,
            }
            query = "&".join(f"{k}={v}" for k, v in params.items())
            url = f"{api_url}?{query}"

            proc = subprocess.run(
                ["curl", "-s", "--connect-timeout", "10", "--max-time", "30", url],
                capture_output=True, text=True, timeout=35,
            )
            data = json.loads(proc.stdout)

            if data.get("status") != "1" or not data.get("result"):
                return []

            deployments = []
            for tx in data["result"]:
                # Contract creation = 'to' is empty
                if not tx.get("to") or tx["to"] == "":
                    deployments.append({
                        "address": tx.get("contractAddress", ""),
                        "deployer": tx.get("from", ""),
                        "block": int(tx.get("blockNumber", 0)),
                        "tx_hash": tx.get("hash", ""),
                        "timestamp": int(tx.get("timeStamp", 0)),
                        "factory": None,
                        "factory_name": None,
                        "chain": chain,
                    })
            return deployments
        except Exception:
            return []

    def _check_factories(self, chain: str, last_block: Optional[int]) -> List[Dict]:
        """Check known factory contracts for Deploy events."""
        factories = DEFI_FACTORIES.get(chain, [])
        if not factories:
            return []

        deployments = []
        for factory in factories:
            try:
                # Use eth_getLogs to find Deploy events
                # Deploy(address,address) = keccak256("Deploy(address,address)")
                deploy_topic = "0xd784d4261578468e33136e1c7c3f408484c1c715c03f642e547d6e09f8c5e0b3"

                payload = json.dumps({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "eth_getLogs",
                    "params": [{
                        "fromBlock": hex(last_block or 0),
                        "toBlock": "latest",
                        "address": factory["address"],
                        "topics": [deploy_topic],
                    }],
                })

                rpc_url = self._get_rpc(chain)
                proc = subprocess.run(
                    ["curl", "-s", "-X", "POST",
                     "-H", "Content-Type: application/json",
                     "-d", payload, rpc_url],
                    capture_output=True, text=True, timeout=30,
                )
                data = json.loads(proc.stdout)
                logs = data.get("result", [])

                for log in logs:
                    if not isinstance(log, dict):
                        continue
                    # Deploy events typically have the new contract address in topics or data
                    topics = log.get("topics", [])
                    if len(topics) >= 2:
                        new_addr = "0x" + topics[1][-40:]
                        deployments.append({
                            "address": new_addr,
                            "deployer": log.get("address", ""),  # factory address
                            "block": int(log.get("blockNumber", "0x0"), 16),
                            "tx_hash": log.get("transactionHash", ""),
                            "timestamp": 0,
                            "factory": factory["address"],
                            "factory_name": factory["name"],
                            "chain": chain,
                        })
            except Exception:
                continue

        return deployments

    @staticmethod
    def _chain_id(chain: str) -> str:
        return {
            "ethereum": "1", "bsc": "56", "polygon": "137",
            "arbitrum": "42161", "optimism": "10", "base": "8453",
            "avalanche": "43114", "fantom": "250", "gnosis": "100",
        }.get(chain, "1")

    @staticmethod
    def _get_rpc(chain: str) -> str:
        return {
            "ethereum": "https://ethereum-rpc.publicnode.com",
            "bsc": "https://bsc-dataseed.binance.org",
            "polygon": "https://polygon-rpc.com",
            "arbitrum": "https://arb1.arbitrum.io/rpc",
            "optimism": "https://mainnet.optimism.io",
            "base": "https://mainnet.base.org",
        }.get(chain, "https://ethereum-rpc.publicnode.com")

    @staticmethod
    def detect_chain_from_rpc(rpc_url: str) -> str:
        """Detect chain from RPC URL by checking well-known hostnames."""
        rpc_lower = rpc_url.lower()
        if "llamarpc.com" in rpc_lower or "eth.node" in rpc_lower or "ethereum-rpc" in rpc_lower:
            return "ethereum"
        if "bsc-dataseed" in rpc_lower or "bsc" in rpc_lower and "node" not in rpc_lower:
            return "bsc"
        if "polygon" in rpc_lower:
            return "polygon"
        if "arbitrum" in rpc_lower or "arb1" in rpc_lower:
            return "arbitrum"
        if "optimism" in rpc_lower or "optimistic" in rpc_lower:
            return "optimism"
        if "base.org" in rpc_lower or "base" in rpc_lower and "mainnet" in rpc_lower:
            return "base"
        if "avax" in rpc_lower or "avalanche" in rpc_lower:
            return "avalanche"
        if "fantom" in rpc_lower:
            return "fantom"
        if "gnosis" in rpc_lower or "xdai" in rpc_lower:
            return "gnosis"
        return "ethereum"  # default

    def filter_defi_contracts(self, deployments: List[Dict], rpc_url: Optional[str] = None) -> List[Dict]:
        """Filter deployments to only likely DeFi contracts.

        Checks bytecode size and common DeFi function selectors.
        """
        if not rpc_url:
            return deployments

        filtered = []
        for dep in deployments:
            addr = dep.get("address", "")
            if not addr:
                continue

            try:
                payload = json.dumps({
                    "jsonrpc": "2.0", "id": 1,
                    "method": "eth_getCode",
                    "params": [addr, "latest"],
                })
                proc = subprocess.run(
                    ["curl", "-s", "-X", "POST",
                     "-H", "Content-Type: application/json",
                     "-d", payload, rpc_url],
                    capture_output=True, text=True, timeout=15,
                )
                data = json.loads(proc.stdout)
                code = data.get("result", "0x")

                if not code or code == "0x" or code == "0x0":
                    continue  # EOA, not a contract

                code_hex = code[2:] if code.startswith("0x") else code
                code_size = len(code_hex) // 2

                # Minimum size filter (skip tiny contracts)
                if code_size < 100:
                    continue

                # Check for common DeFi selectors in bytecode
                defi_selectors = [
                    "b6b55f25",  # deposit()
                    "2e1a7d4d",  # withdraw(uint256)
                    "095ea7b3",  # approve(address,uint256)
                    "a9059cbb",  # transfer(address,uint256)
                    "70a08231",  # balanceOf(address)
                    "18160ddd",  # totalSupply()
                    "06fdde03",  # name()
                    "95d89b41",  # symbol()
                ]
                has_defi = any(sel in code_hex for sel in defi_selectors)

                if has_defi or code_size > 1000:
                    dep["code_size"] = code_size
                    dep["is_defi"] = has_defi
                    filtered.append(dep)
            except Exception:
                continue

        return filtered
