"""Protocol-name resolution via DefiLlama (free, no API key).

Lets the wizard work when the user has NOTHING but a protocol name
(e.g. "spark", "aave", "lido"): DefiLlama returns the protocol's anchor
contract address(es), website, chains, and GitHub orgs — which we feed
into the normal verify → preview → checks → report pipeline.
"""
from __future__ import annotations

import re
import time
from typing import Dict, List, Optional

import requests

LLAMA_API = "https://api.llama.fi/protocol/{name}"

_ADDR = re.compile(r"0x[a-fA-F0-9]{40}")


def resolve_protocol(name: str, attempts: int = 3) -> Optional[Dict]:
    """Look up a protocol name on DefiLlama. Returns a summary dict or None.

    Retries on transient network errors (this network is flaky); returns
    None for 404 / unknown names / repeated failures.
    """
    slug = name.strip().lower().replace(" ", "-")
    for i in range(attempts):
        try:
            resp = requests.get(LLAMA_API.format(name=slug), timeout=25)
            if resp.status_code == 200:
                return _summarize(resp.json())
            if resp.status_code == 404:
                return None
        except requests.RequestException:
            pass
        if i < attempts - 1:
            time.sleep(2)
    return None


def _summarize(data: Dict) -> Dict:
    """Extract the useful bits from DefiLlama's protocol response."""
    addresses = set()
    # Single-chain protocols put their main contract in `address`.
    if isinstance(data.get("address"), str) and _ADDR.fullmatch(data["address"]):
        addresses.add(data["address"].lower())
    # `tokens` is a time-series of {symbol: amount | {address: amount}} maps —
    # some protocols include per-token addresses there; collect any we find.
    for entry in data.get("tokens", []):
        for sym, value in (entry.get("tokens") or {}).items():
            if isinstance(value, dict):
                for addr in value:
                    if isinstance(addr, str) and _ADDR.fullmatch(addr):
                        addresses.add(addr.lower())

    github = data.get("github") or []
    if isinstance(github, str):
        github = [github]

    chains = data.get("chains") or []
    if not chains and isinstance(data.get("currentChainTvls"), dict):
        # keys include TVL buckets ("staking", "borrowed") and per-chain
        # buckets ("Ethereum-staking") — keep only plain chain names.
        buckets = {"staking", "borrowed", "pool2", "liquid-staking", "delegated"}
        chains = [
            c for c in data["currentChainTvls"]
            if "-" not in c and c.lower() not in buckets
        ]

    return {
        "name": data.get("name") or "Unknown",
        "url": data.get("url") or "",
        "chains": chains,
        "github_orgs": github,
        "addresses": sorted(addresses),
    }
