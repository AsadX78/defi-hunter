"""Real ABI resolution for fork proofs.

The fork verifier used to guess function selectors from a hardcoded list
(mint(address,uint256), withdraw(uint256), …). On real contracts most of
those guesses miss — the Morpho/Permit2 runs ended with 36 failed
simulations and "No callable-by-anyone findings". A real tool fetches the
contract's ACTUAL ABI (the same Etherscan v2 API that serves the source),
maps each attack route to the functions that really exist, and calls them
with real calldata.

Results are cached on disk (~/.cache/defihunter/abi/<addr>.json) so a scan
of the same protocol twice does not re-hit the API.
"""
import json
import os
from pathlib import Path
from typing import Dict, List, Optional

from defihunter.core.analyzer import run

CACHE_DIR = Path(os.getenv("XDG_CACHE_HOME", "~/.cache")).expanduser() / "defihunter" / "abi"


def _cache_path(address: str) -> Path:
    return CACHE_DIR / f"{address.lower()}.json"


def fetch_abi(address: str, api_key: Optional[str] = None) -> List[Dict]:
    """Verified ABI for a contract, from cache or Etherscan v2.

    Returns [] when the contract has no verified ABI (unverified source,
    EOA, or API failure) — callers treat [] as "ABI unknown", NOT as
    "no functions".
    """
    address = address.lower()
    _cache_path(address).parent.mkdir(parents=True, exist_ok=True)

    cached = _cache_path(address)
    if cached.exists():
        try:
            return json.loads(cached.read_text())
        except Exception:
            pass

    api_key = api_key or os.getenv("ETHERSCAN_API_KEY", "")
    if not api_key:
        return []

    url = ("https://api.etherscan.io/v2/api?chainid=1&module=contract"
           f"&action=getabi&address={address}&apikey={api_key}")
    result = run(f'curl -sL "{url}"')
    try:
        data = json.loads(result)
        if data.get("status") == "1":
            abi = json.loads(data.get("result") or "[]")
            if isinstance(abi, list):
                try:
                    cached.write_text(json.dumps(abi))
                except Exception:
                    pass
                return abi
    except Exception:
        pass
    return []


def functions(abi: List[Dict]) -> List[Dict]:
    """The callable functions (state-changing + view) in an ABI."""
    return [e for e in abi if isinstance(e, dict) and e.get("type") == "function"]


def function_names(abi: List[Dict]) -> List[str]:
    return [f.get("name", "") for f in functions(abi)]


def canonical(fn: Dict) -> str:
    """cast-style signature: 'mint(address,uint256)'."""
    ins = ",".join(i.get("type", "") for i in fn.get("inputs", []))
    return f"{fn.get('name', '')}({ins})"


def find(abi: List[Dict], name: str, argc: Optional[int] = None) -> List[Dict]:
    """Every ABI function matching name (optionally with argc inputs)."""
    out = []
    for f in functions(abi):
        if f.get("name") == name:
            if argc is None or len(f.get("inputs", [])) == argc:
                out.append(f)
    return out
