"""GitHub repo scanner — clone a protocol repo and extract contract addresses.

Wizard uses this to turn a plain GitHub link (e.g.
https://github.com/Layr-Labs/eigenlayer-contracts) into a list of on-chain
contract addresses that `analyze` / `simulate` can then attack.
"""
from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

from defihunter.core.recon import ReconScanner

ADDR_RE = re.compile(r"0x[a-fA-F0-9]{40}")

SKIP_DIRS = {
    ".git", "node_modules", ".venv", "venv", "dist", "build", "__pycache__",
    ".next", ".pytest_cache", ".cache", "coverage", "lib", "libs",
}
TEXT_EXTS = {
    ".json", ".md", ".txt", ".sol", ".ts", ".tsx", ".js", ".jsx", ".py",
    ".toml", ".yaml", ".yml", ".env", ".cfg", ".conf", ".csv", ".html",
    ".svelte", ".vue", ".mustache",
}
MAX_FILES = 2000
MAX_FILE_SIZE = 2 * 1024 * 1024
VERIFY_LIMIT = 100  # cap on-chain `cast code` checks per scan

TMP_ROOT = Path("/tmp/defi-hunter-repos")

# 40-hex values that look like addresses but are NOT deployed contracts.
# These appear constantly in protocol repos as sentinels / storage slots /
# bitmask constants and would pollute the candidate list.
NON_CONTRACT_ADDRESSES = {
    "0x0000000000000000000000000000000000000000",  # address(0) placeholder
    "0x0000000000000000000000000000000000000001",  # address(1)
    "0xffffffffffffffffffffffffffffffffffffffff",  # ETH sentinel (Aave/Spark)
    "0xeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",  # ETH sentinel
    "0xb53127684a568b3173ae13b9f8a6016e243e63b6",  # EIP-1967 admin storage slot
    "0x360894a13ba1a3210667c828492db98dca3e2076",  # EIP-1967 implementation slot
    "0xfffffffffffffffffffffffffffffffffff00000",  # Aave health-factor bitmask
    "0xffffffffffffffffffffffffff000000000fffff",  # Aave bitmask constant
    "0x5555555555555555555555555555555555555555",  # bit pattern
    "0xaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",  # bit pattern
    "0x3333333333333333333333333333333333333333",  # bit pattern
    "0xcccccccccccccccccccccccccccccccccccccccc",  # bit pattern
}


def is_non_contract_address(addr: str) -> bool:
    """True for sentinel/slot/bitmask addresses that are never deployed."""
    if addr in NON_CONTRACT_ADDRESSES:
        return True
    nibbles = addr[2:]
    # All-nibble-equal patterns (0xffff…, 0x0000…, 0xaaaa…) are constants.
    if len(set(nibbles)) == 1:
        return True
    # Mask-style constants (repeated f/0 runs with gaps), e.g. Spark's
    # 0xffffffffffffffffffffff0000ffffffffffffff. Real deployed addresses
    # almost never have ≥75% f-or-0 nibbles.
    f0 = sum(1 for c in nibbles if c in "f0")
    if f0 / len(nibbles) >= 0.75:
        return True
    return False


def is_repo_dir(path: str) -> bool:
    """True if the string points at an existing local directory (for testing)."""
    return Path(path).expanduser().is_dir()


def looks_like_git_url(url: str) -> bool:
    return url.startswith(("http://", "https://", "git@", "ssh://")) and (
        "github.com" in url or "gitlab.com" in url or url.endswith(".git")
    )


def clone(repo_url: str) -> Path:
    """Shallow-clone a git repo into the temp dir. Returns the repo root."""
    TMP_ROOT.mkdir(parents=True, exist_ok=True)
    name = re.sub(r"[^A-Za-z0-9_.-]", "_", repo_url.rstrip("/").split("/")[-1]) or "repo"
    dest = TMP_ROOT / name
    if dest.exists():
        shutil.rmtree(dest)
    proc = subprocess.run(
        ["git", "clone", "--depth", "1", "--quiet", repo_url, str(dest)],
        capture_output=True, text=True, timeout=180,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Could not clone {repo_url}: "
            f"{(proc.stderr or proc.stdout).strip()}"
        )
    return dest


def extract_addresses(repo_dir: Path) -> Dict[str, Dict[str, object]]:
    """Walk a repo and collect every 0x…40 address + where it was found."""
    found: Dict[str, Dict[str, object]] = {}
    file_count = 0
    for path in repo_dir.rglob("*"):
        if file_count > MAX_FILES:
            break
        if not path.is_file():
            continue
        rel = path.relative_to(repo_dir)
        if any(part in SKIP_DIRS for part in rel.parts):
            continue
        if path.suffix and path.suffix.lower() not in TEXT_EXTS:
            continue
        if path.stat().st_size > MAX_FILE_SIZE:
            continue
        file_count += 1
        try:
            text = path.read_text(errors="ignore", encoding="utf-8")
        except Exception:
            continue
        for m in ADDR_RE.findall(text):
            addr = m.lower()
            if is_non_contract_address(addr):
                continue
            entry = found.setdefault(addr, {"sources": set(), "count": 0})
            entry["sources"].add(str(rel))
            entry["count"] += 1

    return {
        addr: {"sources": sorted(v["sources"]), "count": v["count"]}
        for addr, v in found.items()
    }


def scan_repo(
    repo_url: str,
    rpc_url: Optional[str] = None,
    verbose: bool = False,
) -> Dict:
    """Full flow: clone (or use local dir) → extract → optional on-chain verify.

    Returns a dict shaped like ReconScanner.scan() so the rest of the
    toolkit (tables, analyze, simulate) can consume it unchanged:
        {repo_url, repo_dir, total_addresses, contracts: {addr: info}}
    """
    if is_repo_dir(repo_url):
        repo_dir = Path(repo_url).expanduser().resolve()
        repo_source = repo_url
    else:
        repo_dir = clone(repo_url)
        repo_source = repo_url

    addresses = extract_addresses(repo_dir)

    contracts: Dict[str, Dict[str, object]] = {}
    ordered = sorted(
        addresses.items(), key=lambda kv: kv[1]["count"], reverse=True
    )

    verified_addrs: Dict[str, Dict[str, object]] = {}
    if rpc_url:
        to_verify = [addr for addr, _ in ordered[:VERIFY_LIMIT]]
        if to_verify:
            scanner = ReconScanner(rpc_url=rpc_url)
            verified_addrs = scanner._filter_contracts(to_verify)

    for addr, info in ordered:
        entry = dict(info)
        if addr in verified_addrs:
            vinfo = verified_addrs[addr]
            entry.update({
                "name": vinfo.get("name", "Unknown"),
                "code_size": vinfo.get("code_size", 0),
                "has_code": True,
                "verified": True,
                "status": f"{vinfo.get('code_size', 0):,} bytes",
            })
        elif rpc_url:
            entry.update({
                "name": "Unknown", "code_size": 0, "has_code": False,
                "verified": False, "status": "no code",
            })
        else:
            entry.update({
                "name": "Unknown", "code_size": 0, "has_code": False,
                "verified": False, "status": "unverified",
            })
        contracts[addr] = entry

    return {
        "repo_url": repo_source,
        "repo_dir": str(repo_dir),
        "total_addresses": len(addresses),
        "contracts": contracts,
    }
