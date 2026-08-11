"""Advanced scanners — governance, oracle, upgradability, cross-chain sweeps.

These are source-level sweeps that go beyond the line-aware engine in
analyzer.py: they look for *patterns* across a contract's full source
(not single lines) and tag findings with the attack routes the wizard's
fork simulator can verify.
"""
from __future__ import annotations

import re
from pathlib import Path
from typing import Dict, List

from defihunter.core.analyzer import _iter_sol_files, _strip_comments

# ---------------------------------------------------------------------------
# Governance scanner — flash-loan governance, veto/proposal weaknesses
# ---------------------------------------------------------------------------

GOVERNANCE_PATTERNS = [
    {
        "name": "flash-loan governance (weighted voting)",
        "attack": "governance",
        "severity": "HIGH",
        "regex": r"getBalance|balanceOf|_weights|votes\s*=|votingPower",
        "desc": "Voting power is read from a mutable token balance (or an "
                "externally-weighted source) without a snapshot. An attacker can "
                "flash-loan tokens, pass a malicious proposal, and repay — "
                "flash-loan governance. Require time-weighted snapshots "
                "(e.g. OZ Votes with checkpoint delay).",
    },
    {
        "name": "missing proposal threshold",
        "attack": "governance",
        "severity": "MEDIUM",
        "regex": r"function\s+propose\s*\(|function\s+createProposal\s*\(",
        "desc": "Proposal creation lacks a delegated-vote threshold check "
                "(proposalThreshold). Spammers can flood the governance queue. "
                "Enforce a minimum delegated voting power to create proposals.",
    },
    {
        "name": "short voting period",
        "attack": "governance",
        "severity": "MEDIUM",
        "regex": r"votingPeriod\s*[=:]\s*(?:<|<=)?\s*[1-9]\d{1,2}\s*[;)]",
        "desc": "Voting period is short (seconds, not blocks-days). Short periods "
                "discourage participation and enable last-block voting manipulation. "
                "Use >= 1 day (7200+ blocks) voting periods.",
    },
    {
        "name": "governance action without timelock",
        "attack": "governance",
        "severity": "MEDIUM",
        "regex": r"function\s+execute\s*\(|function\s+queue\s*\(",
        "desc": "Proposal execution path has no visible timelock/queue delay. "
                "Executing instantly removes the community's exit window on "
                "malicious proposals. Route executions through a TimelockController.",
    },
]

# ---------------------------------------------------------------------------
# Oracle scanner — spot price, manipulable feeds
# ---------------------------------------------------------------------------

ORACLE_PATTERNS = [
    {
        "name": "spot price via DEX reserves",
        "attack": "oracle",
        "severity": "HIGH",
        "regex": r"getReserves\s*\(|getAmountsOut\s*\(|slot0\s*\(",
        "desc": "Pricing reads DEX spot reserves (Uniswap V2 getReserves or V3 "
                "slot0). Spot price is manipulable in a single block via a "
                "flash loan — swap the pair, trigger the vulnerable read, repay. "
                "Use a TWAP oracle (>= 30 min window) or Chainlink.",
    },
    {
        "name": "single oracle source without deviation checks",
        "attack": "oracle",
        "severity": "MEDIUM",
        "regex": r"latestRoundData\s*\(|latestAnswer\s*\(",
        "desc": "Uses a Chainlink feed without validating staleness/round "
                "freshness (updatedAt age check) or deviation guard. A stale or "
                "manipulated feed directly prices user funds. Validate "
                "updateTime recency and add min/max circuit breakers.",
    },
    {
        "name": "unchecked oracle return",
        "attack": "oracle",
        "severity": "MEDIUM",
        "regex": r"price\s*=.*(?:latestAnswer|latestRoundData)|return\s*\([^)]*price",
        "desc": "Oracle price returned without sanity range checks. If the feed "
                "returns 0 or an extreme value (e.g. during an outage), "
                "liquidation/borrow logic misprices risk. Add min/max price "
                "bounds and zero-check.",
    },
]

# ---------------------------------------------------------------------------
# Upgradability scanner — unguarded upgrades, EOA admin
# ---------------------------------------------------------------------------

UPGRADABILITY_PATTERNS = [
    {
        "name": "upgrade function without access control",
        "attack": "delegatecall",
        "severity": "HIGH",
        "regex": r"function\s+(?:upgradeTo|upgradeToAndCall|setImplementation|"
                 r"changeProxyAdmin|updateImplementation)\s*\(",
        "desc": "Upgrade path present but no visible modifier/role guard in the "
                "signature context. Anyone able to call it can point the proxy "
                "at attacker logic and steal all funds. Add onlyOwner/timelock "
                "or OpenZeppelin UUPS authorizeUpgrade.",
    },
    {
        "name": "proxy admin is a single EOA",
        "attack": "delegatecall",
        "severity": "MEDIUM",
        "regex": r"admin\s*[=:]\s*0x[a-fA-F0-9]{40}|owner\s*[=:]\s*0x[a-fA-F0-9]{40}",
        "desc": "An admin/owner address is hardcoded to a single EOA. Key "
                "compromise = instant proxy takeover and full drain. Move "
                "upgrade authority to a multisig/timelock (e.g. Safe + "
                "TimelockController).",
    },
    {
        "name": "constructor-less proxy (init not protected)",
        "attack": "initialize",
        "severity": "HIGH",
        "regex": r"constructor\s*\(\)\s*(?:public|internal)?\s*\{\s*\}|"
                 r"function\s+initialize\s*\([^)]*\)\s*(?:external|public)",
        "desc": "Proxy pattern with no constructor init and an initialize() that "
                "may lack the initializer guard — first caller wins ownership. "
                "Verify OZ Initializer/onlyInitializing is on every initialize().",
    },
]

# ---------------------------------------------------------------------------
# Cross-chain scanner — missing replay protection
# ---------------------------------------------------------------------------

CROSS_CHAIN_PATTERNS = [
    {
        "name": "missing cross-chain replay protection",
        "attack": "bridge",
        "severity": "HIGH",
        "regex": r"receiveMessage|processMessage|handleMessage|executeMessage|"
                 r"relayMessage|claimMessage",
        "desc": "Cross-chain message handler found. If the handler does not "
                "verify source chain id + nonce/replay guard, the same message "
                "can be replayed on every chain (or re-submitted). Verify "
                "nonce incrementing, chain-id check, and per-message execution "
                "flag before state changes.",
    },
    {
        "name": "mint/burn bridge without merkle or sig verification",
        "attack": "bridge",
        "severity": "HIGH",
        "regex": r"function\s+mint\s*\([^)]*(?:to|recipient)|function\s+burn\s*\(",
        "desc": "Bridge mint/burn without visible Merkle proof or signature "
                "verification. Anyone (or a spoofed source message) can mint "
                "unbacked tokens. Require verified inclusion proofs and a "
                "trusted validator set.",
    },
    {
        "name": "chain id not included in domain/message hash",
        "attack": "bridge",
        "severity": "MEDIUM",
        "regex": r"keccak256\s*\(\s*abi\.encode|DOMAIN_SEPARATOR|domainSeparator",
        "desc": "Hashing does not obviously bind the message to a specific "
                "chainId. Cross-chain replay across forks/deployments becomes "
                "possible. Include chainid in the message hash / EIP-712 domain.",
    },
]


ALL_SCANNERS: Dict[str, List[Dict]] = {
    "governance": GOVERNANCE_PATTERNS,
    "oracle": ORACLE_PATTERNS,
    "upgradability": UPGRADABILITY_PATTERNS,
    "cross_chain": CROSS_CHAIN_PATTERNS,
}

SCANNER_LABELS = {
    "governance": "Governance",
    "oracle": "Oracle",
    "upgradability": "Upgradability",
    "cross_chain": "Cross-Chain",
}


def scan_source_text(source: str, label: str = "source") -> List[Dict]:
    """Run all advanced scanner patterns against a full source text."""
    stripped = _strip_comments(source)
    findings: List[Dict] = []
    for scanner_name, patterns in ALL_SCANNERS.items():
        for pat in patterns:
            m = re.search(pat["regex"], stripped, re.IGNORECASE)
            if not m:
                continue
            line = source[: m.start()].count("\n") + 1
            # grab surrounding snippet
            lines = source.splitlines()
            snippet = lines[line - 1].strip()[:140] if 0 < line <= len(lines) else ""
            findings.append({
                "severity": pat["severity"],
                "title": f"{SCANNER_LABELS[scanner_name]}: {pat['name']}",
                "attack": pat["attack"],
                "file": label,
                "line": line,
                "snippet": snippet,
                "endpoint": f"{label}:{line}",
                "description": pat["desc"],
                "scanner": scanner_name,
                "confirmed": False,
                "source": "scanner",
            })
    return findings


def scan_repo_dir(repo_dir: str, repo_label: str = "") -> List[Dict]:
    """Run the advanced scanners across every protocol-owned .sol file."""
    root = Path(repo_dir)
    if not root.is_dir():
        return []
    findings: List[Dict] = []
    for sol in _iter_sol_files(root):
        try:
            text = sol.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(sol.relative_to(root))
        hits = scan_source_text(text, label=rel)
        for f in hits:
            f["endpoint"] = f"{rel}:{f['line']}"
            if repo_label:
                f["repo"] = repo_label
        findings.extend(hits)
    # Sort CRITICAL-first
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return sorted(findings, key=lambda f: order.get(f["severity"], 99))
