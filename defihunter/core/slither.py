"""Slither integration — run 90+ detectors alongside our line-aware analyzer.

Slither is a Solidity static analysis framework (https://github.com/crytic/slither).
If `slither` is on PATH, we run it and merge findings into our report.
If not installed, we gracefully skip (no hard dependency).
"""
from __future__ import annotations

import json
import shutil
import subprocess
from typing import Dict, List

# --- Slither detector to our finding mapping ---

SLITHER_DETECTOR_MAP: Dict[str, Dict] = {
    "reentrancy-eth": {
        "attack": "reentrancy",
        "title": "Slither: reentrancy-eth",
        "severity": "HIGH",
        "desc": "Slither detected reentrancy via .call() — state updated after external call",
    },
    "reentrancy-no-eth": {
        "attack": "reentrancy",
        "title": "Slither: reentrancy-no-eth",
        "severity": "HIGH",
        "desc": "Slither detected reentrancy via send/transfer",
    },
    "reentrancy-unlimited": {
        "attack": "reentrancy",
        "title": "Slither: reentrancy-unlimited",
        "severity": "HIGH",
        "desc": "Unbounded call/delegatecall in a loop",
    },
    "wrong-visibility": {
        "attack": "governance",
        "title": "Slither: wrong-visibility",
        "severity": "MEDIUM",
        "desc": "Function has weaker visibility than intended",
    },
    "missing-zero": {
        "attack": "governance",
        "title": "Slither: missing-zero-check",
        "severity": "MEDIUM",
        "desc": "Address argument missing zero-check",
    },
    "unchecked-low-level": {
        "attack": "arbitrarycall",
        "title": "Slither: unchecked-low-level",
        "severity": "MEDIUM",
        "desc": "Low-level calls without return data verification",
    },
    "arithmetic": {
        "attack": "overflow",
        "title": "Slither: arithmetic",
        "severity": "HIGH",
        "desc": "Integer overflow/underflow detected",
    },
    "timestamp": {
        "attack": "oracle",
        "title": "Slither: timestamp-dependence",
        "severity": "MEDIUM",
        "desc": "Block timestamp dependence can enable oracle manipulation",
    },
    "block-number": {
        "attack": "oracle",
        "title": "Slither: block-number-dependence",
        "severity": "LOW",
        "desc": "Block number dependence",
    },
    "arbitrary-send": {
        "attack": "governance",
        "title": "Slither: arbitrary-send",
        "severity": "HIGH",
        "desc": "Arbitrary ether sending — potential rug pull",
    },
    "delegatecall-loop": {
        "attack": "delegatecall",
        "title": "Slither: delegatecall-loop",
        "severity": "HIGH",
        "desc": "Delegatecall to user-controlled address in a loop",
    },
    "delegatecall-unbound": {
        "attack": "delegatecall",
        "title": "Slither: delegatecall-unbound",
        "severity": "HIGH",
        "desc": "Unbound delegatecall — potential code injection",
    },
    "front-running": {
        "attack": "frontrun",
        "title": "Slither: front-running",
        "severity": "MEDIUM",
        "desc": "State variable read after call — front-running risk",
    },
    "suicidal-transfers": {
        "attack": "selfdestruct",
        "title": "Slither: suicidal-transfers",
        "severity": "HIGH",
        "desc": "Contract has selfdestruct that can be triggered",
    },
    "uninitialized-local": {
        "attack": "governance",
        "title": "Slither: uninitialized-local",
        "severity": "MEDIUM",
        "desc": "Local variable not initialized",
    },
    "uninitialized-state": {
        "attack": "governance",
        "title": "Slither: uninitialized-state",
        "severity": "LOW",
        "desc": "State variable not initialized in constructor",
    },
    "default": {
        "attack": "governance",
        "title": "Slither: {detector}",
        "severity": "MEDIUM",
        "desc": "Slither detector flagged a potential issue",
    },
}


def _sev_rank(s: str) -> int:
    order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    return order.get(s, 99)


def slither_available() -> bool:
    """Check if slither binary is on PATH."""
    import shutil
    return shutil.which("slither") is not None


def run_slither(target: str, timeout: int = 120) -> List[Dict]:
    """Run Slither on a target, return parsed findings.

    Args:
        target: path to .sol file, directory, or "0x..." address
        timeout: max seconds

    Returns:
        List of finding dicts compatible with analyze_file output
    """
    if not slither_available():
        return []

    import os
    import json
    from pathlib import Path

    # Handle address-based targets: need to get source first
    if target.lower().startswith("0x"):
        api_key = os.getenv("ETHERSCAN_API_KEY", "")
        if not api_key:
            return []
        # Fetch verified source and write to temp file
        from tempfile import TemporaryDirectory
        with TemporaryDirectory(prefix="defihunter-slither-") as td:
            src_file = Path(td) / "contract.sol"
            url = f"https://api.etherscan.io/v2/api?chainid=1&module=contract&action=getsourcecode&address={target}&apikey={api_key}"
            try:
                result = subprocess.run(
                    ["curl", "-sL", url],
                    capture_output=True, text=True, timeout=30,
                )
                data = json.loads(result.stdout)
                if data.get("status") == "1":
                    source = data["result"][0].get("SourceCode", "")
                    src_file.write_text(source)
                    return _run_slither_on_file(str(src_file), timeout)
            except Exception:
                return []
        return []
    else:
        return _run_slither_on_file(str(target), timeout)


def _run_slither_on_file(target: str, timeout: int) -> List[Dict]:
    """Run slither on a file/directory and parse JSON output."""
    import subprocess
    import json

    cmd = ["slither", target, "--json", "-"]
    try:
        result = subprocess.run(
            cmd, capture_output=True, text=True, timeout=timeout,
        )
    except (subprocess.TimeoutExpired, FileNotFoundError):
        return []

    if result.returncode != 0 and not result.stdout.strip():
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    findings: List[Dict] = []
    # Slither's JSON schema: results.detectors (not "detection"). Accept both
    # so we're resilient across slither versions.
    results = data.get("results", {})
    dets = results.get("detectors") or results.get("detection") or []
    for det in dets:
        detector_id = det.get("check", "") or det.get("id", "")
        if not detector_id:
            continue
        info = SLITHER_DETECTOR_MAP.get(detector_id, SLITHER_DETECTOR_MAP["default"]).copy()
        if detector_id not in SLITHER_DETECTOR_MAP:
            info["title"] = info["title"].format(detector=detector_id)

        elements = det.get("elements", [])
        src = ""
        line = 0
        snippet = ""
        if elements:
            first = elements[0]
            sm = first.get("source_mapping", {})
            # Prefer the short name; fall back to relative/absolute. Slither's
            # filename_relative can contain ../.. traversal when run on a bare
            # file — strip that so endpoints stay clean.
            src = (sm.get("filename_short")
                   or sm.get("filename_relative")
                   or sm.get("filename", ""))
            src = src.replace("../../", "").replace("../", "")
            line = (sm.get("lines") or [0])[0] or 0
            snippet = sm.get("source", "")[:140]

        desc = info.get("desc", "Slither finding")
        wiki = det.get("reference", "") or det.get("wiki", "")
        if wiki:
            desc += f"\n\nReference: {wiki}"
        if det.get("description"):
            desc = f"{desc}\n\n{det['description']}" if desc != info.get("desc") else det["description"]

        # Severity from the detector map; fall back to slither's impact rating
        # for detectors we don't explicitly map.
        severity = info.get("severity", "MEDIUM")
        mapped = detector_id in SLITHER_DETECTOR_MAP
        impact = (det.get("impact") or "").lower()
        if not mapped:
            severity = {
                "high": "HIGH", "medium": "MEDIUM", "low": "LOW",
                "informational": "INFO", "optimization": "INFO",
            }.get(impact, severity)

        finding = {
            "severity": severity,
            "title": info.get("title", f"Slither: {detector_id}"),
            "attack": info.get("attack", "governance"),
            "file": src or target,
            "line": line,
            "snippet": snippet,
            "endpoint": f"{src}:{line}" if src else str(target),
            "description": desc,
            "confirmed": False,
            "source": "slither",
            "detector_id": detector_id,
            "impact": det.get("impact", ""),
            "references": [r for r in [wiki] if r],
        }
        findings.append(finding)

    return findings


def merge_slither_findings(existing: List[Dict], slither_findings: List[Dict]) -> List[Dict]:
    """Merge Slither findings — bump severity if same attack type found in same file."""
    if not slither_findings:
        return existing

    indexed = {}
    for ef in existing:
        key = (ef.get("attack"), ef.get("file"))
        if key not in indexed or _sev_rank(ef.get("severity")) < _sev_rank(indexed[key].get("severity")):
            indexed[key] = ef

    merged = list(existing)
    for sf in slither_findings:
        key = (sf.get("attack"), sf.get("file"))
        if key in indexed:
            ef = indexed[key]
            if _sev_rank(sf.get("severity")) < _sev_rank(ef.get("severity")):
                ef["severity"] = sf["severity"]
                ef["source"] = (ef.get("source", "") or "") + "+slither"
        else:
            merged.append(sf)

    return merged
