"""SARIF 2.1.0 export — OASIS static analysis results format.

Compatible with GitHub Advanced Security / CodeQL ingestion so findings
appear directly in a repo's Security tab. Also consumable by SARIF
viewers (VS Code SARIF viewer, sarif-web-component).
"""
from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Dict, List, Optional

SARIF_VERSION = "2.1.0"
SCHEMA = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"

# severity → SARIF level
_SEV_LEVEL = {
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
    "INFO": "note",
}


def _rule_key(f: Dict) -> str:
    return f.get("title", "finding")[:90]


def _artifact_path(f: Dict) -> str:
    return f.get("file") or f.get("endpoint") or f.get("contract") or "target.sol"


def findings_to_sarif(findings: List[Dict],
                      tool_name: str = "defi-hunter",
                      tool_version: str = "unknown",
                      target: str = "target",
                      repo_uri: Optional[str] = None) -> Dict:
    """Convert defi-hunter findings to a SARIF 2.1.0 log dict."""
    rules: Dict[str, Dict] = {}
    results: List[Dict] = []

    for idx, f in enumerate(findings):
        sev = f.get("severity", "INFO").upper()
        level = _SEV_LEVEL.get(sev, "warning")
        key = _rule_key(f)
        if key not in rules:
            rules[key] = {
                "id": f"DH-{idx + 1:04d}",
                "name": f.get("title", "finding"),
                "shortDescription": {"text": f.get("title", "finding")},
                "fullDescription": {"text": f.get("description", "")},
                "defaultConfiguration": {"level": level},
                "properties": {
                    "severity": sev,
                    "attack": f.get("attack", ""),
                    "source": f.get("source", "analyzer"),
                    "tags": [t for t in [f.get("attack"), f.get("scanner")] if t],
                },
                "help": {"text": f.get("description", "")},
            }

        rule_id = rules[key]["id"]
        path = _artifact_path(f)
        line = int(f.get("line", 0) or 0)
        result = {
            "ruleId": rule_id,
            "ruleIndex": list(rules).index(key),
            "level": level,
            "message": {"text": f"{f.get('title', 'finding')} — {f.get('description', '')}"},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": path},
                    "region": {"startLine": max(1, line)} if line else {},
                }
            }],
            "properties": {
                "severity": sev,
                "attack": f.get("attack", ""),
                "endpoint": f.get("endpoint", ""),
                "confirmed": bool(f.get("confirmed", False)),
            },
        }
        if repo_uri:
            result["locations"][0]["physicalLocation"]["artifactLocation"]["uriBaseId"] = "SRCROOT"
        results.append(result)

    log = {
        "$schema": SCHEMA,
        "version": SARIF_VERSION,
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": "https://github.com/AsadX78/defi-hunter",
                    "rules": list(rules.values()),
                }
            },
            "automationDetails": {
                "id": f"defi-hunter/{target}",
                "description": {"text": f"DeFi Hunter security assessment of {target}"},
            },
            "results": results,
            "originalUriBaseIds": {"SRCROOT": {"uri": repo_uri or "file:///"}},
            "invocations": [{
                "executionSuccessful": True,
                "startTimeUtc": datetime.now(timezone.utc).isoformat(),
                "toolExecutionNotifications": [],
            }],
        }]
    }
    return log


def export_sarif(findings: List[Dict], output: str, **kwargs) -> str:
    """Write a SARIF log file; returns the output path."""
    log = findings_to_sarif(findings, **kwargs)
    with open(output, "w", encoding="utf-8") as fh:
        json.dump(log, fh, indent=2)
    return output
