"""Issue sync — push findings to GitHub Issues or Jira.

Both syncs use the standard REST APIs with token auth:
  - GitHub:  POST /repos/{owner}/{repo}/issues  (GITHUB_TOKEN)
  - Jira:    POST /rest/api/2/issue              (JIRA_BASE_URL + JIRA_EMAIL + JIRA_API_TOKEN)

Every finding above a severity floor becomes a ticket with the PoC,
evidence, and remediation from the report. Dry-run mode prints instead
of creating — useful for CI previews.
"""
from __future__ import annotations

import json
import os
import urllib.request
from typing import Dict, List, Optional

SEV_FLOOR = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}


class SyncError(Exception):
    pass


def _floor_reached(sev: str, floor: str) -> bool:
    return SEV_FLOOR.get(sev.upper(), 99) <= SEV_FLOOR.get(floor.upper(), 3)


def _request(url: str, payload: Dict, token: str, extra_headers: Optional[Dict] = None,
             method: str = "POST") -> Dict:
    headers = {
        "Authorization": f"Bearer {token}",
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "defi-hunter/1.6",
    }
    if extra_headers:
        headers.update(extra_headers)
    req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                 headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=30) as resp:
            body = resp.read().decode("utf-8", errors="replace")
            return json.loads(body) if body else {}
    except urllib.error.HTTPError as e:
        detail = e.read().decode("utf-8", errors="replace")[:400]
        raise SyncError(f"HTTP {e.code} from {url}: {detail}")
    except urllib.error.URLError as e:
        raise SyncError(f"Network error to {url}: {e.reason}")


# ---------------------------------------------------------------------------
# GitHub
# ---------------------------------------------------------------------------

def _github_issue_body(f: Dict) -> str:
    lines = [
        f"**Severity:** {f.get('severity', 'INFO')}",
        f"**Attack:** `{f.get('attack', 'unknown')}`",
        f"**Location:** `{f.get('endpoint', f.get('file', ''))}`",
        "",
        "**Description**",
        f"{f.get('description', '')}",
    ]
    if f.get("evidence"):
        lines += ["", "**Evidence**", f"```", f"{f['evidence']}", "```"]
    if f.get("remediation"):
        lines += ["", "**Remediation**", f"{f['remediation']}"]
    if f.get("references"):
        lines += ["", "**References**"] + [f"- {r}" for r in f["references"] if r]
    return "\n".join(lines)


def sync_github(findings: List[Dict], owner: str, repo: str,
                token: Optional[str] = None, floor: str = "MEDIUM",
                dry_run: bool = False, labels: Optional[List[str]] = None) -> Dict:
    """Create a GitHub issue per finding. Returns {"created": [...], "skipped": N}."""
    token = token or os.getenv("GITHUB_TOKEN")
    if not token and not dry_run:
        raise SyncError("GITHUB_TOKEN not set (and no --token given)")

    created: List[Dict] = []
    skipped = 0
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if not _floor_reached(sev, floor):
            skipped += 1
            continue
        issue = {
            "title": f"[{sev}] {f.get('title', 'finding')}",
            "body": _github_issue_body(f),
        }
        lbl = labels or [f"defi-hunter", sev.lower()]
        issue["labels"] = lbl
        if dry_run:
            created.append({"dry_run": True, **issue})
            continue
        try:
            resp = _request(f"https://api.github.com/repos/{owner}/{repo}/issues",
                            issue, token)
            created.append({"url": resp.get("html_url", ""), "number": resp.get("number")})
        except SyncError as e:
            skipped += 1
    return {"created": created, "skipped": skipped, "dry_run": dry_run}


# ---------------------------------------------------------------------------
# Jira
# ---------------------------------------------------------------------------

def _jira_payload(f: Dict, project: str, issue_type: str) -> Dict:
    summary = f"[{f.get('severity','INFO')}] {f.get('title','finding')}"
    desc = (
        f"h3. Description\n\n{f.get('description','')}\n\n"
        f"|| Field || Value ||\n"
        f"| Severity | {f.get('severity','INFO')} |\n"
        f"| Attack | {f.get('attack','unknown')} |\n"
        f"| Location | {f.get('endpoint', f.get('file',''))} |\n\n"
        f"h3. Remediation\n\n{f.get('remediation', 'Manual review recommended.')}"
    )
    return {
        "fields": {
            "project": {"key": project},
            "summary": summary[:250],
            "description": desc,
            "issuetype": {"name": issue_type},
        }
    }


def sync_jira(findings: List[Dict], base_url: str, project: str,
              email: Optional[str] = None, token: Optional[str] = None,
              issue_type: str = "Bug", floor: str = "MEDIUM",
              dry_run: bool = False) -> Dict:
    """Create a Jira issue per finding. Returns {"created": [...], "skipped": N}."""
    email = email or os.getenv("JIRA_EMAIL")
    token = token or os.getenv("JIRA_API_TOKEN")
    if (not email or not token) and not dry_run:
        raise SyncError("JIRA_EMAIL / JIRA_API_TOKEN not set")

    created: List[Dict] = []
    skipped = 0
    for f in findings:
        sev = f.get("severity", "INFO").upper()
        if not _floor_reached(sev, floor):
            skipped += 1
            continue
        payload = _jira_payload(f, project, issue_type)
        if dry_run:
            created.append({"dry_run": True, **payload})
            continue
        try:
            url = base_url.rstrip("/") + "/rest/api/2/issue"
            headers = {
                "Authorization": "Basic " + __import__("base64").b64encode(
                    f"{email}:{token}".encode()).decode(),
            }
            resp = _request(url, payload, token, extra_headers=headers)
            created.append({"key": resp.get("key", ""), "url": resp.get("self", "")})
        except SyncError as e:
            skipped += 1
    return {"created": created, "skipped": skipped, "dry_run": dry_run}
