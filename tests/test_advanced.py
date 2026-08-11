"""Tests for advanced features: Slither integration, scanners, diagrams,
SARIF export, fuzz generation, and issue sync."""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from defihunter.core.analyzer import analyze_repo_dir, analyze_repo_with_slither
from defihunter.core.scanners import scan_source_text, scan_repo_dir, ALL_SCANNERS
from defihunter.core.diagrams import attack_flow, call_graph, storage_layout, render_diagram_markdown
from defihunter.core.sarif import findings_to_sarif, export_sarif
from defihunter.core.fuzz import generate_fuzz_suite, run_fuzz_suite, forge_available, fuzz_test_name
from defihunter.core.sync import sync_github, sync_jira, SyncError


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------

@pytest.fixture
def vuln_repo(tmp_path: Path) -> Path:
    """A tiny Solidity repo with an obvious unguarded mint."""
    repo = tmp_path / "vuln-repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "BadToken.sol").write_text('''// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract BadToken {
    mapping(address => uint256) public balances;
    address public owner;

    function mint(address to, uint256 amount) public {
        balances[to] += amount;  // no access control!
    }

    function withdraw(uint256 amount) external {
        // CEI violation: external call before state update
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "transfer failed");
        balances[msg.sender] -= amount;
    }

    function getPrice() public view returns (uint256) {
        // spot price from reserves — oracle manipulable
        return balances[address(this)];
    }
}
''')
    (repo / "README.md").write_text("bad repo")
    return repo


@pytest.fixture
def findings() -> list:
    return [
        {
            "severity": "HIGH",
            "title": "mint() without access control",
            "attack": "mint",
            "file": "src/BadToken.sol",
            "line": 8,
            "description": "Anyone can mint",
            "endpoint": "src/BadToken.sol:8",
            "confirmed": False,
        },
        {
            "severity": "MEDIUM",
            "title": "CEI violation",
            "attack": "reentrancy",
            "file": "src/BadToken.sol",
            "line": 13,
            "description": "External call before state update",
            "endpoint": "src/BadToken.sol:13",
            "confirmed": False,
        },
    ]


# ---------------------------------------------------------------------------
# Advanced scanners
# ---------------------------------------------------------------------------

def test_scan_source_text_governance():
    src = "function propose(address[] calldata targets) external { execute(targets); }"
    hits = scan_source_text(src, label="Gov.sol")
    assert hits
    assert all(h["scanner"] == "governance" for h in hits)
    assert all(h.get("source") == "scanner" for h in hits)


def test_scan_source_text_oracle():
    src = "(uint112 r0, uint112 r1,) = pair.getReserves();"
    hits = scan_source_text(src, label="Oracle.sol")
    assert any(h["scanner"] == "oracle" and h["attack"] == "oracle" for h in hits)


def test_scan_source_text_upgradability():
    src = "function upgradeTo(address newImpl) external { _setImplementation(newImpl); }"
    hits = scan_source_text(src, label="Proxy.sol")
    assert any(h["scanner"] == "upgradability" and h["attack"] == "delegatecall" for h in hits)


def test_scan_source_text_cross_chain():
    src = "function handleMessage(bytes memory data) external { mint(data); }"
    hits = scan_source_text(src, label="Bridge.sol")
    assert any(h["scanner"] == "cross_chain" and h["attack"] == "bridge" for h in hits)


def test_all_scanners_have_required_fields():
    for name, patterns in ALL_SCANNERS.items():
        for pat in patterns:
            assert pat["name"]
            assert pat["attack"]
            assert pat["severity"] in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
            assert pat["regex"]


def test_scan_repo_dir_finds_patterns(vuln_repo: Path):
    hits = scan_repo_dir(str(vuln_repo), repo_label="test")
    assert hits
    for h in hits:
        assert h["endpoint"].startswith("src/")


def test_scan_source_comments_ignored():
    src = "// getReserves() is safe here — we use TWAP\nfunction f() public {}"
    hits = scan_source_text(src, label="Comment.sol")
    assert not hits


# ---------------------------------------------------------------------------
# Slither integration
# ---------------------------------------------------------------------------

def test_analyze_repo_with_slither_runs_without_crash(vuln_repo: Path):
    """The combined wrapper should work even when slither is not installed."""
    result = analyze_repo_with_slither(str(vuln_repo), repo_label="test")
    assert "findings" in result
    assert "slither" in result
    assert "slither_ran" in result
    assert result["findings"]  # line-aware engine always finds the unguarded mint


def test_slither_available_returns_bool():
    assert isinstance(__import__("defihunter.core.slither", fromlist=["slither_available"]).slither_available(), bool)


def test_analyze_repo_dir_keeps_working(vuln_repo: Path):
    findings = analyze_repo_dir(str(vuln_repo), repo_label="test")
    assert findings
    attacks = {f["attack"] for f in findings}
    assert "mint" in attacks


# ---------------------------------------------------------------------------
# Mermaid diagrams
# ---------------------------------------------------------------------------

def test_attack_flow_diagram(findings):
    mmd = attack_flow(findings, "BadToken")
    assert mmd.startswith("flowchart TD")
    assert "Attacker" in mmd
    assert "BadToken" in mmd
    assert "mint" in mmd


def test_call_graph_diagram(findings):
    contracts = {"0xabc": {"name": "BadToken"}}
    mmd = call_graph(contracts, findings, "BadToken")
    assert mmd.startswith("flowchart LR")
    assert "BadToken" in mmd


def test_storage_layout_diagram():
    src = "contract C { address owner; uint256 totalSupply; mapping(address=>uint256) balances; }"
    mmd = storage_layout([src], "C")
    assert "slot 0" in mmd
    assert "owner" in mmd


def test_render_diagram_markdown_empty():
    assert render_diagram_markdown("attack_flow", findings=[]) == ""


def test_render_diagram_markdown_fenced(findings):
    md = render_diagram_markdown("attack_flow", target="T", findings=findings)
    assert md.startswith("```mermaid")
    assert md.endswith("```")


# ---------------------------------------------------------------------------
# SARIF export
# ---------------------------------------------------------------------------

def test_sarif_structure(findings):
    log = findings_to_sarif(findings, tool_version="1.5.0", target="BadToken")
    assert log["version"] == "2.1.0"
    run = log["runs"][0]
    assert run["tool"]["driver"]["name"] == "defi-hunter"
    assert len(run["results"]) == 2
    # Severity → level mapping
    assert run["results"][0]["level"] == "error"
    assert run["results"][1]["level"] == "warning"


def test_sarif_export_file(findings, tmp_path):
    out = tmp_path / "report.sarif"
    export_sarif(findings, str(out), tool_version="1.5.0", target="T")
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"
    assert len(data["runs"][0]["results"]) == 2


def test_sarif_empty():
    log = findings_to_sarif([], target="T")
    assert log["runs"][0]["results"] == []


# ---------------------------------------------------------------------------
# Fuzz integration
# ---------------------------------------------------------------------------

def test_fuzz_test_name():
    assert fuzz_test_name("0x1234567890abcdef") == "Fuzz1234"


def test_generate_fuzz_suite(tmp_path):
    path = generate_fuzz_suite(["mint", "initialize"], target_addr="0x1234567890abcdef",
                               out_dir=str(tmp_path / "fuzz"))
    assert path and Path(path).exists()
    content = Path(path).read_text()
    assert "testFuzz_mint_anyone" in content
    assert "testFuzz_initialize_secondCaller" in content
    assert "forge-std/Test.sol" in content


def test_generate_fuzz_suite_no_match(tmp_path):
    path = generate_fuzz_suite(["unknownattack"], out_dir=str(tmp_path))
    assert path is None


def test_run_fuzz_suite_graceful_missing(tmp_path):
    """Without forge, run_fuzz_suite returns ran=False rather than crashing."""
    result = run_fuzz_suite(str(tmp_path / "nope.t.sol"))
    assert result["ran"] is False
    assert "passed" in result and "failed" in result


# ---------------------------------------------------------------------------
# Reporter integration (diagrams + custom template)
# ---------------------------------------------------------------------------

@pytest.fixture
def report_payload(findings) -> dict:
    return {
        "tool": "defihunter",
        "version": "1.5.0",
        "target": "BadToken",
        "chain": "ethereum",
        "contracts": {"0x1234": {"name": "BadToken", "verified": True}},
        "vulnerabilities": findings,
        "scan_time": "2026-08-11T00:00:00",
        "tool_version": "1.5.0",
    }


def test_report_html_with_diagrams(report_payload, tmp_path):
    from defihunter.core.reporter import ReportGenerator
    out = tmp_path / "report.html"
    ReportGenerator().generate(report_payload, format="html", output=str(out),
                               diagrams=["attack_flow", "call_graph"])
    html = out.read_text()
    assert "class='mermaid'" in html
    assert "mermaid.initialize" in html


def test_report_markdown_with_diagrams(report_payload, tmp_path):
    from defihunter.core.reporter import ReportGenerator
    out = tmp_path / "report.md"
    ReportGenerator().generate(report_payload, format="markdown", output=str(out),
                               diagrams=["attack_flow"])
    md = out.read_text()
    assert "```mermaid" in md
    assert "## Diagrams" in md


def test_report_sarif_format(report_payload, tmp_path):
    from defihunter.core.reporter import ReportGenerator
    out = tmp_path / "report.sarif"
    ReportGenerator().generate(report_payload, format="sarif", output=str(out))
    data = json.loads(out.read_text())
    assert data["version"] == "2.1.0"


def test_report_custom_template(report_payload, tmp_path):
    """Custom Jinja2 template rendering (jinja2 is a dev extra)."""
    jinja2 = pytest.importorskip("jinja2")
    from defihunter.core.reporter import ReportGenerator
    tpl = tmp_path / "custom.html.j2"
    tpl.write_text(
        "<html><h1>{{ target }}</h1><p>risk {{ risk_score }}</p>"
        "<p>crit {{ counts.CRITICAL }}</p>{{ findings_html }}</html>")
    out = tmp_path / "custom.html"
    ReportGenerator().generate(report_payload, format="html", output=str(out),
                               template=str(tpl))
    html = out.read_text()
    assert "BadToken" in html
    assert "risk 35" in html  # 1 HIGH(25) + 1 MEDIUM(10) = 35


# ---------------------------------------------------------------------------
# Issue sync
# ---------------------------------------------------------------------------

def test_sync_github_dry_run(findings):
    res = sync_github(findings, "AsadX78", "defi-hunter", floor="MEDIUM", dry_run=True)
    assert res["dry_run"] is True
    assert len(res["created"]) == 2  # both above/at MEDIUM
    assert res["created"][0]["title"].startswith("[HIGH]")


def test_sync_github_floor_skips_low():
    low = [{"severity": "LOW", "title": "x", "attack": "a", "description": "d"}]
    res = sync_github(low, "o", "r", floor="MEDIUM", dry_run=True)
    assert res["skipped"] == 1
    assert res["created"] == []


def test_sync_github_no_token_raises(findings):
    os.environ.pop("GITHUB_TOKEN", None)
    with pytest.raises(SyncError):
        sync_github(findings, "o", "r", floor="MEDIUM", dry_run=False)


def test_sync_jira_dry_run(findings):
    res = sync_jira(findings, "https://example.atlassian.net", "SEC",
                    email="a@b.c", token="x", dry_run=True)
    assert res["dry_run"] is True
    assert len(res["created"]) == 2
    assert res["created"][0]["fields"]["issuetype"]["name"] == "Bug"


def test_sync_jira_no_creds_raises(findings):
    os.environ.pop("JIRA_EMAIL", None)
    os.environ.pop("JIRA_API_TOKEN", None)
    with pytest.raises(SyncError):
        sync_jira(findings, "https://example.atlassian.net", "SEC",
                  floor="MEDIUM", dry_run=False)
