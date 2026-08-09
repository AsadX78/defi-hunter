"""Benchmark + analyzer guard-correctness tests (offline, no RPC)."""

import json

from defihunter.core.benchmark import run_benchmark, summarize
from defihunter.core.analyzer import analyze_repo_dir, _is_guarded


def test_benchmark_detects_all_historical_exploits():
    results = run_benchmark()
    by_id = {r["id"]: r for r in results}
    # every vulnerable fixture must be flagged
    for r in results:
        if not r["control"]:
            assert r["detected"], f"{r['id']} not detected: missed={r['missed']}"
    # the clean vault must produce zero HIGH/CRITICAL findings
    assert by_id["control-clean-vault"]["detected"]
    # public constants (EIP-1967 slots, padded selectors) must NOT be flagged
    assert by_id["control-public-constants"]["detected"], (
        "public-constants control failed: " +
        str([f["title"] for f in by_id["control-public-constants"]["findings"]
             if f.get("severity") in ("CRITICAL", "HIGH")]))
    s = summarize(results)
    assert s["detected"] == s["total"] == 12
    assert s["false_positives"] == 0


def test_benchmark_results_are_reproducible():
    """Same corpus twice → identical verdicts (deterministic, offline)."""
    r1 = {r["id"]: r["detected"] for r in run_benchmark()}
    r2 = {r["id"]: r["detected"] for r in run_benchmark()}
    assert r1 == r2


def test_guard_check_ignores_comments():
    """'// no onlyOwner' describes the code — it must NOT count as a guard."""
    assert not _is_guarded("function mint(address to, uint256 amt) public { // no onlyOwner")


def test_guard_check_still_detects_real_modifiers():
    assert _is_guarded("function mint(address to, uint256 amt) external onlyOwner {")
    assert _is_guarded("function initialize(address o) public { require(!init);")


def test_analyzer_comment_does_not_suppress_mint(tmp_path):
    src = """pragma solidity ^0.8.0;
contract Token {
    function mint(address to, uint256 amount) public {   // TODO: add onlyOwner!
        balanceOf[to] += amount;
    }
}
"""
    (tmp_path / "Case.sol").write_text(src)
    findings = analyze_repo_dir(str(tmp_path))
    assert any(f.get("attack") == "mint" for f in findings)


def test_benchmark_cli_json_serializable():
    """The JSON the CLI emits must be cleanly serializable."""
    results = run_benchmark()
    slim = [{k: r[k] for k in ("id", "ref", "control", "detected", "missed")}
            for r in results]
    dumped = json.dumps(slim)
    assert "detected" in dumped
