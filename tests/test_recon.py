"""Tests for ReconScanner verification retry logic (defihunter/core/recon.py).

The core invariant: transient RPC/DNS failures must not turn real contracts
into "no code", while a clean "0x" answer (genuinely no code) must return
immediately without burning retries or sleeping.
"""
import time

from defihunter.core.recon import ReconScanner, run

ADDR = "0xc20059e0317de91738d13af027dfc4a50781b066"
CODE = "0x608060405234801561001057600080fd5b5060"


class Scanner(ReconScanner):
    def __init__(self, rpc_url="http://rpc"):
        super().__init__(rpc_url=rpc_url)


def test_code_with_retry_success_first_try(monkeypatch):
    calls = {"n": 0}

    def fake_run(cmd, timeout=30):
        calls["n"] += 1
        return CODE

    monkeypatch.setattr("defihunter.core.recon.run", fake_run)
    assert Scanner()._code_with_retry(ADDR) == CODE
    assert calls["n"] == 1


def test_code_with_retry_no_code_stops_immediately(monkeypatch):
    calls = {"n": 0}
    sleeps = {"n": 0}

    def fake_run(cmd, timeout=30):
        calls["n"] += 1
        return "0x"

    def fake_sleep(seconds):
        sleeps["n"] += 1

    monkeypatch.setattr("defihunter.core.recon.run", fake_run)
    monkeypatch.setattr("defihunter.core.recon.time.sleep", fake_sleep)
    assert Scanner()._code_with_retry(ADDR) == ""
    assert calls["n"] == 1  # a clean "0x" must NOT retry
    assert sleeps["n"] == 0  # and must NOT backoff


def test_code_with_retry_transient_then_success(monkeypatch):
    """Empty stdout (network error) twice, then the real code."""
    calls = {"n": 0}

    def fake_run(cmd, timeout=30):
        calls["n"] += 1
        return CODE if calls["n"] == 3 else ""

    monkeypatch.setattr("defihunter.core.recon.run", fake_run)
    monkeypatch.setattr("defihunter.core.recon.time.sleep", lambda s: None)
    assert Scanner()._code_with_retry(ADDR, attempts=3) == CODE
    assert calls["n"] == 3


def test_code_with_retry_gives_up_after_attempts(monkeypatch):
    calls = {"n": 0}
    sleeps = []

    def fake_run(cmd, timeout=30):
        calls["n"] += 1
        return ""  # persistent outage

    def fake_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr("defihunter.core.recon.run", fake_run)
    monkeypatch.setattr("defihunter.core.recon.time.sleep", fake_sleep)
    assert Scanner()._code_with_retry(ADDR, attempts=3, backoff=1.0) == ""
    assert calls["n"] == 3
    assert sleeps == [1.0, 2.0]  # 1s and 2s backoff between retries
