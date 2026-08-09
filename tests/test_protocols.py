"""Tests for DefiLlama protocol-name resolution (defihunter/core/protocols.py)."""
import pytest

from defihunter.core import protocols


class FakeResp:
    def __init__(self, status_code, payload=None):
        self.status_code = status_code
        self._payload = payload or {}

    def json(self):
        return self._payload


def test_resolve_single_chain_protocol(monkeypatch):
    """The `address` field is the anchor contract for single-chain protocols."""
    monkeypatch.setattr(protocols.requests, "get", lambda url, timeout=25: FakeResp(200, {
        "name": "Spark",
        "url": "https://spark.finance/",
        "address": "0xc20059e0317de91738d13af027dfc4a50781b066",
        "chains": [],
        "github": ["sparkdotfi"],
        "tokens": [],
        "currentChainTvls": {"Ethereum": 1, "Ethereum-borrowed": 1, "Gnosis": 1,
                             "staking": 1, "borrowed": 1},
    }))
    info = protocols.resolve_protocol("spark")
    assert info is not None
    assert info["name"] == "Spark"
    assert info["addresses"] == ["0xc20059e0317de91738d13af027dfc4a50781b066"]
    assert info["github_orgs"] == ["sparkdotfi"]
    # chain keys with "-" and TVL buckets are filtered out
    assert info["chains"] == ["Ethereum", "Gnosis"]


def test_resolve_collects_token_addresses(monkeypatch):
    """Multi-chain protocols expose addresses inside the tokens time-series."""
    monkeypatch.setattr(protocols.requests, "get", lambda url, timeout=25: FakeResp(200, {
        "name": "Fake",
        "address": None,
        "chains": ["ethereum"],
        "tokens": [
            {"tokens": {
                "DAI": {"0x6b175474e89094c44da98b954eedeac495271d0f": 100.0},
                "USDC": {"0xa0b86991c6218b36c1d19d4a2e9eb0ce3606eb48": 50.0},
                "amount-only": 42.0,  # non-dict entries ignored
            }},
        ],
    }))
    info = protocols.resolve_protocol("fake")
    assert len(info["addresses"]) == 2
    assert "0x6b175474e89094c44da98b954eedeac495271d0f" in info["addresses"]


def test_resolve_unknown_name_returns_none(monkeypatch):
    monkeypatch.setattr(protocols.requests, "get", lambda url, timeout=25: FakeResp(404))
    assert protocols.resolve_protocol("no-such-protocol-xyz") is None


def test_resolve_retries_on_network_error(monkeypatch):
    """Transient request errors are retried (up to attempts), then None."""
    calls = {"n": 0}

    def flaky_get(url, timeout=25):
        calls["n"] += 1
        raise protocols.requests.RequestException("boom")

    monkeypatch.setattr(protocols.requests, "get", flaky_get)
    assert protocols.resolve_protocol("flaky", attempts=2) is None
    assert calls["n"] == 2  # every attempt was made


def test_resolve_recovers_after_transient_error(monkeypatch):
    """A failure followed by a success returns the summary."""
    calls = {"n": 0}

    def flaky_get(url, timeout=25):
        calls["n"] += 1
        if calls["n"] == 1:
            raise protocols.requests.RequestException("boom")
        return FakeResp(200, {"name": "Recovered", "address": None, "tokens": []})

    monkeypatch.setattr(protocols.requests, "get", flaky_get)
    info = protocols.resolve_protocol("flaky", attempts=3)
    assert info is not None
    assert info["name"] == "Recovered"
