"""ABI resolution + ABI-aware fork-proof candidate selection tests (offline)."""
import json

from defihunter.core import abi as abi_util
from defihunter.core.simulator import ForkSimulator

MORPHO_ABI = [
    {"type": "function", "name": "balanceOf", "stateMutability": "view",
     "inputs": [{"name": "account", "type": "address"}],
     "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "transfer", "stateMutability": "nonpayable",
     "inputs": [{"name": "to", "type": "address"},
                {"name": "amount", "type": "uint256"}],
     "outputs": [{"name": "", "type": "bool"}]},
    {"type": "function", "name": "approve", "stateMutability": "nonpayable",
     "inputs": [{"name": "spender", "type": "address"},
                {"name": "amount", "type": "uint256"}],
     "outputs": [{"name": "", "type": "bool"}]},
]

PROXY_ABI = [
    {"type": "function", "name": "upgradeTo", "stateMutability": "nonpayable",
     "inputs": [{"name": "newImplementation", "type": "address"}],
     "outputs": []},
    {"type": "function", "name": "initialize",
     "stateMutability": "nonpayable",
     "inputs": [{"name": "owner", "type": "address"},
                {"name": "vault", "type": "address"},
                {"name": "fee", "type": "uint256"}],
     "outputs": []},
]


MINT_ABI = [
    {"type": "function", "name": "balanceOf", "stateMutability": "view",
     "inputs": [{"name": "account", "type": "address"}],
     "outputs": [{"name": "", "type": "uint256"}]},
    {"type": "function", "name": "mint", "stateMutability": "nonpayable",
     "inputs": [{"name": "to", "type": "address"},
                {"name": "amount", "type": "uint256"}],
     "outputs": [{"name": "", "type": "bool"}]},
]


def test_fetch_abi_uses_cache(monkeypatch, tmp_path):
    """Second fetch for the same address hits the disk cache, not the API."""
    calls = {"n": 0}

    class FakeResp:
        def get(self, key, default=None):
            if key == "status":
                return "1"
            if key == "result":
                return json.dumps(MORPHO_ABI)
            return default

    def fake_run(cmd):
        calls["n"] += 1
        return json.dumps({"status": "1", "result": json.dumps(MORPHO_ABI)})

    monkeypatch.setattr(abi_util, "run", fake_run)
    monkeypatch.setattr(abi_util, "CACHE_DIR", tmp_path)

    a1 = abi_util.fetch_abi("0x58d97b57bb95320f9a05dc918aef65434969c2b2",
                            api_key="K")
    a2 = abi_util.fetch_abi("0x58d97b57bb95320f9a05dc918aef65434969c2b2",
                            api_key="K")
    assert a1 == a2 == MORPHO_ABI
    assert calls["n"] == 1  # cache hit on second call


def test_fetch_abi_empty_without_key(monkeypatch, tmp_path):
    monkeypatch.setattr(abi_util, "CACHE_DIR", tmp_path)
    monkeypatch.delenv("ETHERSCAN_API_KEY", raising=False)
    assert abi_util.fetch_abi("0xabc") == []


def test_canonical_signature():
    assert abi_util.canonical({"name": "mint", "inputs": [
        {"type": "address"}, {"type": "uint256"}]}) == "mint(address,uint256)"
    assert abi_util.canonical({"name": "claim", "inputs": []}) == "claim()"


def test_find_functions_by_name_and_arity():
    assert len(abi_util.find(MORPHO_ABI, "transfer")) == 1
    assert len(abi_util.find(MORPHO_ABI, "transfer", argc=2)) == 1
    assert abi_util.find(MORPHO_ABI, "transfer", argc=1) == []


def _fork(abi_list):
    f = ForkSimulator(rpc_url="http://localhost:8545")
    f._abi = abi_list
    f.available = True  # tests don't boot anvil; simulate a live fork
    f.why_not = ""
    return f


def test_abi_candidates_mint_uses_real_signature():
    f = _fork(MORPHO_ABI)
    # no mint in MORPHO_ABI → no ABI candidates for mint
    assert f._abi_candidates("mint") == []
    assert f._abi_candidates("approve") == [
        ("approve(address,uint256)", [f.attacker, f.MAX_UINT])]


def test_merge_candidates_prefers_abi_no_dupes():
    f = _fork(MORPHO_ABI)
    f._attack_candidates = f._abi_candidates("approve")
    merged = f._merge_candidates([("approve(address,uint256)",
                                   [f.attacker, "5"])])
    # ABI version comes first, hardcoded dupe suppressed
    assert merged[0][0] == "approve(address,uint256)"
    assert merged[0][1][1] == f.MAX_UINT
    assert len([m for m in merged if m[0] == "approve(address,uint256)"]) == 1


def test_abi_candidates_initialize_uses_real_arity():
    f = _fork(PROXY_ABI)
    cands = f._abi_candidates("initialize")
    assert cands == [
        ("initialize(address,address,uint256)", [f.attacker, f.attacker, "1000000"])]


def test_abi_candidates_reentrancy_uses_one_wei():
    f = _fork([
        {"type": "function", "name": "withdraw",
         "inputs": [{"type": "uint256"}], "outputs": []},
    ])
    assert f._abi_candidates("reentrancy") == [
        ("withdraw(uint256)", ["1"])]


def test_run_verdict_unverified_without_abi(monkeypatch):
    """No ABI + all guesses revert → UNVERIFIED (can't prove either way)."""
    f = _fork([])
    monkeypatch.setattr(f, "_has_code", lambda: True)
    calls = []
    monkeypatch.setattr(f, "_fund_attacker", lambda: True)
    monkeypatch.setattr(f, "_call", lambda sel, args, extra_from=True:
                        {"ok": False, "stdout": "", "stderr": "reverted"})
    monkeypatch.setattr(f, "_send", lambda sel, args:
                        {"ok": False, "stdout": "", "stderr": "reverted"})
    res = f.run("mint", "0x1111111111111111111111111111111111111111")
    assert res["verdict"] == "UNVERIFIED"
    assert not res["success"]


def test_run_verdict_refuted_when_abi_function_reverts(monkeypatch):
    """ABI says mint exists but it reverts for an arbitrary account → REFUTED:
    provably NOT callable by anyone. This is the self-correction a real tool
    needs — the static HIGH is dropped, not left screaming."""
    f = _fork(MINT_ABI)
    monkeypatch.setattr(f, "_has_code", lambda: True)
    monkeypatch.setattr(f, "_fund_attacker", lambda: True)
    monkeypatch.setattr(f, "_call", lambda sel, args, extra_from=True:
                        {"ok": False, "stdout": "", "stderr": "reverted"})
    monkeypatch.setattr(f, "_send", lambda sel, args:
                        {"ok": False, "stdout": "", "stderr": "reverted"})
    res = f.run("mint", "0x1111111111111111111111111111111111111111",
                abi=MINT_ABI)
    assert res["verdict"] == "REFUTED"
    assert not res["success"]


def test_run_verdict_confirmed_when_abi_mint_succeeds(monkeypatch):
    """ABI mint() mines from an arbitrary account AND credits the caller →
    CONFIRMED with the before/after balance evidence. (A mined mint that
    does not change balanceOf is a no-op → REFUTED, covered separately.)"""
    f = _fork(MINT_ABI)
    monkeypatch.setattr(f, "_has_code", lambda: True)
    monkeypatch.setattr(f, "_fund_attacker", lambda: True)
    reads = {"count": 0}

    def fake_call(sel, args, extra_from=True):
        if sel == "balanceOf(address)":
            reads["count"] += 1
            return {"ok": True,
                    "stdout": "1000000" if reads["count"] > 1 else "0",
                    "stderr": ""}
        return {"ok": True, "stdout": "", "stderr": ""}

    monkeypatch.setattr(f, "_call", fake_call)
    monkeypatch.setattr(f, "_send", lambda sel, args:
                        {"ok": True, "stdout": "mined", "stderr": ""})
    res = f.run("mint", "0x1111111111111111111111111111111111111111",
                abi=MINT_ABI)
    assert res["success"] and res["verdict"] == "CONFIRMED"
    assert "1000000" in res["evidence"]


def test_run_verdict_refuted_when_abi_mint_noop(monkeypatch):
    """ABI mint() mines from an arbitrary account but balanceOf does NOT
    change (no-op / fallback hit / minting to a fixed treasury) → REFUTED."""
    f = _fork(MINT_ABI)
    monkeypatch.setattr(f, "_has_code", lambda: True)
    monkeypatch.setattr(f, "_fund_attacker", lambda: True)
    monkeypatch.setattr(f, "_call", lambda sel, args, extra_from=True:
                        {"ok": True, "stdout": "0", "stderr": ""})
    monkeypatch.setattr(f, "_send", lambda sel, args:
                        {"ok": True, "stdout": "mined", "stderr": ""})
    res = f.run("mint", "0x1111111111111111111111111111111111111111",
                abi=MINT_ABI)
    assert not res["success"]
    assert res["verdict"] == "REFUTED"


def test_run_refutes_no_code_target():
    """An address with no bytecode on the fork is provably not exploitable
    (devnet-only/placeholder) → REFUTED, never CONFIRMED."""
    f = _fork(MORPHO_ABI)
    monkeypatch = __import__("pytest").MonkeyPatch()
    monkeypatch.setattr(f, "_has_code", lambda: False)
    res = f.run("mint", "0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef",
                abi=MORPHO_ABI)
    assert res["verdict"] == "REFUTED"
    monkeypatch.undo()
