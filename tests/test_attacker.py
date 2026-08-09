"""Offline tests for the one-block exploit chain replay (F3).

These never touch a mainnet RPC — they boot a blank anvil, deploy the
vulnerable SimpleVault demo and the ReentrancyAttacker, and prove the drain
with a real mined transaction.
"""
import shutil

import pytest

from defihunter.core import attacker
from defihunter.core.simulator import ForkSimulator

pytestmark = pytest.mark.skipif(
    not (attacker.available()
         and shutil.which("anvil") and shutil.which("cast")),
    reason="solc + anvil/cast needed for the drain replay demo")


def _demo():
    with ForkSimulator(rpc_url=None) as fork:
        assert fork.available, fork.why_not
        return fork.offline_demo()


class TestEmbeddedContracts:
    def test_both_contracts_compile(self):
        for name in ("ReentrancyAttacker", "SimpleVault"):
            art = attacker.get_contract(name)
            assert art.get("bytecode"), f"{name} did not compile"
            assert art.get("abi"), f"{name} has no ABI"

    def test_attacker_has_fallback_not_receive(self):
        """Plain ETH transfers must land in the reentry fallback — if a
        receive() exists the victim's empty-calldata payout would NOT re-enter."""
        art = attacker.get_contract("ReentrancyAttacker")
        types = {e.get("type") for e in art["abi"]}
        assert "fallback" in types
        assert "receive" not in types

    def test_attacker_has_bounded_reentry(self):
        """Unbounded re-entry exhausts the EVM stack and reverts the whole
        tx (rolling back all evidence). The cap makes the demo reliable."""
        src = attacker.REENTRANCY_ATTACKER
        assert "MAX_REENTRIES" in src and "reentries++" in src


class TestReentrancyProof:
    def test_demo_drains_victim(self):
        res = _demo()
        assert res.get("success"), res.get("error")
        assert res["verdict"] == "CONFIRMED"
        assert res["attack"] == "reentrancy"

    def test_demo_shows_multiple_reentries(self):
        res = _demo()
        assert "re-entrant withdrawals" in res["profit"]
        n = res["evidence"].split("×")[0].split("re-entered ")[-1]
        assert int(n) > 1

    def test_demo_shows_state_diff(self):
        res = _demo()
        # "victim ETH 1000000000000000000 → 999999999999999899" — drain must
        # move ETH OUT of the victim after the seed.
        for s in res.get("steps", []):
            if "after seed → after drain" in s["step"]:
                before, after = s["value"].split(" → ")
                assert int(before) > int(after)   # cast balance = DECIMAL
                break
        else:
            pytest.fail("no state-diff step in evidence")

    def test_demo_accounting_is_exact(self):
        """The drain must be a perfect ledger: victim loss == profit swept to
        the attacker wallet, and nothing left in the attacker contract.
        cast balance returns DECIMAL — parsing it as hex inflates values
        16^18-fold and would break this (regression guard)."""
        res = _demo()
        # re-run the exact flow so we can read all three balances
        with ForkSimulator(rpc_url=None) as fork:
            import subprocess
            from defihunter.core import attacker
            rpc = fork.rpc_url_local
            SINK = "0x70997970C51812dc3A010C7d01b50e0d17dc79C8"
            vault = attacker.get_contract("SimpleVault")
            v = fork._deploy(vault["bytecode"])["address"]
            art = attacker.get_contract("ReentrancyAttacker")
            payload = (fork._sig_selector("withdraw(uint256)")
                       + fork._abi_encode(["uint256"], ["1"])[2:])
            a = fork._deploy(art["bytecode"],
                             ["address", "address", "bytes"],
                             [v, SINK, payload])["address"]

            def run(*args):
                pr = subprocess.run(
                    ["cast", *args, "--rpc-url", rpc],
                    capture_output=True, text=True, timeout=90)
                return pr.returncode, pr.stdout.strip()

            def bal(ad):
                return int(run("balance", ad)[1], 10)

            run("send", "--unlocked", a, "depositIntoVictim()",
                "--from", fork.attacker, "--value", "1ether")
            seeded = bal(v)
            s0 = bal(SINK)
            run("send", "--unlocked", a, "go()",
                "--from", fork.attacker, "--gas-limit", "30000000")
            n = int(run("call", a, "reentries()")[1], 16)
            victim_loss = seeded - bal(v)
            sink_gain = bal(SINK) - s0
            assert victim_loss == n + 1  # reentries + the initial payout call
            assert sink_gain == victim_loss  # every wei lands in the wallet
            assert bal(a) == 0  # attacker contract fully swept

    def test_prove_reentrancy_refutes_empty_target(self):
        """An address with no bytecode must NOT be reported exploitable."""
        with ForkSimulator(rpc_url=None) as fork:
            res = fork.prove_reentrancy(
                "0x0000000000000000000000000000000000000001",
                "withdraw(uint256)", "1")
        assert res["verdict"] == "REFUTED"
        assert not res.get("success")


class TestDeployHelper:
    def test_deploy_with_constructor_args(self):
        with ForkSimulator(rpc_url=None) as fork:
            art = attacker.get_contract("SimpleVault")
            dep = fork._deploy(art["bytecode"])
            assert dep.get("ok"), dep.get("stderr")
            assert dep["address"].startswith("0x")
