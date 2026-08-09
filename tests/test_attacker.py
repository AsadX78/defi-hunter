"""Offline tests for the one-block exploit chain replay (F3).

These never touch a mainnet RPC — they boot a blank anvil, deploy the
vulnerable SimpleVault demo and the ReentrancyAttacker, and prove the drain
with a real mined transaction.
"""
import pytest

from defihunter.core import attacker
from defihunter.core.simulator import ForkSimulator

pytestmark = pytest.mark.skipif(
    not attacker.available(),
    reason="solc/forge not available — drain replay needs a compiler")


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
                assert int(before, 16) > int(after, 16)
                break
        else:
            pytest.fail("no state-diff step in evidence")

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
