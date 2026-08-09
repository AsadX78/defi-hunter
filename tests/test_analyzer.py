"""Tests for the source-level static analyzer (analyze_repo_dir) and the
anvil fork verifier (ForkSimulator)."""
import textwrap

import pytest

from defihunter import ui
from defihunter.core.analyzer import (
    SEVERITY_ORDER,
    _iter_sol_files,
    analyze_file,
    analyze_repo_dir,
)
from defihunter.core.simulator import ForkSimulator


def _write(tmp_path, name, content):
    p = tmp_path / name
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(textwrap.dedent(content))
    return p


class TestAnalyzeFile:
    def test_selfdestruct_critical(self, tmp_path):
        p = _write(tmp_path, "Kill.sol", """
            contract Kill {
                function die() external { selfdestruct(payable(msg.sender)); }
            }
        """)
        f = analyze_file(p)
        assert any(x["severity"] == "CRITICAL" and "selfdestruct" in x["title"]
                   for x in f)

    def test_tx_origin_high(self, tmp_path):
        p = _write(tmp_path, "Auth.sol", """
            contract Auth {
                function guarded() external {
                    require(tx.origin == owner);
                }
            }
        """)
        f = analyze_file(p)
        assert any(x["severity"] == "HIGH" and "tx.origin" in x["title"] for x in f)

    def test_delegatecall_high(self, tmp_path):
        p = _write(tmp_path, "Proxy.sol", """
            contract Proxy {
                function exec(address t, bytes memory d) external { t.delegatecall(d); }
            }
        """)
        f = analyze_file(p)
        assert any(x["severity"] == "HIGH" and "delegatecall" in x["title"] for x in f)

    def test_unguarded_mint_high(self, tmp_path):
        p = _write(tmp_path, "Token.sol", """
            contract Token {
                function mint(address to, uint256 amount) external { _mint(to, amount); }
            }
        """)
        f = analyze_file(p)
        assert any(x["severity"] == "HIGH" and x["attack"] == "mint" for x in f)

    def test_guarded_mint_not_flagged(self, tmp_path):
        p = _write(tmp_path, "Token.sol", """
            contract Token {
                function mint(address to, uint256 amount) external onlyMinter {
                    _mint(to, amount);
                }
                modifier onlyMinter() { require(msg.sender == minter); _; }
            }
        """)
        f = analyze_file(p)
        assert not any(x["attack"] == "mint" for x in f)

    def test_initialize_attack_tag(self, tmp_path):
        p = _write(tmp_path, "Impl.sol", """
            contract Impl {
                function initialize(address owner_) external {
                    owner = owner_;
                }
            }
        """)
        f = analyze_file(p)
        assert any(x["attack"] == "initialize" for x in f)

    def test_line_numbers_present(self, tmp_path):
        p = _write(tmp_path, "Mix.sol", """
            contract Mix {
                function a() external { }
                function b() external { selfdestruct(payable(msg.sender)); }
            }
        """)
        f = analyze_file(p)
        hit = next(x for x in f if "selfdestruct" in x["title"])
        assert hit["line"] == 4  # the selfdestruct line
        assert "Mix.sol:4" in hit["endpoint"]

    def test_hardcoded_secret(self, tmp_path):
        p = _write(tmp_path, "Deploy.sol", """
            contract Deploy {
                bytes32 constant secret = 0xdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef;
            }
        """)
        f = analyze_file(p)
        assert any(x["severity"] == "HIGH" and "secret" in x["title"].lower() for x in f)

    def test_padded_selector_is_not_secret(self, tmp_path):
        """Yul assembly mstore(function-selector + 56 zero-bytes) is a PUBLIC
        ERC20 selector (0x23b872dd = transferFrom), not a private key. This
        false positive was found on Uniswap's audited Permit2."""
        p = _write(tmp_path, "Sel.sol", """
            contract Sel {
                function sel(address to, uint256 amount) public pure {
                    assembly {
                        let fmp := mload(0x40)
                        mstore(fmp, 0x23b872dd00000000000000000000000000000000000000000000000000000000)
                        mstore(add(fmp, 4), to)
                        mstore(add(fmp, 36), amount)
                    }
                }
            }
        """)
        f = analyze_file(p)
        assert not any("64-hex" in x["title"] for x in f)
        assert not any("private key" in x["title"].lower() for x in f)

    def test_erc1967_slots_are_not_secret(self, tmp_path):
        """The EIP-1967 implementation/admin/beacon storage slots are public,
        documented constants — found in EVERY proxy. Not leaked keys (MORPHO
        token regression)."""
        p = _write(tmp_path, "Proxy.sol", """
            contract Proxy {
                bytes32 internal constant IMPLEMENTATION_SLOT =
                    0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc;
                bytes32 internal constant ADMIN_SLOT =
                    0xb53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103;
                bytes32 internal constant BEACON_SLOT =
                    0xa3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50;
            }
        """)
        f = analyze_file(p)
        assert not any("64-hex" in x["title"] for x in f)
        assert not any("private key" in x["title"].lower() for x in f)

    def test_bitmask_is_not_secret(self, tmp_path):
        """0x7fff…ff UPPER_BIT_MASK (found in Uniswap Permit2) is a bitmask
        constant — 63 f's is not a private key (keys are uniformly random)."""
        p = _write(tmp_path, "Mask.sol", """
            contract Mask {
                bytes32 constant UPPER_BIT_MASK =
                    (0x7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff);
            }
        """)
        f = analyze_file(p)
        assert not any("64-hex" in x["title"] for x in f)
        assert not any("private key" in x["title"].lower() for x in f)

    def test_spot_oracle_medium(self, tmp_path):
        p = _write(tmp_path, "Feed.sol", """
            contract Feed {
                function price() external view returns (uint256) {
                    (uint112 r0, uint112 r1,) = pair.getReserves();
                    return r1 * 1e18 / r0;
                }
            }
        """)
        f = analyze_file(p)
        assert any(x["severity"] == "MEDIUM" and x["attack"] == "oracle" for x in f)


class TestAnalyzeRepoDir:
    def test_skips_lib_and_tests(self, tmp_path):
        _write(tmp_path, "src/Vault.sol", "contract Vault { function die() external { selfdestruct(payable(msg.sender)); } }\n")
        _write(tmp_path, "lib/openzeppelin/Utils.sol", "contract Utils {}\n")
        _write(tmp_path, "test/Vault.t.sol", "contract VaultTest {}\n")
        _write(tmp_path, "script/Deploy.s.sol", "contract DeployScript {}\n")

        files = _iter_sol_files(tmp_path)
        names = [str(f.relative_to(tmp_path)) for f in files]
        assert names == ["src/Vault.sol"], names

        findings = analyze_repo_dir(str(tmp_path), repo_label="acme")
        assert findings
        # Every finding carries repo-relative path + repo label
        for f in findings:
            assert not f["file"].startswith("/")
            assert f["repo"] == "acme"
            assert isinstance(f["line"], int)

    def test_severity_sorting(self, tmp_path):
        _write(tmp_path, "src/Both.sol", """
            contract Both {
                function a() external { require(tx.origin == owner); }
                function b() external { selfdestruct(payable(msg.sender)); }
            }
        """)
        findings = analyze_repo_dir(str(tmp_path))
        sevs = [SEVERITY_ORDER[f["severity"]] for f in findings]
        assert sevs == sorted(sevs)

    def test_missing_dir_returns_empty(self, tmp_path):
        assert analyze_repo_dir(str(tmp_path / "nope")) == []


class TestForkSimulator:
    def test_missing_binaries_degrades_gracefully(self, monkeypatch):
        monkeypatch.setattr(ForkSimulator, "_has_tool", lambda self, name: False)
        with ForkSimulator(rpc_url="https://example.com/rpc") as fork:
            assert not fork.available
            assert "foundry" in fork.why_not
            res = fork.run("mint", "0x1234")
            assert not res["success"]

    def test_blank_anvil_offline_chain(self, monkeypatch):
        """rpc_url=None now boots a BLANK anvil chain (offline self-test /
        drain demo). It must come up available without any mainnet RPC."""
        import shutil
        if not shutil.which("anvil") or not shutil.which("cast"):
            pytest.skip("anvil/cast not installed on this runner")
        monkeypatch.setattr(ForkSimulator, "_has_tool", lambda self, name: True)
        with ForkSimulator(rpc_url=None) as fork:
            assert fork.available
            assert not fork.why_not

    def test_free_port(self):
        port = ForkSimulator._free_port()
        assert 0 < port < 65536

    def test_run_rejects_no_code_target(self, monkeypatch):
        """A tx to an address with no bytecode mines vacuously — never proof."""
        fork = ForkSimulator(rpc_url="http://127.0.0.1:8545")
        fork.available = True  # no real anvil needed; _has_code is stubbed
        target = "0xdead00000000000000000000000000000000dead"
        monkeypatch.setattr(fork, "_has_code", lambda: False)
        res = fork.run("mint", target)
        assert not res["success"]
        assert "no bytecode" in res["evidence"]

    def _ready_fork(self, monkeypatch, target):
        """ForkSimulator that is 'live' but with all cast calls stubbed."""
        fork = ForkSimulator(rpc_url="http://127.0.0.1:8545")
        fork.available = True
        monkeypatch.setattr(fork, "_has_code", lambda: True)
        return fork

    def _fake_send(self, ok_for=()):
        calls = []

        def send(selector, args):
            calls.append(selector)
            return {"ok": selector in ok_for, "stdout": "0x",
                    "stderr": ""}
        return calls, send

    def test_reentrancy_proof_hits_payout_sink(self, monkeypatch):
        from defihunter.core.simulator import ForkSimulator
        fork = self._ready_fork(monkeypatch, "0x1111")
        calls, send = self._fake_send(ok_for={"withdraw()"})
        monkeypatch.setattr(fork, "_send", send)
        res = fork.run("reentrancy", "0x1111")
        assert res["success"]
        assert "withdraw()" in res["evidence"]
        assert any("withdraw(uint256)" in c for c in calls)

    def test_reentrancy_proof_no_sink(self, monkeypatch):
        from defihunter.core.simulator import ForkSimulator
        fork = self._ready_fork(monkeypatch, "0x1111")
        calls, send = self._fake_send()  # nothing mines
        monkeypatch.setattr(fork, "_send", send)
        res = fork.run("reentrancy", "0x1111")
        assert not res["success"]
        assert "No permissionless payout sink" in res["evidence"]

    def test_arbitrarycall_proof_forwarder(self, monkeypatch):
        from defihunter.core.simulator import ForkSimulator
        fork = self._ready_fork(monkeypatch, "0x1111")
        calls = []

        def call(selector, args, extra_from=True):
            calls.append(selector)
            return {"ok": selector == "execute(address,bytes)",
                    "stdout": "0x", "stderr": ""}
        monkeypatch.setattr(fork, "_call", call)
        res = fork.run("arbitrarycall", "0x1111")
        assert res["success"]
        assert "execute(address,bytes)" in res["evidence"]
        assert "attacker" in res["profit"].lower()

    def test_approve_proof_grants_allowance(self, monkeypatch):
        from defihunter.core.simulator import ForkSimulator
        fork = self._ready_fork(monkeypatch, "0x1111")
        calls, send = self._fake_send(ok_for={"approve(address,uint256)"})
        monkeypatch.setattr(fork, "_send", send)
        monkeypatch.setattr(
            fork, "_call",
            lambda sel, args, extra_from=True:
                {"ok": True, "stdout": "115792089237316195423570985008687907853269984665640564039457584007913129639935",
                 "stderr": ""})
        res = fork.run("approve", "0x1111")
        assert res["success"]
        assert "allowance(target→attacker) > 0" in res["evidence"]

    def test_selfdestruct_proof_transfers_balance(self, monkeypatch):
        from defihunter.core.simulator import ForkSimulator
        fork = self._ready_fork(monkeypatch, "0x1111")
        calls, send = self._fake_send(ok_for={"kill()"})
        monkeypatch.setattr(fork, "_send", send)
        code_after = [True]

        def has_code():
            return code_after[0]
        monkeypatch.setattr(fork, "_has_code", has_code)
        monkeypatch.setattr(fork, "_balance", lambda addr: "500000000000000000")
        res = fork.run("selfdestruct", "0x1111")
        assert res["success"]
        assert "kill() mined" in res["evidence"]
        assert "→" in res["evidence"]  # state-diff before → after

    def test_mint_evidence_has_state_diff(self, monkeypatch):
        from defihunter.core.simulator import ForkSimulator
        fork = self._ready_fork(monkeypatch, "0x1111")
        monkeypatch.setattr(fork, "_send",
                            lambda sel, args: {"ok": True, "stdout": "0x", "stderr": ""})
        monkeypatch.setattr(fork, "_call",
                            lambda sel, args, extra_from=True:
                                {"ok": True, "stdout": "1000000000000000000000000",
                                 "stderr": ""})
        res = fork.run("mint", "0x1111")
        assert res["success"]
        assert "→" in res["evidence"]  # balance before → after


def _render(renderable) -> str:
    """Render any rich renderable to plain text for assertions."""
    from rich.console import Console
    from defihunter import ui
    console = Console(width=120, force_terminal=False, color_system=None,
                      theme=ui.THEME)
    with console.capture() as cap:
        console.print(renderable)
    return cap.get()


class TestVisualToolkit:
    """The world-record visual toolkit — pure rendering, no console needed."""

    def test_threat_level_mapping(self):
        from defihunter.ui import threat_level
        assert threat_level([]) == "CLEAN"
        assert threat_level([{"severity": "CRITICAL"}]) == "CRITICAL"
        assert threat_level([{"severity": "HIGH"}]) == "HIGH"
        assert threat_level([{"severity": "LOW"}]) == "LOW"
        assert threat_level([{"severity": "MEDIUM"}]) == "MODERATE"

    def test_threat_banner_renders(self):
        from defihunter.ui import threat_banner
        text = _render(threat_banner("CRITICAL", extra="boom"))
        assert "CRITICAL" in text
        assert "boom" in text

    def test_attack_surface_gauge_scores(self):
        from defihunter.ui import attack_surface_gauge
        p = attack_surface_gauge([{"severity": "CRITICAL"},
                                  {"severity": "HIGH"}, {"severity": "HIGH"}])
        text = _render(p)
        import re as _re
        assert _re.search(r"\d\.\d/10", text)  # a numeric score is rendered

    def test_severity_chart_counts(self):
        from defihunter.ui import severity_chart
        p = severity_chart([{"severity": "CRITICAL"}, {"severity": "HIGH"},
                            {"severity": "HIGH"}, {"severity": "LOW"}])
        text = _render(p)
        assert "CRITICAL" in text
        assert "2" in text

    def test_attack_flow_statuses(self):
        from defihunter.ui import attack_flow
        findings = [{"severity": "HIGH", "title": "mint() no guard",
                     "file": "src/A.sol", "line": 5, "attack": "mint"},
                    {"severity": "HIGH", "title": "tx.origin",
                     "file": "src/B.sol", "line": 3, "attack": "admin"}]
        forks = [{"success": True, "attack": "mint", "target": "0xabc",
                  "source_finding": {"file": "src/A.sol", "line": 5}}]
        panel = attack_flow(findings, forks)
        text = _render(panel)
        assert "EXPLOITABLE" in text   # mint fork-proven
        assert "POSSIBLE" in text      # admin static-only

    def test_hunt_complete_smoke(self, capsys):
        from defihunter.ui import hunt_complete
        hunt_complete([("repo", "x"), ("findings", "2")], level="HIGH")
        out = capsys.readouterr().out
        assert "HUNT COMPLETE" in out
        assert "THREAT LEVEL: HIGH" in out

    def test_mega_banner_smoke(self, capsys):
        from defihunter.ui import mega_banner
        mega_banner("9.9.9")
        out = capsys.readouterr().out
        assert "WORLD RECORD" in out and "fork-proves" in out
        assert "9.9.9" in out


class TestForkProofHelpers:
    """State-changing proof helpers — mocked cast, no real fork needed."""

    def test_fund_attacker_success(self, monkeypatch):
        import subprocess
        from defihunter.core.simulator import ForkSimulator

        def fake_run(cmd, capture_output, text, timeout):
            class R:
                returncode = 0
                stdout = "null\n"
                stderr = ""
            return R()

        monkeypatch.setattr(subprocess, "run", fake_run)
        fork = ForkSimulator(rpc_url="http://127.0.0.1:8545")
        assert fork._fund_attacker()

    def test_fund_attacker_failure(self, monkeypatch):
        import subprocess
        from defihunter.core.simulator import ForkSimulator

        def fake_run(cmd, capture_output, text, timeout):
            class R:
                returncode = 1
                stdout = ""
                stderr = "boom"
            return R()

        monkeypatch.setattr(subprocess, "run", fake_run)
        fork = ForkSimulator(rpc_url="http://127.0.0.1:8545")
        assert not fork._fund_attacker()


class TestIntro:
    """Boot intro: animation on terminals, instant static elsewhere."""

    @staticmethod
    def _fake_console(tty: bool):
        """Return (console, file) — output lands in the fake file, not stdout."""
        import io
        from rich.console import Console

        class _TTY(io.StringIO):
            def isatty(self):
                return tty
            def fileno(self):
                raise io.UnsupportedOperation("no fileno")

        f = _TTY()
        console = Console(file=f, highlight=False, theme=ui.THEME,
                          color_system=None)
        return console, f

    def test_static_when_not_terminal(self, monkeypatch):
        console, f = self._fake_console(tty=False)
        monkeypatch.setattr(ui, "console", console)
        ui.intro("1.2.3")
        out = f.getvalue()
        assert "WORLD RECORD" in out and "fork-proves" in out
        assert "1.2.3" in out

    def test_static_when_env_skip(self, monkeypatch):
        console, f = self._fake_console(tty=True)
        monkeypatch.setattr(ui, "console", console)
        monkeypatch.setenv("DEFIHUNTER_NO_INTRO", "1")
        ui.intro("4.5.6")
        out = f.getvalue()
        assert "WORLD RECORD" in out and "fork-proves" in out
        assert "4.5.6" in out

    def test_animation_runs_to_completion(self, monkeypatch):
        """Real animation path on a fake terminal. The clock is faked so the
        ~1.5s of animation completes instantly; must end with the boxed
        banner and never raise."""
        import time as _time
        console, f = self._fake_console(tty=True)
        monkeypatch.setattr(ui, "console", console)
        monkeypatch.delenv("DEFIHUNTER_NO_INTRO", raising=False)

        class FakeClock:
            def __init__(self):
                self.now = 0.0
            def __call__(self):
                return self.now

        clock = FakeClock()
        monkeypatch.setattr(_time, "time", clock)
        monkeypatch.setattr(_time, "sleep",
                            lambda s: clock.__setattr__("now", clock.now + s))

        ui.intro("7.8.9")
        out = f.getvalue()
        assert "WORLD RECORD" in out and "fork-proves" in out
        assert "7.8.9" in out



class TestInconclusiveVerdict:
    """Never claim CLEAN on data that was never analyzed."""

    def test_threat_level_inconclusive_when_not_analyzed(self):
        assert ui.threat_level([], analyzed=False) == "INCONCLUSIVE"
        assert ui.threat_level([], analyzed=True) == "CLEAN"
        assert ui.threat_level([{"severity": "LOW"}], analyzed=False) == "LOW"

    def test_gauge_inconclusive_renders_na(self):
        text = _render(ui.attack_surface_gauge([], analyzed=False))
        assert "N/A" in text
        assert "skipped" in text
        assert "0.0/10" not in text  # no fake CLEAN score

    def test_chart_inconclusive_renders_skipped(self):
        text = _render(ui.severity_chart([], analyzed=False))
        assert "skipped" in text
        assert "clean repo" not in text

    def test_threat_banner_inconclusive(self):
        text = _render(ui.threat_banner("INCONCLUSIVE"))
        assert "INCONCLUSIVE" in text

    def test_verdict_panels_hug_width(self):
        """Verdict panels must not balloon to terminal width (expand=False)."""
        from rich.console import Console
        console = Console(width=160, force_terminal=False, color_system=None,
                          theme=ui.THEME)
        for panel in (ui.threat_banner("HIGH"),
                      ui.attack_surface_gauge([{"severity": "HIGH"}]),
                      ui.severity_chart([{"severity": "HIGH"}])):
            with console.capture() as cap:
                console.print(panel)
            # rendered lines must be well under the 160-col console width
            assert max(len(line) for line in cap.get().splitlines()) < 120


class TestInterfaceSkip:
    """Interfaces are declarations only — no bodies to attack, no findings."""

    def test_interface_dir_skipped(self, tmp_path):
        from pathlib import Path as P
        d = tmp_path / "contracts" / "interfaces"
        d.mkdir(parents=True)
        p = d / "IAVSDirectory.sol"
        p.write_text("""// SPDX-License-Identifier: MIT
pragma solidity ^0.8.12;
interface IAVSDirectory {
    function initialize(address initialOwner) external;
    function mint(address to, uint256 amount) external;
}
""")
        assert analyze_file(p) == []

    def test_capital_i_filename_skipped(self, tmp_path):
        p = _write(tmp_path, "IStrategyManager.sol", """
            interface IStrategyManager {
                function initialize(address owner) external;
                function mint(address to, uint256 amount) external;
            }
        """)
        assert analyze_file(p) == []

    def test_impl_file_still_flagged(self, tmp_path):
        p = _write(tmp_path, "StrategyManager.sol", """
            contract StrategyManager {
                function initialize(address owner) external {
                    owner_ = owner;
                }
                function mint(address to, uint256 amount) external { _mint(to, amount); }
            }
        """)
        f = analyze_file(p)
        assert any(x["attack"] == "mint" for x in f)
        assert any(x["attack"] == "initialize" for x in f)

    def test_interface_helper(self):
        from defihunter.core.analyzer import _is_interface
        assert _is_interface("/tmp/x/src/contracts/interfaces/IStrategyManager.sol")
        assert _is_interface("/tmp/x/IEigen.sol")
        assert _is_interface("/tmp/x/IERC20.sol")
        assert not _is_interface("/tmp/x/StrategyManager.sol")
        assert not _is_interface("/tmp/x/Index.sol")      # I + lowercase is a name, not interface
        assert not _is_interface("/tmp/x/Inflation.sol")


class TestContractAnalyzerUnified:
    """Address scans now run the SAME line-aware engine as repo scans."""

    def _analyzer(self, monkeypatch, source):
        from defihunter.core.analyzer import ContractAnalyzer
        a = ContractAnalyzer(rpc_url="http://localhost:8545")
        monkeypatch.setattr(a, "_get_source", lambda addr: source)
        return a.analyze("0x58d97b57bb95320f9a05dc918aef65434969c2b2")

    def test_findings_carry_address_and_attack(self, monkeypatch):
        findings = self._analyzer(monkeypatch, """
            contract Token {
                function mint(address to, uint256 amount) public {
                    balances[to] += amount;
                }
            }
        """)
        assert findings
        for f in findings:
            assert f.get("address") == "0x58d97b57bb95320f9a05dc918aef65434969c2b2"
        assert any(f.get("attack") == "mint" for f in findings)

    def test_erc20_transfer_is_not_reentrancy(self, monkeypatch):
        """The old crude rule flagged ANY `.transfer(` as CRITICAL — an ERC20's
        own transfer() would blow up. That noise is gone."""
        findings = self._analyzer(monkeypatch, """
            contract Token {
                mapping(address => uint256) public balanceOf;
                function transfer(address to, uint256 amount) public returns (bool) {
                    balanceOf[msg.sender] -= amount;
                    balanceOf[to] += amount;
                    return true;
                }
            }
        """)
        assert not any(f.get("severity") == "CRITICAL" for f in findings)
        assert not any(f.get("attack") == "reentrancy" for f in findings)

    def test_eth_call_still_caught(self, monkeypatch):
        findings = self._analyzer(monkeypatch, """
            contract Vault {
                mapping(address => uint256) public balances;
                function withdraw(uint256 amt) public {
                    (bool ok, ) = msg.sender.call{value: amt}("");
                    require(ok);
                    balances[msg.sender] -= amt;
                }
            }
        """)
        assert any(f.get("attack") == "reentrancy" for f in findings)

    def test_payable_transfer_still_caught(self, monkeypatch):
        findings = self._analyzer(monkeypatch, """
            contract Bank {
                address public owner;
                function sweep() public {
                    payable(owner).transfer(address(this).balance);
                }
            }
        """)
        assert any(f.get("attack") == "reentrancy" for f in findings)

    def test_proxy_note_is_low_and_forkable(self, monkeypatch):
        findings = self._analyzer(monkeypatch, """
            contract Proxy {
                address public implementation;
                fallback() external { implementation.delegatecall(msg.data); }
            }
        """)
        assert any(f.get("severity") == "LOW"
                   and f.get("attack") == "delegatecall"
                   and "proxy" in f.get("title", "").lower()
                   for f in findings)

    def test_json_standard_input_parsed(self, monkeypatch):
        from defihunter.core.analyzer import _source_texts
        blob = ('{"language":"Solidity","sources":{"A.sol":{"content":'
                '"contract A { function kill() public { selfdestruct(payable(msg.sender)); } }"},'
                '"B.sol":{"content":"contract B { function mint(address to) public {} }"}}}')
        texts = _source_texts(blob)
        assert len(texts) == 2
        assert "kill()" in texts[0]

    def test_json_double_braced_wrapper_parsed(self, monkeypatch):
        """Real Etherscan standard-json blobs come wrapped in an EXTRA pair
        of braces ({{...}}). json.loads fails on them — the unified parser
        must unwrap before parsing, or address scans silently return no
        findings (the MORPHO token bug)."""
        from defihunter.core.analyzer import _source_texts
        blob = ('{{"language":"Solidity","sources":{"Morpho.sol":{"content":'
                '"contract Morpho { function kill() public { selfdestruct(payable(msg.sender)); } }"},'
                '"Token.sol":{"content":"contract Token { function mint(address to) public {} }"}}}}')
        texts = _source_texts(blob)
        assert len(texts) == 2
        assert "selfdestruct" in texts[0]
        assert "Token" in texts[1]

    def test_json_wrapper_unwrapped_findings(self, monkeypatch):
        """End-to-end: a double-braced blob must produce real findings."""
        findings = self._analyzer(monkeypatch, (
            '{{"language":"Solidity","sources":{"Morpho.sol":{"content":'
            '"contract Morpho { function kill() public { selfdestruct(payable(msg.sender)); } }"}}}}'
        ))
        assert any(f.get("severity") == "CRITICAL"
                   and "selfdestruct" in f.get("title", "")
                   for f in findings)

    def test_no_source_returns_empty(self, monkeypatch):
        from defihunter.core.analyzer import ContractAnalyzer
        a = ContractAnalyzer(rpc_url="http://localhost:8545")
        monkeypatch.setattr(a, "_get_source", lambda addr: "")
        assert a.analyze("0xabc") == []


class TestForkVerifyAddressFindings:
    """Address-scan findings (f['address']) skip repo resolution entirely."""

    def test_resolves_directly_via_address(self, tmp_path, monkeypatch):
        from defihunter import wizard
        finding = {
            "severity": "HIGH", "title": "unguarded mint",
            "file": "0x58d97b57bb95320f9a05dc918aef65434969c2b2",
            "line": 3, "attack": "mint",
            "address": "0x58d97b57bb95320f9a05dc918aef65434969c2b2",
        }
        called = []
        class FakeFork:
            available = True
            rpc_url = "http://127.0.0.1:8545"
            why_not = ""
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def run(self, attack, target, source_finding=None, abi=None):
                called.append((attack, target))
                return {"success": True, "attack": attack, "target": target,
                        "verdict": "CONFIRMED",
                        "source_finding": source_finding}
        monkeypatch.setattr(wizard, "ForkSimulator", lambda rpc_url=None: FakeFork())
        monkeypatch.setattr(wizard.abi_util, "fetch_abi", lambda addr: [])
        from rich.console import Console
        monkeypatch.setattr(wizard.ui, "console",
                            Console(file=__import__("io").StringIO(),
                                    force_terminal=False, color_system=None,
                                    width=120, theme=wizard.ui.THEME))
        results = wizard._run_fork_verify([finding], {}, "http://rpc")
        assert called == [("mint", "0x58d97b57bb95320f9a05dc918aef65434969c2b2")]
        assert results[0]["success"]
