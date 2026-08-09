"""Tests for the source-level static analyzer (analyze_repo_dir) and the
anvil fork verifier (ForkSimulator)."""
import textwrap

import pytest

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

    def test_missing_rpc_degrades_gracefully(self, monkeypatch):
        monkeypatch.setattr(ForkSimulator, "_has_tool", lambda self, name: True)
        with ForkSimulator(rpc_url=None) as fork:
            assert not fork.available
            assert "RPC" in fork.why_not

    def test_free_port(self):
        port = ForkSimulator._free_port()
        assert 0 < port < 65536
