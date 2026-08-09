"""Tests for the GitHub repo scanner + interactive wizard."""
import pytest
from pathlib import Path

from defihunter.core import github


@pytest.fixture()
def fake_repo(tmp_path: Path) -> Path:
    """A tiny local 'protocol repo' with deployment files."""
    repo = tmp_path / "fake-protocol"
    (repo / "deployments").mkdir(parents=True)
    (repo / "deployments" / "mainnet.json").write_text(
        json_dumps({
            "DelegationManager": "0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A",
            "StrategyManager": "0x858646372CC42E1A627fcE94aa7A7033e7CF075A",
        })
    )
    (repo / "README.md").write_text(
        "Deployed at 0xec53bF9167f50cDEB3Ae105f56099aaaB9061F83 (EIGEN token)\n"
        "bad example 0x1234\n"  # too short, must NOT match
    )
    (repo / "node_modules" / "junk").mkdir(parents=True)
    (repo / "node_modules" / "junk" / "x.json").write_text(
        '{"addr": "0x1111111111111111111111111111111111111111"}'
    )
    return repo


def json_dumps(obj) -> str:
    import json
    return json.dumps(obj, indent=2)


def test_is_repo_dir_and_url_helpers(fake_repo: Path):
    assert github.is_repo_dir(str(fake_repo))
    assert not github.is_repo_dir("/nonexistent/definitely/missing")
    assert github.looks_like_git_url("https://github.com/owner/repo")
    assert github.looks_like_git_url("git@github.com:owner/repo.git")
    assert not github.looks_like_git_url("sky.money")


def test_extract_addresses_skips_noise(fake_repo: Path):
    found = github.extract_addresses(fake_repo)
    # node_modules and short hex must be excluded; case normalized
    assert "0x39053d51b77dc0d36036fc1fcc8cb819df8ef37a" in found
    assert "0xec53bf9167f50cdeb3ae105f56099aaab9061f83" in found
    assert "0x1111111111111111111111111111111111111111" not in found
    assert len(found) == 3
    # sources are tracked
    assert any("deployments" in s for s in found["0x39053d51b77dc0d36036fc1fcc8cb819df8ef37a"]["sources"])


def test_extract_addresses_skips_sentinels_and_slots(tmp_path: Path):
    """ETH sentinels, EIP-1967 storage slots, and bitmask constants are not contracts."""
    repo = tmp_path / "repo"
    (repo / "src").mkdir(parents=True)
    (repo / "src" / "MockPool.sol").write_text(
        "// SparkPool v1\n"
        "address constant ETH = 0xEeeeeEeeeEeEeeEeEeEeeEEEeeeeEeeeeeeeEEeE;\n"
        "address constant NATIVE = 0xffffffffffffffffffffffffffffffffffffffff;\n"
        "bytes32 private constant IMPL = 0x360894a13ba1a3210667c828492db98dca3e2076;\n"
        "bytes32 private constant ADMIN = 0xb53127684a568b3173ae13b9f8a6016e243e63b6;\n"
        "uint256 constant MASK = 0xfffffffffffffffffffffffffffffffffff00000;\n"
        "address public pool = 0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2;\n"
        "address public zero = 0x0000000000000000000000000000000000000000;\n"
    )
    found = github.extract_addresses(repo)
    # only the real WETH address survives
    assert "0xc02aaa39b223fe8d0a0e5c4f27ead9083c756cc2" in found
    assert len(found) == 1


def test_scan_repo_no_rpc(fake_repo: Path):
    scan = github.scan_repo(str(fake_repo), rpc_url=None)
    assert scan["total_addresses"] == 3
    assert all(not c["verified"] for c in scan["contracts"].values())
    assert all(c["status"] == "unverified" for c in scan["contracts"].values())
    assert "repo_dir" in scan


def test_address_list_helpers():
    assert github.is_address_list("0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2")
    assert github.is_address_list(
        "0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2, 0xCdFdFA..."
        .replace("...", "0000000000000000000000000000000000")
    )
    assert github.is_address_list("0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2 "
                                  + "0xCdFdFA" + "0" * 34)
    assert not github.is_address_list("https://github.com/owner/repo")
    assert not github.is_address_list("0x1234")
    assert not github.is_address_list("0xzzzz9f8f72aa9304c8b593d555f12ef6589cc3a579a2")
    parsed = github.parse_address_list(
        "0x9F8f72Aa9304c8B593d555F12eF6589cC3A579A2, 0xcdFdFA000000000000000000000000000000000000"
    )
    assert parsed[0] == "0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2"  # normalized lowercase
    assert len(parsed) == 2


def test_scan_addresses_no_rpc():
    scan = github.scan_addresses("0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2", rpc_url=None)
    assert scan["total_addresses"] == 1
    assert scan["repo_dir"] == "(addresses)"
    c = scan["contracts"]["0x9f8f72aa9304c8b593d555f12ef6589cc3a579a2"]
    assert not c["verified"]
    assert c["status"] == "unverified"


def test_wizard_boots_with_preset_repo(fake_repo: Path):
    """`defihunter wizard --repo <dir> --check static` should complete non-interactively
    except for the RPC question; supply 'skip' via stdin."""
    from click.testing import CliRunner
    from defihunter.cli import cli

    runner = CliRunner()
    # input for ask_rpc: type 'skip' -> no on-chain verification
    result = runner.invoke(
        cli, ["wizard", "--repo", str(fake_repo), "--check", "static"],
        input="skip\nn\n",  # rpc=skip, then "Generate report?" = no
    )
    assert result.exit_code == 0, result.output
    assert "Found 3 candidate address" in result.output
    assert "STATIC ANALYSIS" in result.output
    assert "Hunt Complete" in result.output


def test_bare_cli_boots_wizard(fake_repo: Path):
    """Running `defihunter` with no args starts the wizard (repo prompt first)."""
    from click.testing import CliRunner
    from defihunter.cli import cli

    runner = CliRunner()
    result = runner.invoke(cli, [], input=f"{fake_repo}\nskip\n3\nall\nn\n")
    # check type "3" = both, attacks "all" -> runs the whole pipeline
    assert result.exit_code == 0, result.output
    assert "GitHub repo URL" in result.output or "Protocol source" in result.output
    assert "Hunt Complete" in result.output
