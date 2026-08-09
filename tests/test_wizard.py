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


def test_scan_repo_no_rpc(fake_repo: Path):
    scan = github.scan_repo(str(fake_repo), rpc_url=None)
    assert scan["total_addresses"] == 3
    assert all(not c["verified"] for c in scan["contracts"].values())
    assert all(c["status"] == "unverified" for c in scan["contracts"].values())
    assert "repo_dir" in scan


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
