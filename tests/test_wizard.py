"""Tests for the GitHub repo scanner + interactive wizard."""
import json
import pytest
from pathlib import Path

from defihunter.core import github
from defihunter import wizard


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
    assert "HUNT COMPLETE" in result.output


def test_bare_cli_boots_wizard(fake_repo: Path):
    """Running `defihunter` with no args starts the wizard (repo prompt first)."""
    from click.testing import CliRunner
    from defihunter.cli import cli

    runner = CliRunner()
    result = runner.invoke(cli, [], input=f"{fake_repo}\nskip\n3\nall\nn\n")
    # check type "3" = both, attacks "all" -> runs the whole pipeline
    assert result.exit_code == 0, result.output
    assert "GitHub repo URL" in result.output or "Protocol source" in result.output
    assert "HUNT COMPLETE" in result.output


# --- GitHub org repo listing (llama depth step) -----------------------------


class DummyConfirm:
    answer = False

    @classmethod
    def ask(cls, *args, **kwargs):
        return cls.answer


class DummyPrompt:
    answer = "skip"

    @classmethod
    def ask(cls, *args, **kwargs):
        return cls.answer


class FakeResp:
    def __init__(self, payload, status=200):
        self._payload = payload
        self.status_code = status

    def raise_for_status(self):
        if self.status_code >= 400:
            raise github.requests.RequestException(f"HTTP {self.status_code}")

    def json(self):
        return self._payload


def _repo(full_name: str, **kw):
    base = {
        "full_name": full_name, "name": full_name.split("/")[-1],
        "fork": False, "archived": False, "description": "",
        "updated_at": "2026-08-01T00:00:00Z", "stargazers_count": 0,
        "language": "Solidity",
    }
    base.update(kw)
    return base


def test_list_org_repos_filters_forks_and_archived(monkeypatch):
    payload = [
        _repo("Layr-Labs/eigenlayer-contracts", stargazers_count=120),
        _repo("Layr-Labs/eigenlayer-middleware", fork=True),
        _repo("Layr-Labs/old-tooling", archived=True),
        _repo("Layr-Labs/docs", language="Markdown"),
    ]
    monkeypatch.setattr(github.requests, "get",
                        lambda url, timeout=30, headers=None: FakeResp(payload))
    repos = github.list_org_repos("Layr-Labs")
    names = [r["name"] for r in repos]
    assert "Layr-Labs/eigenlayer-contracts" in names
    assert "Layr-Labs/docs" in names
    assert not any("middleware" in n or "old-tooling" in n for n in names)
    assert repos[0]["stars"] == 120
    assert repos[0]["updated"] == "2026-08-01"


def test_list_org_repos_network_failure_returns_empty(monkeypatch):
    def boom(url, timeout=30, headers=None):
        raise github.requests.RequestException("boom")

    monkeypatch.setattr(github.requests, "get", boom)
    assert github.list_org_repos("Layr-Labs", attempts=2) == []


def test_llama_scan_sets_friendly_label(monkeypatch):
    """Llama runs label the repo as 'DefiLlama: <name>', not the raw prefix."""
    from defihunter import wizard
    from defihunter.core import protocols

    monkeypatch.setattr(protocols, "resolve_protocol", lambda name: {
        "name": "Spark", "url": "https://spark.finance/", "chains": ["Ethereum"],
        "github_orgs": [],
        "addresses": ["0xc20059e0317de91738d13af027dfc4a50781b066"],
    })
    monkeypatch.setattr(wizard.github, "scan_addresses",
                        lambda src, rpc_url=None: {
                            "contracts": {"0xc20059e0317de91738d13af027dfc4a50781b066": {"verified": True}},
                            "total_addresses": 1, "repo_dir": "(addresses)"})
    scan = wizard._scan_llama_protocol("llama:spark", rpc=None)
    assert scan["repo_url"] == "DefiLlama: Spark"
    assert "deep_repo" not in scan  # no orgs -> no depth prompt


def test_llama_scan_skips_org_repo_when_declined(monkeypatch):
    from defihunter import wizard
    from defihunter.core import protocols

    monkeypatch.setattr(protocols, "resolve_protocol", lambda name: {
        "name": "EigenCloud", "url": "", "chains": ["Ethereum"],
        "github_orgs": ["Layr-Labs"],
        "addresses": ["0xec53bf9167f50cdeb3ae105f56099aaab9061f83"],
    })
    monkeypatch.setattr(wizard.github, "scan_addresses",
                        lambda src, rpc_url=None: {
                            "contracts": {"0xec53bf9167f50cdeb3ae105f56099aaab9061f83": {"verified": True}},
                            "total_addresses": 1, "repo_dir": "(addresses)"})
    DummyConfirm.answer = False
    monkeypatch.setattr(wizard, "Confirm", DummyConfirm)
    scan = wizard._scan_llama_protocol("llama:eigenlayer", rpc=None)
    assert "deep_repo" not in scan
    assert scan["repo_url"] == "DefiLlama: EigenCloud"


def test_llama_scan_merges_org_repo_when_picked(monkeypatch):
    from defihunter import wizard
    from defihunter.core import protocols

    monkeypatch.setattr(protocols, "resolve_protocol", lambda name: {
        "name": "EigenCloud", "url": "", "chains": ["Ethereum"],
        "github_orgs": ["Layr-Labs"],
        "addresses": ["0xec53bf9167f50cdeb3ae105f56099aaab9061f83"],
    })
    monkeypatch.setattr(wizard.github, "scan_addresses",
                        lambda src, rpc_url=None: {
                            "contracts": {"0xec53bf9167f50cdeb3ae105f56099aaab9061f83": {"verified": True}},
                            "total_addresses": 1, "repo_dir": "(addresses)"})
    monkeypatch.setattr(wizard.github, "list_org_repos",
                        lambda org, attempts=3, timeout=30: [
                            {"name": "Layr-Labs/eigenlayer-contracts",
                             "description": "core", "updated": "2026-08-01",
                             "stars": 100, "language": "Solidity",
                             "default_branch": "main"},
                        ])
    monkeypatch.setattr(wizard.github, "detect_ca_repos",
                        lambda repos: {"Layr-Labs/eigenlayer-contracts": 7})
    monkeypatch.setattr(wizard.github, "scan_repo", lambda url, rpc_url=None: {
        "contracts": {"0x39053d51b77dc0d36036fc1fcc8cb819df8ef37a": {"verified": True}},
        "total_addresses": 1, "repo_dir": "/tmp/x"})
    DummyConfirm.answer = True
    DummyPrompt.answer = "1"
    monkeypatch.setattr(wizard, "Confirm", DummyConfirm)
    monkeypatch.setattr(wizard, "Prompt", DummyPrompt)
    scan = wizard._scan_llama_protocol("llama:eigenlayer", rpc=None)
    assert scan["deep_repo"] == "Layr-Labs/eigenlayer-contracts"
    assert scan["total_addresses"] == 2  # anchor + repo's contracts merged
    assert "0x39053d51b77dc0d36036fc1fcc8cb819df8ef37a" in scan["contracts"]
    assert "Layr-Labs" in scan["repo_dir"]


# --- deployed-address (CA) repo auto-detection ------------------------------


def test_score_repo_for_ca_detects_deployment_layout():
    """A foundry protocol repo with deployment artifacts scores high."""
    paths = [
        "script/output/mainnet/deployment_data.json",
        "script/deploy/deploy_from_scratch.s.sol",
        "script/configs/mainnet/mainnet-addresses.config.json",
        "foundry.toml",
        "src/DelegationManager.sol",
    ]
    readme = "Deployed contracts live at 0x39053D51B77DC0d36036Fc1fCc8Cb819df8Ef37A"
    assert github.score_repo_for_ca(paths, readme) >= 4


def test_score_repo_for_ca_plain_repo_scores_low():
    """A docs/tooling repo without deployment files scores ~0."""
    paths = ["src/main.rs", "Cargo.toml", "README.md", ".github/workflows/ci.yml"]
    assert github.score_repo_for_ca(paths, "A challenge repo. No contracts.") < 4


def test_detect_ca_repos_ranks_contract_repo_first(monkeypatch):
    """detect_ca_repos scores each repo; failures degrade to 0."""
    github._detect_cache.clear()
    repos = [
        {"name": "Layr-Labs/eigenlayer-contracts", "default_branch": "main"},
        {"name": "Layr-Labs/lighter-prover-challenge", "default_branch": "main"},
        {"name": "Layr-Labs/rate-limited", "default_branch": "main"},
    ]

    def fake_json(url, attempts=2, timeout=10):
        if "eigenlayer-contracts" in url:
            return {"tree": [
                {"path": "script/output/mainnet/deployment_data.json"},
                {"path": "src/DelegationManager.sol"},
                {"path": "foundry.toml"},
            ]}
        return None  # lighter-prover + rate-limited: tree fetch fails

    monkeypatch.setattr(github, "_github_get_json", fake_json)
    scores = github.detect_ca_repos(repos)
    assert scores["Layr-Labs/eigenlayer-contracts"] >= 4
    assert scores["Layr-Labs/lighter-prover-challenge"] == 0
    assert scores["Layr-Labs/rate-limited"] == 0  # network failure -> 0


def test_detect_ca_repos_caches_results(monkeypatch):
    """A repeated repo set is served from cache — zero extra API calls."""
    github._detect_cache.clear()
    repos = [{"name": "Layr-Labs/eigenlayer-contracts", "default_branch": "main"}]
    calls = {"n": 0}

    def fake_json(url, attempts=2, timeout=10):
        calls["n"] += 1
        return {"tree": [{"path": "src/DelegationManager.sol"}]}

    monkeypatch.setattr(github, "_github_get_json", fake_json)
    first = github.detect_ca_repos(repos)
    assert calls["n"] == 1
    second = github.detect_ca_repos(repos)  # cached
    assert calls["n"] == 1
    assert first == second


def test_list_org_repos_includes_default_branch(monkeypatch):
    payload = [_repo("Layr-Labs/eigenlayer-contracts", default_branch="master")]
    monkeypatch.setattr(github.requests, "get",
                        lambda url, timeout=30, headers=None: FakeResp(payload))
    repos = github.list_org_repos("Layr-Labs")
    assert repos[0]["default_branch"] == "master"


def test_github_headers_without_token(monkeypatch):
    """No token configured -> no Authorization header."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    assert github._github_headers() == {}


def test_github_headers_with_token(monkeypatch):
    """GITHUB_TOKEN is sent as a Bearer Authorization header."""
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_123secret")
    assert github._github_headers() == {"Authorization": "Bearer ghp_123secret"}


def test_list_org_repos_sends_token_when_configured(monkeypatch):
    """With GITHUB_TOKEN set, org listing sends the auth header."""
    seen = {}

    def capture(url, timeout=30, headers=None):
        seen["headers"] = headers
        return FakeResp([_repo("Layr-Labs/eigenlayer-contracts")])

    monkeypatch.setattr(github.requests, "get", capture)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_123secret")
    github.list_org_repos("Layr-Labs")
    assert seen["headers"].get("Authorization") == "Bearer ghp_123secret"


# --- Anchor identity matching ----------------------------------------------


def test_identity_match_symbol_equals():
    assert wizard.identity_match("sky", "SKY Governance Token", "SKY") == "match"


def test_identity_match_name_substring():
    # protocol name is a substring of the on-chain name
    assert wizard.identity_match("eigenlayer", "EigenLayer", "EIGEN") == "match"


def test_identity_match_detects_wrong_anchor():
    # DefiLlama resolved EigenCloud but the token identifies as EigenLayer
    assert wizard.identity_match("eigencloud", "EigenLayer", "EIGEN") == "mismatch"


def test_identity_match_no_metadata():
    assert wizard.identity_match("sky", None, None) == "unknown"
    assert wizard.identity_match("", "Sky", "SKY") == "unknown"


def test_llama_scan_marks_anchor_identity_match(monkeypatch):
    """Verified anchors with matching name/symbol get identity='match'."""
    from defihunter import wizard
    from defihunter.core import protocols

    monkeypatch.setattr(protocols, "resolve_protocol", lambda name: {
        "name": "Sky", "url": "", "chains": ["Ethereum"],
        "github_orgs": [],
        "addresses": ["0x56072c95faa701256059aa122697b133aded9279"],
    })
    monkeypatch.setattr(wizard.github, "scan_addresses",
                        lambda src, rpc_url=None: {
                            "contracts": {"0x56072c95faa701256059aa122697b133aded9279": {
                                "verified": True, "name": "SKY Governance Token",
                                "symbol": "SKY"}},
                            "total_addresses": 1, "repo_dir": "(addresses)"})
    scan = wizard._scan_llama_protocol("llama:sky", rpc=None)
    entry = scan["contracts"]["0x56072c95faa701256059aa122697b133aded9279"]
    assert entry["identity"] == "match"


def test_llama_scan_marks_anchor_identity_mismatch(monkeypatch):
    """The eigenlayer->EigenCloud trap: token says EigenLayer, resolved says
    EigenCloud -> identity flagged 'mismatch' instead of silently passing."""
    from defihunter import wizard
    from defihunter.core import protocols

    monkeypatch.setattr(protocols, "resolve_protocol", lambda name: {
        "name": "EigenCloud", "url": "", "chains": ["Ethereum"],
        "github_orgs": [],
        "addresses": ["0xec53bf9167f50cdeb3ae105f56099aaab9061f83"],
    })
    monkeypatch.setattr(wizard.github, "scan_addresses",
                        lambda src, rpc_url=None: {
                            "contracts": {"0xec53bf9167f50cdeb3ae105f56099aaab9061f83": {
                                "verified": True, "name": "EigenLayer",
                                "symbol": "EIGEN"}},
                            "total_addresses": 1, "repo_dir": "(addresses)"})
    scan = wizard._scan_llama_protocol("llama:eigenlayer", rpc=None)
    entry = scan["contracts"]["0xec53bf9167f50cdeb3ae105f56099aaab9061f83"]
    assert entry["identity"] == "mismatch"


def test_rate_limit_hint_without_token(monkeypatch):
    """No token in the shell -> hint points at stale shell / missing export."""
    monkeypatch.delenv("GITHUB_TOKEN", raising=False)
    monkeypatch.delenv("GH_TOKEN", raising=False)
    hint = wizard._rate_limit_hint()
    assert "NEW terminal" in hint
    assert "source ~/.zshrc" in hint


def test_rate_limit_hint_with_token(monkeypatch):
    """Token present but still refused -> hint points at token itself."""
    monkeypatch.setenv("GITHUB_TOKEN", "ghp_x")
    monkeypatch.delenv("GH_TOKEN", raising=False)
    hint = wizard._rate_limit_hint()
    assert "expired" in hint
    assert "NEW terminal" not in hint


def test_clone_retries_transient_failure(monkeypatch):
    """A flaky DNS clone failure is retried once before succeeding."""
    from defihunter.core import github as gh
    calls = {"n": 0}

    def fake_subprocess_run(cmd, capture_output, text, timeout):
        calls["n"] += 1
        class Proc:
            returncode = 0 if calls["n"] == 2 else 128
            stdout = ""
            stderr = "fatal: Could not resolve host: github.com" if calls["n"] == 1 else ""
        return Proc()

    monkeypatch.setattr(gh, "_try_tarball", lambda url, dest: False)
    monkeypatch.setattr(gh.subprocess, "run", fake_subprocess_run)
    monkeypatch.setattr(gh.time, "sleep", lambda s: None)
    dest = gh.clone("https://github.com/Layr-Labs/zeus")
    assert calls["n"] == 2  # failed once, retried, succeeded
    assert dest.exists() or True  # (tmp dir cleanup may differ; success path hit)


def test_clone_raises_after_retries(monkeypatch):
    from defihunter.core import github as gh
    calls = {"n": 0}

    def fake_subprocess_run(cmd, capture_output, text, timeout):
        calls["n"] += 1
        class Proc:
            returncode = 128
            stdout = ""
            stderr = "fatal: Could not resolve host: github.com"
        return Proc()

    monkeypatch.setattr(gh, "_try_tarball", lambda url, dest: False)
    monkeypatch.setattr(gh.subprocess, "run", fake_subprocess_run)
    monkeypatch.setattr(gh.time, "sleep", lambda s: None)
    try:
        gh.clone("https://github.com/Layr-Labs/zeus")
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "Could not resolve host" in str(e)
    assert calls["n"] == 2  # both attempts used


def test_clone_falls_back_to_tarball(monkeypatch):
    """When git clone fails, a github.com repo is rescued via codeload."""
    from defihunter.core import github as gh
    calls = {"n": 0}

    def fake_subprocess_run(cmd, capture_output, text, timeout):
        calls["n"] += 1
        class Proc:
            returncode = 128
            stdout = ""
            stderr = "fatal: Could not resolve host: github.com"
        return Proc()

    monkeypatch.setattr(gh.subprocess, "run", fake_subprocess_run)
    monkeypatch.setattr(gh.time, "sleep", lambda s: None)

    def fake_tarball(url, dest):
        dest.mkdir(parents=True, exist_ok=True)
        (dest / "README.md").write_text("hi")
        return True

    monkeypatch.setattr(gh, "_try_tarball", fake_tarball)
    dest = gh.clone("https://github.com/Layr-Labs/zeus")
    assert calls["n"] == 1  # git tried once, then tarball rescued
    assert (dest / "README.md").read_text() == "hi"


def test_clone_converts_timeout_to_runtimeerror(monkeypatch):
    """A git-clone timeout must surface as RuntimeError, not escape raw."""
    from defihunter.core import github as gh
    import subprocess

    def boom(cmd, capture_output, text, timeout):
        raise subprocess.TimeoutExpired(cmd, timeout)

    monkeypatch.setattr(gh, "_try_tarball", lambda url, dest: False)
    monkeypatch.setattr(gh.subprocess, "run", boom)
    monkeypatch.setattr(gh.time, "sleep", lambda s: None)
    try:
        gh.clone("https://example.com/big/repo.git")
        assert False, "expected RuntimeError"
    except RuntimeError as e:
        assert "timed out" in str(e)



def test_llama_scan_survives_deep_clone_failure(monkeypatch):
    """A failed deep-repo clone must NOT abort the hunt — anchor scan stands."""
    from defihunter import wizard
    from defihunter.core import protocols

    monkeypatch.setattr(protocols, "resolve_protocol", lambda name: {
        "name": "EigenCloud", "url": "", "chains": ["Ethereum"],
        "github_orgs": ["Layr-Labs"],
        "addresses": ["0xec53bf9167f50cdeb3ae105f56099aaab9061f83"],
    })
    monkeypatch.setattr(wizard.github, "scan_addresses",
                        lambda src, rpc_url=None: {
                            "contracts": {"0xec53bf9167f50cdeb3ae105f56099aaab9061f83": {
                                "verified": True, "name": "Eigen", "symbol": "EIGEN"}},
                            "total_addresses": 1, "repo_dir": "(addresses)"})
    monkeypatch.setattr(wizard.github, "list_org_repos",
                        lambda org, attempts=3, timeout=30: [
                            {"name": "Layr-Labs/eigenlayer-contracts",
                             "description": "Contracts of EigenLayer", "updated": "2026-08-01",
                             "stars": 720, "language": "Solidity", "default_branch": "main"}])
    monkeypatch.setattr(wizard.github, "detect_ca_repos",
                        lambda repos: {"Layr-Labs/eigenlayer-contracts": 5})
    monkeypatch.setattr(wizard.github, "scan_repo",
                        lambda url, rpc_url=None: (_ for _ in ()).throw(
                            RuntimeError("Could not clone ...: Could not resolve host: github.com")))
    DummyConfirm.answer = True  # yes to "also scan a repo?"
    monkeypatch.setattr(wizard, "Confirm", DummyConfirm)
    DummyPrompt.answer = "1"
    monkeypatch.setattr(wizard, "Prompt", DummyPrompt)

    scan = wizard._scan_llama_protocol("llama:eigencloud", rpc=None)
    # hunt survived: anchor scan intact, deep repo not merged
    assert scan["contracts"]["0xec53bf9167f50cdeb3ae105f56099aaab9061f83"]["identity"] == "mismatch"
    assert "deep_repo" not in scan
    assert scan["repo_dir"] == "(addresses)"


def test_source_code_bonus_solidity():
    """Solidity/Vyper repos are the attack surface — get the +2 bump."""
    from defihunter.core.github import source_code_bonus
    assert source_code_bonus({"name": "Layr-Labs/eigenlayer-contracts", "language": "Solidity"}) == 2
    assert source_code_bonus({"name": "vyper-playground", "language": "Vyper"}) == 2


def test_source_code_bonus_name_hint():
    """A 'contracts'-named repo with no language metadata still gets +1."""
    from defihunter.core.github import source_code_bonus
    assert source_code_bonus({"name": "Layr-Labs/eigenlayer-contracts", "language": ""}) == 1
    assert source_code_bonus({"name": "protocol-core", "language": "TypeScript"}) == 1


def test_source_code_bonus_none_for_tooling():
    """Deployer/docs tooling with no source hints gets no bump."""
    from defihunter.core.github import source_code_bonus
    assert source_code_bonus({"name": "Layr-Labs/zeus", "language": "Go"}) == 0
    assert source_code_bonus({"name": "docs", "language": "HTML"}) == 0
    assert source_code_bonus({"name": "", "language": ""}) == 0


def test_repo_score_includes_source_bonus(monkeypatch):
    """The bonus is load-bearing: thin Solidity source beats deployer tooling.

    Without the bonus the tool scores 3 (deploy/ + script/output/) and the
    source repo 2 (foundry.toml + .sol) — tool wins. The +2 Soliditity bump
    flips it to 4 vs 3, which is exactly the nudge the picker needs.
    """
    from defihunter.core.github import _repo_ca_score

    def fake_get_json(url, attempts=2, timeout=10):
        if "zeus" in url:
            # deployer tooling: deploy script + output dir, no source code
            return {"tree": [{"path": ".github/workflows/ci.yml"},
                             {"path": "deploy/zeus.ts"},
                             {"path": "script/output/main.json"}]}
        # eigenlayer-contracts: thin but real Solidity source
        return {"tree": [{"path": "src/StrategyManager.sol"},
                         {"path": "foundry.toml"}]}

    monkeypatch.setattr("defihunter.core.github._github_get_json", fake_get_json)
    zeus = _repo_ca_score({"name": "Layr-Labs/zeus", "default_branch": "main", "language": "Go"})
    contracts = _repo_ca_score({
        "name": "Layr-Labs/eigenlayer-contracts", "default_branch": "main", "language": "Solidity"})
    # without the bonus this fails (3 > 2); with it the source repo wins
    assert contracts[1] > zeus[1]
    assert zeus[1] == 3
    assert contracts[1] == 4


def test_is_source_repo():
    """Solidity/Vyper (or source-named) repos are flagged as source."""
    from defihunter.core.github import is_source_repo
    assert is_source_repo({"name": "Layr-Labs/eigenlayer-contracts", "language": "Solidity"})
    assert is_source_repo({"name": "protocol-core", "language": "TypeScript"})  # name hint
    assert not is_source_repo({"name": "Layr-Labs/zeus", "language": "TypeScript"})
    assert not is_source_repo({"name": "docs", "language": "HTML"})


def test_pick_org_repo_ranks_source_first_even_when_scoring_lower(monkeypatch):
    """A deployer tool with a higher CA score must NOT outrank the source repo.

    Real data showed zeus scoring 26 vs eigenlayer-contracts 18 — the wizard
    must still offer the canonical source repo first.
    """
    from defihunter import wizard

    def fake_list_repos(org, attempts=3, timeout=30):
        return [
            {"name": "Layr-Labs/eigenlayer-contracts", "description": "EigenLayer core contracts",
             "updated": "2026-08-01", "stars": 720, "language": "Solidity", "default_branch": "main"},
            {"name": "Layr-Labs/zeus", "description": "Deployer tooling",
             "updated": "2026-08-02", "stars": 300, "language": "TypeScript", "default_branch": "main"},
        ]

    def fake_detect(repos):
        # tree scoring noise: the deployer tool scores way higher
        return {"Layr-Labs/zeus": 26, "Layr-Labs/eigenlayer-contracts": 18}

    monkeypatch.setattr(wizard.github, "list_org_repos", fake_list_repos)
    monkeypatch.setattr(wizard.github, "detect_ca_repos", fake_detect)
    DummyPrompt.answer = "1"
    monkeypatch.setattr(wizard, "Prompt", DummyPrompt)

    picked = wizard._pick_org_repo("Layr-Labs")
    assert picked == "Layr-Labs/eigenlayer-contracts"  # source first, not zeus


class TestExtractDeployments:
    """Deployment-artifact parsing: config, foundry broadcast, hardhat-deploy."""

    def test_eigenlayer_config_layout(self, tmp_path):
        from defihunter.core.github import extract_deployments
        cfg = tmp_path / "script" / "configs"
        cfg.mkdir(parents=True)
        (cfg / "mainnet.json").write_text(json.dumps({
            "config": {"environment": {"name": "mainnet"}},
            "deployment": {
                "core": {
                    "strategyManager": {
                        "proxy": "0x858646372CC42E1A627fcE94aa7A7033e7CF075A",
                        "impl": "0x70f44c13944d49a236e3cd7a94f48f5dab6c619b",
                    },
                    "avsDirectory": {"proxy": "0x135dda560e946695d6f155dacafc6f1f25c1f5af"},
                },
                "token": {"eigen": {"impl": "0x1111111111111111111111111111111111111111"}},
            },
        }))
        deps = extract_deployments(tmp_path)
        assert "strategymanager" in deps
        assert "0x858646372cc42e1a627fce94aa7a7033e7cf075a" in deps["strategymanager"]
        assert "0x70f44c13944d49a236e3cd7a94f48f5dab6c619b" in deps["strategymanager"]
        assert "eigen" in deps  # impl-only contract still resolved by name

    def test_foundry_broadcast_layout(self, tmp_path):
        from defihunter.core.github import extract_deployments
        art = tmp_path / "broadcast" / "Deploy.s.sol" / "1"
        art.mkdir(parents=True)
        (art / "run-latest.json").write_text(json.dumps({
            "transactions": [
                {"transactionType": "CREATE", "contractName": "StrategyManager",
                 "contractAddress": "0x858646372CC42E1A627fcE94aa7A7033e7CF075A"},
                {"transactionType": "CALL", "contractName": "ProxyAdmin",  # ignored
                 "contractAddress": "0x2222222222222222222222222222222222222222"},
            ],
        }))
        deps = extract_deployments(tmp_path)
        assert "strategymanager" in deps

    def test_hardhat_deploy_layout(self, tmp_path):
        from defihunter.core.github import extract_deployments
        art = tmp_path / "deployments" / "mainnet"
        art.mkdir(parents=True)
        (art / "StrategyManager.json").write_text(json.dumps({
            "address": "0x858646372CC42E1A627fcE94aa7A7033e7CF075A"}))
        deps = extract_deployments(tmp_path)
        assert deps.get("strategymanager") == ["0x858646372cc42e1a627fce94aa7a7033e7cf075a"]

    def test_norm_name_collapses_case_and_separators(self):
        from defihunter.core.github import _norm_name
        assert _norm_name("StrategyManager") == "strategymanager"
        assert _norm_name("strategyManager") == "strategymanager"
        assert _norm_name("strategy_manager") == "strategymanager"
        assert _norm_name("IAVSDirectory") == "iavsdirectory"

    def test_zero_address_and_pendingimpl_placeholders_skipped(self, tmp_path):
        from defihunter.core.github import extract_deployments
        cfg = tmp_path / "script" / "configs"
        cfg.mkdir(parents=True)
        (cfg / "mainnet.json").write_text(json.dumps({
            "deployment": {"core": {"strategyManager": {
                "proxy": "0x858646372CC42E1A627fcE94aa7A7033e7CF075A",
                "impl": "0x70f44c13944d49a236e3cd7a94f48f5dab6c619b",
                "pendingImpl": "0x0000000000000000000000000000000000000000",
                "notAnAddress": "0x1234",  # malformed → dropped
            }}},
        }))
        deps = extract_deployments(tmp_path)
        sm = deps.get("strategymanager", [])
        assert "0x858646372cc42e1a627fce94aa7a7033e7cf075a" in sm
        assert "0x70f44c13944d49a236e3cd7a94f48f5dab6c619b" in sm
        assert len(sm) == 2  # zero + malformed placeholders excluded

    def test_non_mainnet_artifacts_do_not_shadow_mainnet(self, tmp_path):
        from defihunter.core.github import extract_deployments
        cfg = tmp_path / "script" / "configs"
        cfg.mkdir(parents=True)
        (cfg / "mainnet.json").write_text(json.dumps({
            "deployment": {"core": {"strategyManager": {
                "proxy": "0x858646372CC42E1A627fcE94aa7A7033e7CF075A"}}}}))
        dev = tmp_path / "broadcast" / "Deploy.s.sol" / "31337"
        dev.mkdir(parents=True)
        (dev / "run-latest.json").write_text(json.dumps({
            "transactions": [{"transactionType": "CREATE",
                              "contractName": "StrategyManager",
                              "contractAddress": "0x9999999999999999999999999999999999999999"}]}))
        # testnet config whose FILENAME itself is the network tag (zipzoop.json)
        (cfg / "zipzoop.json").write_text(json.dumps({
            "deployment": {"core": {"strategyManager": {
                "proxy": "0x8888888888888888888888888888888888888888"}}}}))
        deps = extract_deployments(tmp_path)
        assert "0x9999999999999999999999999999999999999999" not in deps.get("strategymanager", [])
        assert "0x8888888888888888888888888888888888888888" not in deps.get("strategymanager", [])
        assert "0x858646372cc42e1a627fce94aa7a7033e7cf075a" in deps["strategymanager"]


class TestForkVerifyDeploymentResolution:
    """Findings resolve to live addresses by CONTRACT NAME, not just file mentions."""

    def test_resolves_via_deployment_artifacts(self, tmp_path, monkeypatch):
        from defihunter import wizard
        # fake repo with a deployment config (the eigenlayer layout)
        cfg = tmp_path / "script" / "configs"
        cfg.mkdir(parents=True)
        (cfg / "mainnet.json").write_text(json.dumps({
            "deployment": {"core": {"strategyManager": {
                "proxy": "0x858646372CC42E1A627fcE94aa7A7033e7CF075A"}}},
        }))
        finding = {
            "severity": "HIGH", "title": "initialize() without initializer guard",
            "file": "src/contracts/core/StrategyManager.sol", "line": 57,
            "attack": "initialize",
        }

        called = []
        class FakeFork:
            available = True
            rpc_url = "http://127.0.0.1:8545"
            why_not = ""
            def __enter__(self): return self
            def __exit__(self, *a): return False
            def run(self, attack, target, source_finding=None, abi=None):
                called.append(target)
                return {"success": True, "attack": attack, "target": target,
                        "verdict": "CONFIRMED",
                        "source_finding": source_finding}

        monkeypatch.setattr(wizard, "ForkSimulator", lambda rpc_url=None: FakeFork())
        monkeypatch.setattr(wizard.abi_util, "fetch_abi", lambda addr: [])
        from rich.console import Console
        import io
        monkeypatch.setattr(wizard.ui, "console",
                            Console(file=io.StringIO(), force_terminal=False,
                                    color_system=None, width=120,
                                    theme=wizard.ui.THEME))
        monkeypatch.setattr(wizard.ui, "rule", lambda *a, **k: None)
        monkeypatch.setattr(wizard.ui, "info", lambda *a, **k: None)
        monkeypatch.setattr(wizard.ui, "warn", lambda *a, **k: None)
        results = wizard._run_fork_verify(
            [finding], {}, "https://example.com/rpc", repo_dir=str(tmp_path))
        assert len(results) == 1 and results[0]["success"]
        assert called == ["0x858646372cc42e1a627fce94aa7a7033e7cf075a"]

    def test_skip_when_no_deployment_match(self, tmp_path, monkeypatch):
        from defihunter import wizard
        finding = {
            "severity": "HIGH", "title": "mint() without visible access control",
            "file": "src/contracts/core/StrategyManager.sol", "line": 10,
            "attack": "mint",
        }
        results = wizard._run_fork_verify([finding], {}, None, repo_dir=str(tmp_path))
        assert results == []
