"""Tests for the GitHub repo scanner + interactive wizard."""
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
