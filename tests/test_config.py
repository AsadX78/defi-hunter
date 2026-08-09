"""Tests for local config persistence (config.local.yaml) + RPC default resolution."""
import os
from pathlib import Path

import pytest

from defihunter.core import config


@pytest.fixture
def isolated_config(tmp_path, monkeypatch):
    """Point the local config at a temp file for each test."""
    cfg_file = tmp_path / "config.local.yaml"
    monkeypatch.setenv(config.CONFIG_ENV, str(cfg_file))
    monkeypatch.delenv("DEFIHUNTER_RPC", raising=False)
    monkeypatch.delenv("RPC_URL", raising=False)
    return cfg_file


def test_default_rpc_fallback(isolated_config):
    """No env, no config file → built-in public default."""
    assert config.get_default_rpc() == config.DEFAULT_RPC


def test_default_rpc_from_env(isolated_config):
    """DEFIHUNTER_RPC env var wins over everything else."""
    os.environ["DEFIHUNTER_RPC"] = "https://env.example/rpc"
    assert config.get_default_rpc() == "https://env.example/rpc"


def test_default_rpc_from_config(isolated_config):
    """Saved config value is used when no env var is set."""
    config.save_rpc("https://saved.example/rpc")
    assert config.get_default_rpc() == "https://saved.example/rpc"


def test_env_beats_config(isolated_config):
    """DEFIHUNTER_RPC takes precedence over the saved config value."""
    config.save_rpc("https://saved.example/rpc")
    os.environ["DEFIHUNTER_RPC"] = "https://env.example/rpc"
    assert config.get_default_rpc() == "https://env.example/rpc"


def test_save_rpc_writes_file(isolated_config):
    """save_rpc persists default_rpc key; save_rpc returns the path."""
    path = config.save_rpc("https://alchemy.example/v2/secretkey")
    assert path == isolated_config
    assert isolated_config.exists()
    assert config.load_local_config()["default_rpc"] == "https://alchemy.example/v2/secretkey"


def test_clear_rpc_removes_key(isolated_config):
    """clear_rpc removes only default_rpc, keeping other keys."""
    config.save_local_config({"default_rpc": "https://a/rpc", "other": "keep-me"})
    config.clear_rpc()
    cfg = config.load_local_config()
    assert "default_rpc" not in cfg
    assert cfg.get("other") == "keep-me"


def test_corrupt_config_is_ignored(isolated_config):
    """A malformed config file falls back to the default instead of crashing."""
    isolated_config.write_text("::: not: [valid yaml")
    assert config.get_default_rpc() == config.DEFAULT_RPC


def test_load_config_legacy_still_works():
    """The original multi-chain config loader is untouched."""
    cfg = config.load_config()
    assert cfg["rpc"]["ethereum"]  # per-chain defaults still present
    assert config.get_rpc_url(cfg) == cfg["rpc"]["ethereum"]


def test_home_config_used_from_any_cwd(tmp_path, monkeypatch):
    """With no local config.local.yaml, resolution falls back to
    $XDG_CONFIG_HOME/defi-hunter/config.yaml (home-anchored, works anywhere)."""
    monkeypatch.delenv(config.CONFIG_ENV, raising=False)
    monkeypatch.delenv("DEFIHUNTER_RPC", raising=False)
    monkeypatch.delenv("RPC_URL", raising=False)
    xdg = tmp_path / "xdg"
    monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
    # Run from a random cwd with no config.local.yaml present
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    monkeypatch.chdir(elsewhere)

    assert not Path("config.local.yaml").exists()
    expected = xdg / "defi-hunter" / "config.yaml"
    assert config.config_path() == expected

    path = config.save_rpc("https://home.example/rpc")
    assert path == expected
    assert config.get_default_rpc() == "https://home.example/rpc"


def test_repo_local_config_takes_priority(tmp_path, monkeypatch):
    """A config.local.yaml in the CWD is still honored (legacy repo-local)."""
    monkeypatch.delenv(config.CONFIG_ENV, raising=False)
    monkeypatch.delenv("DEFIHUNTER_RPC", raising=False)
    monkeypatch.delenv("RPC_URL", raising=False)
    monkeypatch.delenv("XDG_CONFIG_HOME", raising=False)
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.chdir(tmp_path)
    (tmp_path / "config.local.yaml").write_text("default_rpc: https://local.example/rpc\n")

    assert config.config_path() == Path("config.local.yaml")
    assert config.get_default_rpc() == "https://local.example/rpc"
