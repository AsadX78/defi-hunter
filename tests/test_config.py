"""Tests for local config persistence (config.local.yaml) + RPC default resolution."""
import os

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
