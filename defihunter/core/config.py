"""Configuration management"""
import os
import yaml
from pathlib import Path
from typing import Optional, Dict, Any

DEFAULT_RPC = "https://eth.drpc.org"
CONFIG_ENV = "DEFIHUNTER_CONFIG"  # optional override for the local config path (tests use this)

DEFAULT_CONFIG = {
    'rpc': {
        'ethereum': 'https://rpc.ankr.com/eth',
        'polygon': 'https://rpc.ankr.com/polygon',
        'arbitrum': 'https://rpc.ankr.com/arbitrum',
        'optimism': 'https://rpc.ankr.com/optimism',
        'bsc': 'https://rpc.ankr.com/bsc',
    },
    'etherscan': {
        'api_key': '',
        'rate_limit': 5,
    },
    'scan': {
        'timeout': 30,
        'max_js_files': 20,
        'scan_subdomains': True,
    },
    'fork': {
        'port': 8545,
        'balance': 10000,
    },
    'findings': {
        'min_severity': 'LOW',
        'include_simulation': True,
    }
}

def load_config(path: Optional[str] = None) -> Dict[str, Any]:
    """Load configuration from file or environment"""
    config = DEFAULT_CONFIG.copy()
    
    # Try config file
    if path:
        config_path = Path(path)
        if config_path.exists():
            file_config = yaml.safe_load(config_path.read_text())
            if file_config:
                config.update(file_config)
    
    # Override with env vars
    for key in ['RPC_URL', 'ETHERSCAN_API_KEY']:
        val = os.getenv(key)
        if val:
            config[key.lower()] = val
    
    return config

def get_rpc_url(config: Dict[str, Any], chain: str = 'ethereum') -> str:
    """Get RPC URL for a chain"""
    # Check env var first
    env_rpc = os.getenv('RPC_URL')
    if env_rpc:
        return env_rpc
    
    # Then config
    return config.get('rpc', {}).get(chain, DEFAULT_CONFIG['rpc']['ethereum'])


# ---------------------------------------------------------------------------
# Local persistence (config.local.yaml — gitignored, machine-local)
# ---------------------------------------------------------------------------

def config_path() -> Path:
    """Resolve the local config file (works from any working directory).

    1. $DEFIHUNTER_CONFIG override (tests use this)
    2. ./config.local.yaml if present (legacy repo-local configs keep working)
    3. ~/.config/defi-hunter/config.yaml (default — survives being run anywhere)
    """
    override = os.getenv(CONFIG_ENV)
    if override:
        return Path(override)
    local = Path("config.local.yaml")
    if local.exists():
        return local
    xdg = os.getenv("XDG_CONFIG_HOME")
    base = Path(xdg) if xdg else Path.home() / ".config"
    return base / "defi-hunter" / "config.yaml"


def load_local_config() -> Dict[str, Any]:
    """Read config.local.yaml (missing/corrupt file -> empty dict)."""
    path = config_path()
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except yaml.YAMLError:
        return {}


def save_local_config(data: Dict[str, Any]) -> Path:
    """Write config.local.yaml, preserving any existing keys."""
    path = config_path()
    merged = dict(load_local_config())
    merged.update(data)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(merged, sort_keys=False), encoding="utf-8")
    return path


def get_default_rpc() -> str:
    """Best RPC default for the wizard:
    $DEFIHUNTER_RPC > config.local.yaml `default_rpc` > built-in default."""
    env_rpc = os.getenv("DEFIHUNTER_RPC")
    if env_rpc:
        return env_rpc.strip()
    cfg = load_local_config()
    rpc = cfg.get("default_rpc")
    if isinstance(rpc, str) and rpc.strip():
        return rpc.strip()
    return DEFAULT_RPC


def save_rpc(url: str) -> Path:
    """Persist an RPC URL for future hunts. Returns the config path written."""
    return save_local_config({"default_rpc": url.strip()})


def clear_rpc() -> None:
    """Remove the saved RPC from config.local.yaml."""
    path = config_path()
    cfg = load_local_config()
    if "default_rpc" in cfg:
        del cfg["default_rpc"]
        path.write_text(yaml.safe_dump(cfg, sort_keys=False), encoding="utf-8")
