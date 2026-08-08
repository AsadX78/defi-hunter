"""Configuration management"""
import os
import yaml
from pathlib import Path
from typing import Optional, Dict, Any

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
