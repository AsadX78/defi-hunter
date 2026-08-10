"""Multi-chain registry — RPC endpoints, block explorers, native tokens.

Supports: Ethereum, BSC, Polygon, Arbitrum, Optimism, Base, Avalanche,
Fantom, Gnosis, Linea, zkSync, Scroll, Mantle, Celo, Moonbeam.
"""

from dataclasses import dataclass
from typing import Dict, Optional

# Default RPCs — public endpoints, rate-limited. Users should set their own.
DEFAULT_RPCS = {
    "ethereum": "https://eth.llamarpc.com",
    "bsc": "https://bsc-dataseed.binance.org",
    "polygon": "https://polygon-rpc.com",
    "arbitrum": "https://arb1.arbitrum.io/rpc",
    "optimism": "https://mainnet.optimism.io",
    "base": "https://mainnet.base.org",
    "avalanche": "https://api.avax.network/ext/bc/C/rpc",
    "fantom": "https://rpc.ftm.tools",
    "gnosis": "https://rpc.gnosischain.com",
    "linea": "https://rpc.linea.build",
    "zksync": "https://mainnet.era.zksync.io",
    "scroll": "https://rpc.scroll.io",
    "mantle": "https://rpc.mantle.xyz",
    "celo": "https://forno.celo.org",
    "moonbeam": "https://rpc.api.moonbeam.network",
}


@dataclass
class ChainInfo:
    name: str
    chain_id: int
    native_token: str
    explorer_url: str
    explorer_api: str
    rpc_url: str
    block_time: float  # seconds
    supports_eip1559: bool = True


CHAINS: Dict[str, ChainInfo] = {
    "ethereum": ChainInfo(
        name="Ethereum Mainnet",
        chain_id=1,
        native_token="ETH",
        explorer_url="https://etherscan.io",
        explorer_api="https://api.etherscan.io/api",
        rpc_url=DEFAULT_RPCS["ethereum"],
        block_time=12.0,
    ),
    "bsc": ChainInfo(
        name="BNB Smart Chain",
        chain_id=56,
        native_token="BNB",
        explorer_url="https://bscscan.com",
        explorer_api="https://api.bscscan.com/api",
        rpc_url=DEFAULT_RPCS["bsc"],
        block_time=3.0,
    ),
    "polygon": ChainInfo(
        name="Polygon PoS",
        chain_id=137,
        native_token="MATIC",
        explorer_url="https://polygonscan.com",
        explorer_api="https://api.polygonscan.com/api",
        rpc_url=DEFAULT_RPCS["polygon"],
        block_time=2.0,
    ),
    "arbitrum": ChainInfo(
        name="Arbitrum One",
        chain_id=42161,
        native_token="ETH",
        explorer_url="https://arbiscan.io",
        explorer_api="https://api.arbiscan.io/api",
        rpc_url=DEFAULT_RPCS["arbitrum"],
        block_time=0.25,
    ),
    "optimism": ChainInfo(
        name="Optimism",
        chain_id=10,
        native_token="ETH",
        explorer_url="https://optimistic.etherscan.io",
        explorer_api="https://api-optimistic.etherscan.io/api",
        rpc_url=DEFAULT_RPCS["optimism"],
        block_time=2.0,
    ),
    "base": ChainInfo(
        name="Base",
        chain_id=8453,
        native_token="ETH",
        explorer_url="https://basescan.org",
        explorer_api="https://api.basescan.org/api",
        rpc_url=DEFAULT_RPCS["base"],
        block_time=2.0,
    ),
    "avalanche": ChainInfo(
        name="Avalanche C-Chain",
        chain_id=43114,
        native_token="AVAX",
        explorer_url="https://snowtrace.io",
        explorer_api="https://api.snowtrace.io/api",
        rpc_url=DEFAULT_RPCS["avalanche"],
        block_time=2.0,
    ),
    "fantom": ChainInfo(
        name="Fantom Opera",
        chain_id=250,
        native_token="FTM",
        explorer_url="https://ftmscan.com",
        explorer_api="https://api.ftmscan.com/api",
        rpc_url=DEFAULT_RPCS["fantom"],
        block_time=1.0,
    ),
    "gnosis": ChainInfo(
        name="Gnosis Chain",
        chain_id=100,
        native_token="xDAI",
        explorer_url="https://gnosisscan.io",
        explorer_api="https://api.gnosisscan.io/api",
        rpc_url=DEFAULT_RPCS["gnosis"],
        block_time=5.0,
    ),
    "linea": ChainInfo(
        name="Linea",
        chain_id=59144,
        native_token="ETH",
        explorer_url="https://lineascan.build",
        explorer_api="https://api.lineascan.build/api",
        rpc_url=DEFAULT_RPCS["linea"],
        block_time=2.0,
    ),
    "zksync": ChainInfo(
        name="zkSync Era",
        chain_id=324,
        native_token="ETH",
        explorer_url="https://explorer.zksync.io",
        explorer_api="https://block-explorer-api.mainnet.zksync.io/api",
        rpc_url=DEFAULT_RPCS["zksync"],
        block_time=1.0,
    ),
    "scroll": ChainInfo(
        name="Scroll",
        chain_id=534352,
        native_token="ETH",
        explorer_url="https://scrollscan.com",
        explorer_api="https://api.scrollscan.com/api",
        rpc_url=DEFAULT_RPCS["scroll"],
        block_time=3.0,
    ),
    "mantle": ChainInfo(
        name="Mantle",
        chain_id=5000,
        native_token="MNT",
        explorer_url="https://mantlescan.xyz",
        explorer_api="https://api.mantlescan.xyz/api",
        rpc_url=DEFAULT_RPCS["mantle"],
        block_time=2.0,
    ),
    "celo": ChainInfo(
        name="Celo",
        chain_id=42220,
        native_token="CELO",
        explorer_url="https://celoscan.io",
        explorer_api="https://api.celoscan.io/api",
        rpc_url=DEFAULT_RPCS["celo"],
        block_time=5.0,
    ),
    "moonbeam": ChainInfo(
        name="Moonbeam",
        chain_id=1284,
        native_token="GLMR",
        explorer_url="https://moonbeam.moonscan.io",
        explorer_api="https://api-moonbeam.moonscan.io/api",
        rpc_url=DEFAULT_RPCS["moonbeam"],
        block_time=12.0,
    ),
}

# Chain aliases: "eth" → "ethereum", "matic" → "polygon", etc.
CHAIN_ALIASES = {
    "eth": "ethereum",
    "mainnet": "ethereum",
    "homestead": "ethereum",
    "matic": "polygon",
    "mumbai": "polygon",  # legacy testnet
    "arb": "arbitrum",
    "arb1": "arbitrum",
    "op": "optimism",
    "optimistic": "optimism",
    "avax": "avalanche",
    "ftm": "fantom",
    "xdai": "gnosis",
    "zksync-era": "zksync",
}


def resolve_chain(name: str) -> Optional[ChainInfo]:
    """Resolve a chain name/alias to ChainInfo. Case-insensitive."""
    key = name.lower().strip().replace(" ", "").replace("-", "")
    # Try direct match
    for chain_key in CHAINS:
        if chain_key.replace("-", "") == key:
            return CHAINS[chain_key]
    # Try alias
    alias_key = CHAIN_ALIASES.get(name.lower().strip())
    if alias_key:
        return CHAINS.get(alias_key)
    return None


def get_chain(name: str) -> ChainInfo:
    """Get chain info, falling back to Ethereum if unknown."""
    chain = resolve_chain(name)
    if chain is None:
        # Try partial match
        name_lower = name.lower()
        for key, info in CHAINS.items():
            if name_lower in key or name_lower in info.name.lower():
                return info
        return CHAINS["ethereum"]
    return chain


def list_chains() -> list:
    """Return all supported chain names."""
    return sorted(CHAINS.keys())


def detect_chain_from_rpc(rpc_url: str) -> Optional[str]:
    """Detect chain from RPC URL pattern."""
    url = rpc_url.lower()
    patterns = {
        "ethereum": ["eth.", "mainnet.infura.io/v3/", "eth.llamarpc", "eth.drpc"],
        "bsc": ["bsc.", "binance", "bsc-dataseed"],
        "polygon": ["polygon.", "matic.", "polygon-rpc"],
        "arbitrum": ["arb.", "arbitrum."],
        "optimism": ["optimism.", "op."],
        "base": ["base.", "base-mainnet"],
        "avalanche": ["avax.", "avalanche.", "snowtrace."],
        "fantom": ["fantom.", "ftm."],
        "gnosis": ["gnosis.", "xdai."],
        "linea": ["linea."],
        "zksync": ["zksync.", "era."],
        "scroll": ["scroll."],
        "mantle": ["mantle."],
        "celo": ["celo."],
        "moonbeam": ["moonbeam."],
    }
    for chain, pats in patterns.items():
        if any(p in url for p in pats):
            return chain
    return None
