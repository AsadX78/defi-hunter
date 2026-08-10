"""Live Fork — direct `eth_call` with state overrides via JSON-RPC.

No Anvil, no Foundry, no local process. Every "fork" operation is a single
RPC call to the real mainnet endpoint with state overrides injected on-the-fly.

How it works:
    1. Read the contract's real bytecode + storage from the live chain.
    2. Override the attacker's balance to 100 ETH (so they can "send" txs).
    3. Call `eth_call` with `stateOverrides` — the node simulates the tx
       against the real chain state with the overridden attacker balance.
    4. If the call reverts → REFUTED. If it succeeds → read resulting state
       (balanceOf, owner, allowance) to prove the exploit.

For reentrancy detection (multi-call traces):
    Use `trace_call` (Parity/OpenEthereum/Geth trace API) which returns
    the full call tree including nested calls. A reentrancy shows as
    repeated calls to the target within a single top-level call.

Performance:
    - Anvil: ~2-4s startup + 1-2s per fork operation = ~5-6s total
    - LiveFork: ~0.3-1s per RPC call = ~1-3s total (no startup)

Requirements:
    - Any Ethereum JSON-RPC endpoint (Alchemy, Infura, public RPC)
    - No external tools (no cast, no anvil, no solc)
"""

import json
import subprocess
from typing import Any, Dict, List, Optional

# Default attacker balance for simulation (100 ETH in wei)
DEFAULT_BALANCE = "0x56BC75E2D63100000"  # 100 * 10^18

# ABI selector → human-readable mapping for common attack functions
SELECTOR_MAP = {
    "0x40c10f19": "mint(address,uint256)",
    "0x1cf5d2a8": "initialize(address)",
    "0xfe4b84df": "initialize()",
    "0xd505accf": "permit(address,address,uint256,uint256,uint8,bytes32,bytes32)",
    "0x095ea7b3": "approve(address,uint256)",
    "0xa9059cbb": "transfer(address,uint256)",
    "0x23b872dd": "transferFrom(address,address,uint256)",
    "0x8da5cb5b": "owner()",
    "0xf2fde38b": "transferOwnership(address)",
    "0x3659cfe6": "upgradeTo(address)",
    "0x4f1ef286": "upgradeToAndCall(address,bytes)",
    "0x5cffe9de": "flashLoan(address,address,uint256,bytes)",
    "0x1f00ca74": "flashLoanSimple(address,address,uint256,bytes)",
    "0x3ccfd60b": "withdraw(uint256)",
    "0x2e1a7d4d": "withdraw(uint256)",
    "0xb6b55f25": "deposit()",
    "0x70a08231": "balanceOf(address)",
    "0xdd62ed3e": "allowance(address,address)",
    "0x18160ddd": "totalSupply()",
    "0x01e1d114": "totalAssets()",
    "0x883bdbfd": "getReserves()",
    "0x0902f1ac": "getReserves()",  # UniswapV2
    "0xf7729d43": "slot0()",
    "0x50d25bcd": "latestAnswer()",
    "0xfeaf968c": "latestRoundData()",
}


class LiveFork:
    """Direct eth_call with state overrides — no Anvil, no Foundry.

    Usage:
        with LiveFork(rpc_url="https://eth.llamarpc.com") as fork:
            result = fork.call_with_override(
                target="0x1234...",
                selector="mint(address,uint256)",
                args=["0xattacker...", "1000000000000000000000"],
                attacker="0xattacker...",
            )
            if result["ok"]:
                print("Transaction succeeded!")
    """

    def __init__(self, rpc_url: str, block: Optional[int] = None,
                 attacker: Optional[str] = None):
        self.rpc_url = rpc_url
        self.block = block
        self.attacker = attacker or "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
        self.available = False
        self.why_not = ""
        self.chain_id = None

    def __enter__(self) -> "LiveFork":
        # Verify the RPC endpoint is reachable
        try:
            resp = self._rpc("eth_chainId", [])
            self.chain_id = int(resp, 16)
            self.available = True
        except Exception as e:
            self.why_not = f"Live fork failed: RPC unreachable ({e})"
        return self

    def __exit__(self, *a) -> None:
        pass  # No cleanup needed — no process to kill

    # ------------------------------------------------------------------
    # Core JSON-RPC transport
    # ------------------------------------------------------------------

    def _rpc(self, method: str, params: list) -> Any:
        """Single JSON-RPC call via curl (zero Python dependencies)."""
        payload = json.dumps({
            "jsonrpc": "2.0",
            "id": 1,
            "method": method,
            "params": params,
        })
        proc = subprocess.run(
            ["curl", "-s", "-X", "POST",
             "-H", "Content-Type: application/json",
             "-d", payload,
             self.rpc_url],
            capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            raise RuntimeError(f"curl failed: {proc.stderr[:200]}")
        data = json.loads(proc.stdout)
        if "error" in data:
            raise RuntimeError(f"RPC error: {data['error']}")
        return data["result"]

    def _rpc_batch(self, calls: list) -> list:
        """Batch multiple JSON-RPC calls in one HTTP request."""
        batch = [{"jsonrpc": "2.0", "id": i + 1, "method": m, "params": p}
                 for i, (m, p) in enumerate(calls)]
        payload = json.dumps(batch)
        proc = subprocess.run(
            ["curl", "-s", "-X", "POST",
             "-H", "Content-Type: application/json",
             "-d", payload,
             self.rpc_url],
            capture_output=True, text=True, timeout=30)
        if proc.returncode != 0:
            raise RuntimeError(f"curl batch failed: {proc.stderr[:200]}")
        data = json.loads(proc.stdout)
        # Sort by id to match request order
        results = sorted(data, key=lambda x: x.get("id", 0))
        return [r.get("result") for r in results]

    # ------------------------------------------------------------------
    # State reads (live chain, no override)
    # ------------------------------------------------------------------

    def get_balance(self, address: str, block: Optional[int] = None) -> int:
        """Read ETH balance from the live chain."""
        tag = hex(block) if block else "latest"
        result = self._rpc("eth_getBalance", [address, tag])
        return int(result, 16)

    def get_code(self, address: str, block: Optional[int] = None) -> str:
        """Read bytecode from the live chain."""
        tag = hex(block) if block else "latest"
        return self._rpc("eth_getCode", [address, tag])

    def has_code(self, address: str) -> bool:
        code = self.get_code(address)
        return bool(code and code not in ("0x", "0x0"))

    def get_block_number(self) -> int:
        result = self._rpc("eth_blockNumber", [])
        return int(result, 16)

    # ------------------------------------------------------------------
    # eth_call with state overrides
    # ------------------------------------------------------------------

    def call_with_override(
        self,
        target: str,
        selector: str,
        args: List[str],
        attacker: Optional[str] = None,
        value: Optional[str] = None,
        balance_override: str = DEFAULT_BALANCE,
    ) -> Dict:
        """Execute eth_call with state overrides — the core of live forking.

        The attacker's ETH balance is overridden to `balance_override`
        (default 100 ETH) so they can "send" transactions that require gas.
        The target contract reads from the real chain state.

        Returns:
            {"ok": True, "return": "0x...", "revert": None} on success
            {"ok": False, "return": None, "revert": "..."} on revert
        """
        attacker = attacker or self.attacker

        # Build calldata: selector + abi-encoded args
        calldata = selector
        for arg in args:
            calldata += self._pad_arg(arg)

        # State override: give attacker 100 ETH
        state_overrides = {
            attacker: {
                "balance": balance_override,
            }
        }

        call_obj = {
            "from": attacker,
            "to": target,
            "data": calldata,
        }
        if value:
            call_obj["value"] = value

        tag = hex(self.block) if self.block else "latest"

        try:
            result = self._rpc("eth_call", [
                call_obj,
                tag,
                state_overrides,  # <-- this is the magic
            ])
            # Check if result is a revert (0x or empty = success, otherwise
            # check for Error(string) selector)
            if result and result != "0x":
                # Check for Panic(uint256) or Error(string) revert
                if result.startswith("0x08c379a0") or result.startswith("0x4e487b71"):
                    error_msg = self._decode_revert(result)
                    return {"ok": False, "return": None, "revert": error_msg}
            return {"ok": True, "return": result, "revert": None}
        except RuntimeError as e:
            # Cast-style revert detection: eth_call may throw
            err_str = str(e)
            if "revert" in err_str.lower() or "execution reverted" in err_str.lower():
                return {"ok": False, "return": None, "revert": err_str[:200]}
            return {"ok": False, "return": None, "revert": err_str[:200]}

    def call_raw(self, target: str, selector: str,
                 args: List[str] = None, from_addr: str = None) -> Dict:
        """eth_call WITHOUT state overrides — reads real chain state.

        Use this for read-only calls (balanceOf, owner, allowance, etc.)
        where we don't need to fake the caller's balance.
        """
        calldata = selector
        for arg in (args or []):
            calldata += self._pad_arg(arg)

        call_obj = {"to": target, "data": calldata}
        if from_addr:
            call_obj["from"] = from_addr

        tag = hex(self.block) if self.block else "latest"

        try:
            result = self._rpc("eth_call", [call_obj, tag])
            return {"ok": True, "return": result}
        except Exception as e:
            return {"ok": False, "return": None, "error": str(e)[:200]}

    # ------------------------------------------------------------------
    # trace_call — full execution trace for reentrancy detection
    # ------------------------------------------------------------------

    def trace_call(
        self,
        target: str,
        selector: str,
        args: List[str],
        attacker: Optional[str] = None,
        value: Optional[str] = None,
        balance_override: str = DEFAULT_BALANCE,
    ) -> Dict:
        """Execute eth_call + trace_call to get the full call tree.

        Returns:
            {"ok": True, "calls": [...], "revert": None} with nested calls
            {"ok": False, "calls": [], "revert": "..."} on revert

        The `calls` list contains every internal call in execution order,
        including nested re-entrant calls. Each call has:
            {"type": "CALL"/"DELEGATECALL"/etc", "from", "to", "input", "output", "revert"}
        """
        attacker = attacker or self.attacker

        calldata = selector
        for arg in args:
            calldata += self._pad_arg(arg)

        state_overrides = {attacker: {"balance": balance_override}}
        tag = hex(self.block) if self.block else "latest"

        call_obj = {
            "from": attacker,
            "to": target,
            "data": calldata,
        }
        if value:
            call_obj["value"] = value

        try:
            result = self._rpc("trace_call", [
                call_obj,
                ["trace"],  # trace type
                tag,
                state_overrides,
            ])
            calls = result.get("output", {}).get("calls", []) if isinstance(result.get("output"), dict) else []
            return {"ok": True, "calls": calls, "revert": result.get("output", {}).get("revert")}
        except RuntimeError as e:
            # trace_call not supported by this node — fall back to basic eth_call
            return {"ok": False, "calls": [], "revert": str(e)[:200],
                    "fallback_to_eth_call": True}
        except Exception as e:
            return {"ok": False, "calls": [], "revert": str(e)[:200]}

    # ------------------------------------------------------------------
    # Multi-call batch read
    # ------------------------------------------------------------------

    def batch_call(self, calls: List[Dict]) -> List[Dict]:
        """Batch multiple eth_call reads in one HTTP request.

        Each call: {"target": "0x...", "selector": "0x...", "args": [...]}
        Returns list of {"ok": bool, "return": str|None}
        """
        rpc_calls = []
        for call in calls:
            calldata = call["selector"]
            for arg in call.get("args", []):
                calldata += self._pad_arg(arg)
            rpc_calls.append(("eth_call", [
                {"to": call["target"], "data": calldata},
                hex(self.block) if self.block else "latest",
            ]))
        results = self._rpc_batch(rpc_calls)
        return [{"ok": r is not None, "return": r} for r in results]

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _pad_arg(arg: str) -> str:
        """Pad a single ABI argument to 32 bytes."""
        arg = arg.strip()
        if arg.startswith("0x"):
            # Address or bytes — pad to 32 bytes (left-padded for address)
            return arg[2:].lower().zfill(64)
        else:
            # uint256 — convert to hex, pad to 32 bytes
            try:
                val = int(arg)
                return hex(val)[2:].zfill(64)
            except ValueError:
                return "0" * 64

    @staticmethod
    def _decode_revert(data: str) -> str:
        """Decode Error(string) revert reason."""
        try:
            if data.startswith("0x08c379a0"):
                # Error(string): skip selector (4 bytes) + offset (32 bytes) + length (32 bytes)
                encoded = data[10:]  # skip 0x08c379a0
                if len(encoded) >= 128:
                    length = int(encoded[64:128], 16)
                    hex_str = encoded[128:128 + length * 2]
                    return bytes.fromhex(hex_str).decode("utf-8", errors="replace")
            elif data.startswith("0x4e487b71"):
                # Panic(uint256)
                if len(data) >= 74:
                    code = int(data[10:74], 16)
                    panics = {0: " compiler bug", 1: "assertion failure",
                              17: "arithmetic overflow", 18: "division by zero",
                              33: "enum conversion", 34: "invalid storage struct",
                              49: "pop on empty array", 50: "out-of-bounds array access",
                              65: "too much memory", 81: "uninitialized function pointer"}
                    return f"Panic({code}){panics.get(code, '')}"
        except Exception:
            pass
        return f"revert: {data[:100]}..."

    def get_chain_name(self) -> str:
        """Map chain ID to human-readable name."""
        names = {
            1: "Ethereum", 56: "BSC", 137: "Polygon",
            42161: "Arbitrum", 10: "Optimism", 8453: "Base",
            43114: "Avalanche", 250: "Fantom", 100: "Gnosis",
            59144: "Linea", 324: "zkSync", 534352: "Scroll",
        }
        return names.get(self.chain_id, f"Chain {self.chain_id}")
