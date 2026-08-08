"""Attack simulator — fork-based simulation"""
import subprocess
from typing import Dict, List, Optional

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
