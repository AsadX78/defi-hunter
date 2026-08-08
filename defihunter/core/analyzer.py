"""Contract analyzer — detect vulnerabilities from source code"""
import re
import subprocess
from typing import Dict, List, Optional

def run(cmd: str, timeout: int = 30) -> str:
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return result.stdout.strip()

class ContractAnalyzer:
    def __init__(self, rpc_url: Optional[str] = None):
        self.rpc_url = rpc_url or ''
    
    def analyze(self, address: str) -> List[Dict]:
        """Analyze a contract for vulnerabilities"""
        findings = []
        
        # Get source code
        source = self._get_source(address)
        
        if source:
            # Pattern-based detection
            findings.extend(self._scan_patterns(source, address))
            
            # Interface-based detection
            findings.extend(self._scan_interface(address))
        
        return findings
    
    def _get_source(self, address: str) -> str:
        """Get verified source from Etherscan"""
        import os
        api_key = os.getenv('ETHERSCAN_API_KEY', '')
        if not api_key:
            return ''
        
        url = f"https://api.etherscan.io/v2/api?chainid=1&module=contract&action=getsourcecode&address={address}&apikey={api_key}"
        result = run(f'curl -sL "{url}"')
        
        try:
            import json
            data = json.loads(result)
            if data.get('status') == '1':
                return data['result'][0].get('SourceCode', '')
        except:
            pass
        
        return ''
    
    def _scan_patterns(self, source: str, address: str) -> List[Dict]:
        """Scan source code for vulnerability patterns"""
        findings = []
        
        # Reentrancy patterns
        if self._check_pattern(source, [
            r'\.call\{value:[^}]+\}\(',
            r'transfer\(',
            r'send\(',
        ]):
            findings.append({
                'title': 'Potential Reentrancy',
                'severity': 'CRITICAL',
                'description': 'External call detected — check if state is updated after',
                'contract': address,
            })
        
        # Admin without timelock
        if self._check_pattern(source, [
            r'function\s+file\s*\(',
            r'mapping\s*\(\s*address\s*=>\s*uint',
            r'auth\s*\{',
        ]):
            findings.append({
                'title': 'Unprotected Admin Function',
                'severity': 'HIGH',
                'description': 'Admin function without timelock detected',
                'contract': address,
            })
        
        # Inflation attack
        if self._check_pattern(source, [
            r'shares\s*=.*totalSupply.*balance',
            r'shares\s*=.*totalSupply.*totalAssets',
        ]):
            findings.append({
                'title': 'First Deposit Inflation Attack',
                'severity': 'HIGH',
                'description': 'Share calculation uses balance directly — vulnerable to donation attack',
                'contract': address,
            })
        
        # Proxy upgrade
        if self._check_pattern(source, [
            r'upgradeTo',
            r'_authorizeUpgrade',
            r'UUPS',
            r'ERC1967',
        ]):
            findings.append({
                'title': 'Upgradeable Proxy',
                'severity': 'HIGH',
                'description': 'Contract is upgradeable — admin can change logic',
                'contract': address,
            })
        
        return findings
    
    def _scan_interface(self, address: str) -> List[Dict]:
        """Analyze contract interface for risks"""
        findings = []
        
        if not self.rpc_url:
            return findings
        
        code = run(f'cast code {address} --rpc-url {self.rpc_url} 2>/dev/null')
        if not code:
            return findings
        
        # Check for deposit/withdraw (vault contract)
        has_deposit = '6e553f65' in code or 'b6b55f25' in code
        has_withdraw = any(s in code for s in ['2e1a7d4d', '00f714ce', 'c23a4d79'])
        has_drip = 'd370ff70' in code
        has_admin = any(s in code for s in ['bf353dbb', '65fae35e', '9c52a7f1'])
        
        if has_deposit and has_withdraw:
            findings.append({
                'title': 'Vault Contract Detected',
                'severity': 'INFO',
                'description': 'Has deposit/withdraw — check for inflation attack',
                'contract': address,
            })
        
        if has_drip:
            findings.append({
                'title': 'Drip Function Detected',
                'severity': 'MEDIUM',
                'description': 'Has drip() — check access control and yield accumulation',
                'contract': address,
            })
        
        if has_admin:
            findings.append({
                'title': 'Access Control Detected',
                'severity': 'MEDIUM',
                'description': 'Has wards/rely/deny — check for timelock',
                'contract': address,
            })
        
        return findings
    
    def _check_pattern(self, source: str, patterns: List[str]) -> bool:
        for pattern in patterns:
            if re.search(pattern, source, re.IGNORECASE | re.MULTILINE):
                return True
        return False
