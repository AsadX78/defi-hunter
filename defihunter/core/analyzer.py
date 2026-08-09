"""Contract analyzer — detect vulnerabilities from source code"""
import re
import subprocess
from pathlib import Path
from typing import Dict, List, Optional

def run(cmd: str, timeout: int = 30) -> str:
    result = subprocess.run(cmd, shell=True, capture_output=True, text=True, timeout=timeout)
    return result.stdout.strip()

# ---------------------------------------------------------------------------
# Source-level static analysis (local clone) — line-aware, file:line evidence.
# This is the "step up" from scanning: it turns a cloned repo into concrete
# findings with severity + attack route, no Etherscan key required.
# ---------------------------------------------------------------------------

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}

# Directories that never hold the protocol's own source.
SKIP_DIRS = {".git", "lib", "node_modules", "out", "cache", "test", "tests",
             "mocks", "mock", "mocks/", "script/deploy", "foundry_deployments"}

# Access-control signals that make a guarded mint/initialize legitimate.
# NOTE: bare 'owner'/'sender' are deliberately absent — an owner_ parameter
# does not protect a function, only modifiers/checks do.


def _iter_sol_files(repo_dir: Path) -> List[Path]:
    """All .sol files that belong to the protocol itself (skip vendored dirs)."""
    out: List[Path] = []
    for path in repo_dir.rglob("*.sol"):
        rel = path.relative_to(repo_dir)
        parts = set(rel.parts)
        if parts & SKIP_DIRS:
            continue
        if "script" in parts and not parts & {"src", "contracts"}:
            continue  # deploy scripts are tooling, not the attack surface
        out.append(path)
    return sorted(out)


def _func_header(lines: List[str], start: int) -> str:
    """Join a function signature across continuation lines up to the '{'."""
    header = lines[start].strip()
    for j in range(start + 1, min(start + 6, len(lines))):
        header += " " + lines[j].strip()
        if "{" in lines[j]:
            break
    return header


def _function_context(lines: List[str], start: int) -> str:
    """Signature + first lines of the body — the context that proves a guard."""
    ctx = _func_header(lines, start)
    for j in range(start + 1, min(start + 9, len(lines))):
        ctx += " " + lines[j].strip()
    return ctx


def _is_guarded(ctx: str) -> bool:
    """True when a function shows an access-control signal.

    Modifiers/guards that actually protect a function: only* modifiers,
    OZ initializer guards, require()/hasRole/_checkRole/_msgSender checks.
    NOTE: bare 'owner'/'sender' are intentionally NOT guards — an owner_
    parameter is normal and does not protect the function.
    """
    return bool(re.search(
        r"only[A-Z]\w*|initializer\b|onlyInitializing|whenNotInitialized|"
        r"whenNotPaused|require\s*\(|_msgSender|hasRole\s*\(|_checkRole\s*\(",
        ctx))


def _is_interface(rel: str) -> bool:
    """True for pure interface files — declarations only, no bodies to attack.

    Two conventions: an `interfaces/` directory, or a PascalCase file name
    starting with `I` (IStrategyManager.sol, IERC20.sol). Reporting HIGH
    findings on these is a false positive — an interface cannot implement
    anything, so there is nothing to exploit.
    """
    if "/interfaces/" in f"/{rel}":
        return True
    return bool(re.match(r"^I[A-Z][A-Za-z0-9]*\.sol$", Path(rel).name))


def analyze_file(path: Path) -> List[Dict]:
    """Line-aware vulnerability scan of one Solidity file."""
    rel = str(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    if _is_interface(rel):
        return []  # declarations only — pattern findings would be false positives
    lines = text.splitlines()
    findings: List[Dict] = []
    add = lambda sev, title, attack, line, desc: findings.append({
        "severity": sev, "title": title, "file": rel, "line": line,
        "snippet": lines[line - 1].strip()[:140],
        "endpoint": f"{rel}:{line}", "attack": attack, "description": desc,
    })

    for i, line in enumerate(lines):
        ln = i + 1
        if re.search(r"selfdestruct\s*\(|suicide\s*\(", line):
            add("CRITICAL", "selfdestruct — kill switch in source", "admin", ln,
                "Any holder of the calling privilege can destroy the contract and "
                "force-send its balance. Verify the modifier is timelocked/DAO-gated.")
        if re.search(r"\btx\.origin\b", line):
            add("HIGH", "tx.origin used for authorization", "admin", ln,
                "tx.origin checks are bypassable via phishing (malicious contract "
                "calls in the victim's name). Only safe when explicitly negated.")
        if re.search(r"\.delegatecall\s*\(", line):
            add("HIGH", "delegatecall — verify target trust", "delegatecall", ln,
                "Runs callee code in THIS contract's storage/context. If the target "
                "is user-controlled or unauthenticated, it's a full takeover.")
        if re.search(r"\.call\s*\{value:", line) or re.search(r"\.transfer\s*\(|\.send\s*\(", line):
            add("MEDIUM", "external ETH call — check CEI ordering", "reentrancy", ln,
                "External call before state updates enables reentrancy. Confirm "
                "checks-effects-interactions order or a reentrancy guard.")
        if re.search(r"\.slot0\s*\(|getReserves\s*\(", line):
            add("MEDIUM", "spot price source (flash-loan manipulable)", "oracle", ln,
                "Reading Uniswap slot0/reserves gives the current spot price — "
                "manipulable in one block. Prefer a TWAP/Chainlink feed.")
        if re.search(r"\bblock\.timestamp\b|\bnow\b", line):
            add("LOW", "timestamp-dependent logic", None, ln,
                "block.timestamp can be skewed by miners/validators by a few "
                "seconds — dangerous if it gates critical state changes.")
        if re.search(r"\b(?:0x)?[0-9a-fA-F]{64}\b", line):
            add("HIGH", "possible hardcoded private key / 64-hex secret", None, ln,
                "A 64-hex literal in source is a private key or secret hash. "
                "Rotate anything that matches and move it to env/secrets.")
        if re.search(r"PRIVATE_KEY\s*=|private\s+key\s*[:=]", line, re.IGNORECASE):
            add("HIGH", "private key assigned in source", None, ln,
                "A private key literal in committed code is compromised. Move to "
                "env vars / a secrets manager and rotate immediately.")

    # Multi-line heuristics
    for i, line in enumerate(lines):
        ln = i + 1
        if re.search(r"function\s+mint\s*\(", line):
            ctx = _function_context(lines, i)
            if not _is_guarded(ctx):
                add("HIGH", "mint() without visible access control", "mint", ln,
                    "Anyone may be able to mint unlimited supply. Verify the "
                    "modifier/role check — if absent, fork-simulate mint() as an "
                    "attacker to confirm.")
        if re.search(r"function\s+initialize\s*\(", line):
            ctx = _function_context(lines, i)
            if not _is_guarded(ctx):
                add("HIGH", "initialize() without initializer guard", "initialize", ln,
                    "On an upgradeable proxy, an unguarded initialize() lets the "
                    "FIRST caller become owner. Confirm the implementation guard "
                    "(initializer/onlyInitializing) exists.")
    return findings


def analyze_repo_dir(repo_dir: str, repo_label: str = "") -> List[Dict]:
    """Scan every protocol-owned .sol file in a cloned repo.

    Returns findings sorted by severity (CRITICAL first), each with file:line
    evidence and an attack tag chained to the wizard's attack menu.
    """
    root = Path(repo_dir)
    if not root.is_dir():
        return []
    findings: List[Dict] = []
    for sol in _iter_sol_files(root):
        findings.extend(analyze_file(sol))
    for f in findings:
        f["file"] = str(Path(f["file"]).relative_to(root))
        f["endpoint"] = f"{f['file']}:{f['line']}"
        if repo_label:
            f["repo"] = repo_label
    return sorted(findings, key=lambda f: SEVERITY_ORDER.get(f["severity"], 99))

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
