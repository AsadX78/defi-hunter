"""Contract analyzer — detect vulnerabilities from source code"""
import re
import subprocess
from pathlib import Path
from tempfile import TemporaryDirectory
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


# 64-hex literals that are PUBLIC, documented values — NOT private keys.
# (a) EIP-1967 proxy storage slots (keccak of "eip1967.proxy.{impl,admin,beacon}")
#     are public constants printed in every proxy implementation.
# (b) Padded function selectors: 0x<4-byte-selector> + 56 zero-bytes appear in
#     inline-assembly mstore() calls (e.g. an ERC20's transfer selector).
# Without these exclusions the rule flags audited contracts (MORPHO token,
# Uniswap Permit2) for constants that are public by design.
_KNOWN_PUBLIC_64HEX = {
    "360894a13ba1a3210667c828492db98dca3e2076cc3735a920a3ca505d382bbc",  # eip1967.implementation
    "b53127684a568b3173ae13b9f8a6016e243e63b6e8ee1178d6a717850b5d6103",  # eip1967.admin
    "a3f0ad74e5423aebfd80d3ef4346578335a9a72aeaee59ff6cb3582b35133d50",  # eip1967.beacon
}


def _is_public_literal(line: str) -> bool:
    """True if the line's 64-hex literal is a documented constant (proxy slot,
    padded function selector, or bitmask), not a leaked private key."""
    for m in re.finditer(r"\b(?:0x)?[0-9a-fA-F]{64}\b", line):
        hx = m.group(0)
        if hx.lower().startswith("0x"):
            hx = hx[2:]
        hx = hx.lower()
        if hx in _KNOWN_PUBLIC_64HEX:
            return True
        if re.fullmatch(r"[0-9a-fA-F]{8}0{48,}", hx):
            return True  # 4-byte selector zero-padded to 32 bytes
        if hx.count("f") >= 56 or hx.count("0") == 64:
            return True  # bitmask (e.g. 0x7fff…ff UPPER_BIT_MASK) or zero value
    return False


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

    Comments are stripped first: "// no onlyOwner" describes the code, it
    does not guard it — comment text must never count as guard evidence.
    """
    ctx = _strip_comments(ctx)
    return bool(re.search(
        r"only[A-Z]\w*|initializer\b|onlyInitializing|whenNotInitialized|"
        r"whenNotPaused|require\s*\(|_msgSender|hasRole\s*\(|_checkRole\s*\(",
        ctx))


def _strip_comments(text: str) -> str:
    """Remove /* */ block comments and // line comments from Solidity text."""
    text = re.sub(r"/\*.*?\*/", " ", text, flags=re.DOTALL)
    text = re.sub(r"//[^\n]*", " ", text)
    return text


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
        if re.search(r"\.call\s*\{value:", line) or re.search(
                r"(?:payable\s*\([^)]*\)|msg\.sender|address\s*\([^)]*\))\.(?:transfer|send)\s*\(", line):
            add("MEDIUM", "external ETH call — check CEI ordering", "reentrancy", ln,
                "External ETH call before state updates enables reentrancy. "
                "Confirm checks-effects-interactions order or a reentrancy guard.")
        if re.search(r"\.slot0\s*\(|getReserves\s*\(", line):
            add("MEDIUM", "spot price source (flash-loan manipulable)", "oracle", ln,
                "Reading Uniswap slot0/reserves gives the current spot price — "
                "manipulable in one block. Prefer a TWAP/Chainlink feed.")
        if re.search(r"\bblock\.timestamp\b|\bnow\b", line):
            add("LOW", "timestamp-dependent logic", None, ln,
                "block.timestamp can be skewed by miners/validators by a few "
                "seconds — dangerous if it gates critical state changes.")
        if re.search(r"\b(?:0x)?[0-9a-fA-F]{64}\b", line) and not _is_public_literal(line):
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
        """Analyze a contract from its Etherscan-verified source.

        Runs the SAME line-aware engine as repo scans (analyze_file), so
        findings carry file:line evidence, snippets and an attack route —
        which lets the wizard fork-verify them against the live address.
        A proxy/delegate pattern is reported as a LOW note (proxies are
        legitimate; the real question — who can upgrade — is answered by
        the fork proof, not by screaming HIGH).

        Address-only scans used to run crude source regexes that flagged
        ANY `.transfer(` as CRITICAL "Potential Reentrancy" (an ERC20's
        own transfer()!) — that noise is gone.
        """
        findings = []
        source = self._get_source(address)
        if not source:
            return findings
        for idx, text in enumerate(_source_texts(source)):
            with TemporaryDirectory(prefix="defihunter-src-") as td:
                path = Path(td, f"Contract{idx}.sol")
                path.write_text(text, encoding="utf-8", errors="replace")
                for f in analyze_file(path):
                    f["address"] = address
                    f["contract"] = address
                    f["endpoint"] = address
                    findings.append(f)
        if re.search(r"_delegate\s*\(|implementation\s*\(\).*ERC1967|"
                     r"upgradeTo|ERC1967|UUPS|diamond|fallback\s*\(\)\s*.*delegatecall",
                     source, re.IGNORECASE):
            findings.append({
                "severity": "LOW",
                "title": "upgradeable proxy pattern — verify upgrade authority",
                "attack": "delegatecall",
                "description": "Contract routes calls through a proxy/delegate "
                               "pattern. Legitimate by design — the fork proof "
                               "checks whether an arbitrary account can actually "
                               "upgrade it.",
                "file": address, "line": 0, "snippet": "",
                "address": address, "contract": address,
                "endpoint": address,
            })
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


def _source_texts(source: str) -> List[str]:
    """Split an Etherscan SourceCode blob into analyzable Solidity texts.

    Etherscan returns either a plain (flattened) .sol file or a
    standard-json-input blob. For the JSON case it can be wrapped in an
    EXTRA pair of braces ({{"language":"Solidity",...}}) — unwrap that
    before parsing. The unified analyzer needs the per-file source
    bodies, not the JSON wrapper.
    """
    if not source.startswith("{"):
        return [source]
    candidate = source[1:-1] if source.startswith("{{") else source
    try:
        import json
        data = json.loads(candidate)
        sources = (data or {}).get("sources", {})
        texts = [v.get("content", "") for v in sources.values()
                 if isinstance(v, dict) and v.get("content")]
        return texts or [source]
    except Exception:
        return [source]
    
