"""Report generator — HTML, JSON, Markdown"""
import json
from pathlib import Path
from datetime import datetime
from typing import Dict, List

class ReportGenerator:
    def generate(self, findings: Dict, format: str = 'html', output: str = 'report.html') -> str:
        if format == 'html':
            return self._gen_html(findings, output)
        elif format == 'markdown':
            return self._gen_markdown(findings, output)
        elif format == 'json':
            return self._gen_json(findings, output)
        return ''
    
    def _gen_html(self, findings: Dict, output: str) -> str:
        target = findings.get('target', 'Unknown')
        contracts = findings.get('contracts', {})
        vulns = findings.get('vulnerabilities', [])
        
        critical = sum(1 for v in vulns if v.get('severity') == 'CRITICAL')
        high = sum(1 for v in vulns if v.get('severity') == 'HIGH')
        medium = sum(1 for v in vulns if v.get('severity') == 'MEDIUM')
        
        contracts_html = ""
        for addr, info in contracts.items():
            name = info.get('name', 'Unknown')
            size = info.get('code_size', 0)
            contracts_html += f"<tr><td><code>{addr}</code></td><td>{name}</td><td>{size}</td></tr>"
        
        vulns_html = ""
        for v in vulns:
            sev = v.get('severity', 'UNKNOWN')
            color = {'CRITICAL': 'red', 'HIGH': 'orange', 'MEDIUM': 'yellow', 'LOW': 'green'}.get(sev, 'gray')
            vulns_html += f'<div class="finding {sev}"><strong>[{sev}]</strong> {v.get("title", "")} — {v.get("description", "")}</div>'
        
        html = f"""<!DOCTYPE html>
<html>
<head>
    <title>DeFi Hunter Report — {target}</title>
    <style>
        body {{ font-family: sans-serif; margin: 2rem; background: #1a1a2e; color: #eee; }}
        h1 {{ color: #e94560; }}
        .summary {{ display: flex; gap: 1rem; margin: 1rem 0; }}
        .summary div {{ background: #16213e; padding: 1rem 2rem; border-radius: 8px; }}
        .summary h2 {{ margin: 0; font-size: 2rem; }}
        .summary span {{ color: #aaa; }}
        table {{ width: 100%; border-collapse: collapse; margin: 1rem 0; }}
        th, td {{ padding: 0.5rem; text-align: left; border-bottom: 1px solid #333; }}
        th {{ background: #16213e; }}
        code {{ background: #0f3460; padding: 0.2rem 0.5rem; border-radius: 4px; }}
        .finding {{ padding: 0.5rem; margin: 0.5rem 0; border-left: 4px solid; background: #16213e; }}
        .finding.CRITICAL {{ border-color: #e94560; }}
        .finding.HIGH {{ border-color: #f59e0b; }}
        .finding.MEDIUM {{ border-color: #fbbf24; }}
        .finding.LOW {{ border-color: #10b981; }}
    </style>
</head>
<body>
    <h1>🛡️ DeFi Hunter Report</h1>
    <p>Target: <strong>{target}</strong> | Generated: {datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
    
    <div class="summary">
        <div><h2>{critical}</h2><span>CRITICAL</span></div>
        <div><h2>{high}</h2><span>HIGH</span></div>
        <div><h2>{medium}</h2><span>MEDIUM</span></div>
        <div><h2>{len(contracts)}</h2><span>Contracts</span></div>
    </div>
    
    <h2>Contracts</h2>
    <table>
        <tr><th>Address</th><th>Name</th><th>Size</th></tr>
        {contracts_html}
    </table>
    
    <h2>Vulnerabilities</h2>
    {vulns_html}
</body>
</html>"""
        
        Path(output).write_text(html)
        return output
    
    def _gen_markdown(self, findings: Dict, output: str) -> str:
        target = findings.get('target', 'Unknown')
        lines = [f"# DeFi Hunter Report: {target}", ""]
        
        for v in findings.get('vulnerabilities', []):
            lines.append(f"- **[{v.get('severity')}] {v.get('title')}** — {v.get('description')}")
        
        Path(output).write_text('\n'.join(lines))
        return output
    
    def _gen_json(self, findings: Dict, output: str) -> str:
        Path(output).write_text(json.dumps(findings, indent=2))
        return output
