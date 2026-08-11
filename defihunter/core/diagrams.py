"""Mermaid diagram generation — call graph, storage layout, attack flow.

Produces Mermaid markup embedded directly in HTML/Markdown reports and
exported as .mmd files. No external renderer required — GitHub,
Mermaid Live Editor, and mermaid.ink render the markdown.

Diagrams:
  - call_graph:    contracts/functions in the scan → external calls
  - storage_layout: state variables per contract (from source when available)
  - attack_flow:   attacker → vulnerability → exploit → impact
"""
from __future__ import annotations

import re
from typing import Dict, List

SEV_COLORS = {
    "CRITICAL": "#f85149",
    "HIGH": "#d29922",
    "MEDIUM": "#3fb950",
    "LOW": "#8b949e",
    "INFO": "#58a6ff",
}


def _esc(text: str) -> str:
    """Escape characters that break Mermaid node labels."""
    return (str(text)
            .replace('"', "'")
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace("\n", " "))[:120]


def attack_flow(findings: List[Dict], target: str = "target") -> str:
    """Mermaid flowchart: attacker → vuln → exploit → impact for top findings."""
    top = sorted(findings, key=lambda f: SEV_COLORS.get(f.get("severity", "INFO"), "#888"))[:6]
    if not top:
        return ""

    lines = ["flowchart TD"]
    lines.append(f'    A["Attacker"]:::attacker')
    lines.append(f'    T["{_esc(target)}"]:::target')
    for i, f in enumerate(top, 1):
        sev = f.get("severity", "INFO")
        title = _esc(f.get("title", "finding"))
        attack = _esc(f.get("attack", "unknown"))
        lines.append(f'    V{i}["{sev} — {title}"]:::{sev.lower()}')
        lines.append(f'    E{i}["{_esc(f.get("endpoint", ""))}"]:::loc')
        lines.append(f'    A -->|"{attack}"| V{i}')
        lines.append(f'    V{i} --> E{i}')
        lines.append(f'    E{i} --> T')

    lines.append("")
    lines.append("classDef attacker fill:#f85149,stroke:#f85149,color:#fff,font-weight:bold;")
    lines.append("classDef target fill:#161b22,stroke:#58a6ff,color:#e6edf3;")
    for sev in SEV_COLORS:
        lines.append(f"classDef {sev.lower()} fill:{SEV_COLORS[sev]}22,stroke:{SEV_COLORS[sev]},color:#e6edf3;")
    lines.append("classDef loc fill:#21262d,stroke:#30363d,color:#8b949e;")
    return "\n".join(lines)


def call_graph(contracts: Dict[str, Dict], findings: List[Dict], target: str = "target") -> str:
    """Mermaid flowchart: contracts → calls/attacks between them."""
    lines = ["flowchart LR"]
    lines.append(f'    T["{_esc(target)}"]:::root')

    seen = set()
    for addr, info in list(contracts.items())[:12]:
        name = info.get("name", addr[:8])
        node = f'C_{re.sub(r"[^A-Za-z0-9_]", "_", str(addr))[:24]}'
        lines.append(f'    {node}["{_esc(name)}"]:::contract')
        lines.append(f'    T --> {node}')

    for i, f in enumerate(findings[:10], 1):
        sev = f.get("severity", "INFO")
        attack = _esc(f.get("attack", "finding"))
        title = _esc(f.get("title", ""))
        node = f"F{i}"
        lines.append(f'    {node}["{_esc(sev)} {_esc(attack)}: {title}"]:::{sev.lower()}')
        addr = f.get("address") or f.get("contract")
        if addr and addr in contracts:
            cnode = f'C_{re.sub(r"[^A-Za-z0-9_]", "_", str(addr))[:24]}'
            lines.append(f'    {cnode} --> {node}')
        else:
            lines.append(f'    T --> {node}')

    lines.append("")
    lines.append("classDef root fill:#161b22,stroke:#58a6ff,color:#e6edf3,font-weight:bold;")
    lines.append("classDef contract fill:#161b22,stroke:#30363d,color:#e6edf3;")
    for sev in SEV_COLORS:
        lines.append(f"classDef {sev.lower()} fill:{SEV_COLORS[sev]}22,stroke:{SEV_COLORS[sev]},color:#e6edf3;")
    return "\n".join(lines)


def storage_layout(sources: List[str], label: str = "contract") -> str:
    """Mermaid flowchart of state variable storage slots from Solidity source."""
    lines = ["flowchart TD"]
    lines.append(f'    S["{_esc(label)} storage"]:::storage')
    slot = 0
    # Match state variable declarations (type name; or type name = ...) but
    # not locals/functions. Operates on the whole (comment-stripped) source
    # so single-line contracts and multi-line ones both work.
    var_pattern = re.compile(
        r"\b(?:address|uint\d*|int\d*|bool|bytes\d*|string|mapping\s*\([^;{}]+?\))\s+"
        r"([A-Za-z_]\w*)\s*(?:=|;|{|,)", re.MULTILINE)
    for src in sources:
        body = re.sub(r"/\*.*?\*/|//[^\n]*", " ", src, flags=re.DOTALL)
        for m in var_pattern.finditer(body):
            name = m.group(1)
            if name in {"if", "for", "while", "return"}:
                continue
            # Skip function-local declarations: only treat vars at brace
            # depth <= 1 (contract/module scope) as storage slots.
            depth = body[: m.start()].count("{") - body[: m.start()].count("}")
            if depth > 1:
                continue
            node = f"V{slot}"
            lines.append(f'    {node}["slot {slot}: {_esc(name)}"]:::var')
            lines.append(f"    S --> {node}")
            slot += 1
            if slot >= 14:
                break
        if slot >= 14:
            break
    if slot == 0:
        return ""
    lines.append("")
    lines.append("classDef storage fill:#161b22,stroke:#d29922,color:#e6edf3,font-weight:bold;")
    lines.append("classDef var fill:#21262d,stroke:#30363d,color:#8b949e;")
    return "\n".join(lines)


def render_diagram_markdown(kind: str, target: str = "target", contracts: Dict = None,
                            findings: List[Dict] = None, sources: List[str] = None) -> str:
    """Return a fenced ```mermaid``` block for embedding in Markdown."""
    if kind == "attack_flow":
        body = attack_flow(findings or [], target)
    elif kind == "call_graph":
        body = call_graph(contracts or {}, findings or [], target)
    elif kind == "storage_layout":
        body = storage_layout(sources or [], target)
    else:
        return ""
    if not body:
        return ""
    return f"```mermaid\n{body}\n```"
