"""DeFi Hunter — UI layer.

Central place for all terminal output: colors, panels, tables, spinners and
the CLI banner. Every command in cli.py should render through here so the
look & feel stays consistent while the rest of the toolkit grows.

Depends only on `rich` — no core logic lives here.
"""
from __future__ import annotations

import time
from contextlib import contextmanager
from typing import Any, Dict, Iterable, Optional, Sequence

from rich.console import Console, Group
from rich.panel import Panel
from rich.progress import (
    BarColumn,
    Progress,
    SpinnerColumn,
    TaskProgressColumn,
    TextColumn,
    TimeElapsedColumn,
)
from rich.spinner import Spinner
from rich.table import Table
from rich.text import Text
from rich.theme import Theme
from rich import box

# ---------------------------------------------------------------------------
# Theme
# ---------------------------------------------------------------------------
THEME = Theme(
    {
        "banner": "bold cyan",
        "cmd": "bold white",
        "step": "bold bright_blue",
        "ok": "bold green",
        "warn": "bold yellow",
        "err": "bold red",
        "muted": "dim",
        "addr": "cyan",
        "accent": "magenta",
        "success": "bold green",
        "fail": "bold red",
        # severity colors
        "sev.CRITICAL": "bold white on red",
        "sev.HIGH": "bold red",
        "sev.MEDIUM": "bold yellow",
        "sev.LOW": "cyan",
        "sev.INFO": "dim",
    }
)

console = Console(theme=THEME, highlight=False)
err_console = Console(theme=THEME, stderr=True)

BANNER = r"""
 ____       _____ _   _   _             _            
|  _ \  ___|  ___(_) | | | |_   _ _ __ | |_ ___ _ __ 
| | | |/ _ \ |_  | | | |_| | | | | '_ \| __/ _ \ '__|
| |_| |  __/  _| | | |  _  | |_| | | | | ||  __/ |   
|____/ \___|_|   |_| |_| |_|\__,_|_| |_|\__\___|_|   
"""

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# ---------------------------------------------------------------------------
# Basic output helpers
# ---------------------------------------------------------------------------


def banner(version: str = "") -> None:
    """Print the DeFi Hunter banner + tagline."""
    tagline = "Open Source DeFi Security Toolkit"
    if version:
        tagline += f"  ·  v{version}"
    console.print(Panel(Text(BANNER.strip("\n"), style="banner"), border_style="cyan", box=box.HEAVY))
    console.print(Text(f"⚡ {tagline}", style="muted"), justify="center")
    console.print()


def ok(msg: str) -> None:
    console.print(f"[ok]✔[/] {msg}")


def warn(msg: str) -> None:
    console.print(f"[warn]⚠[/] {msg}")


def error(msg: str) -> None:
    err_console.print(f"[err]✖[/] {msg}")


def info(msg: str) -> None:
    console.print(f"[muted]•[/] {msg}")


def step(label: str, msg: str = "") -> None:
    """Print a step header, e.g. '[1/4] Reconnaissance'."""
    text = f"[step]▸ {label}[/]"
    if msg:
        text += f"  [muted]{msg}[/]"
    console.print(text)


def rule(title: str = "") -> None:
    console.rule(Text(title, style="accent"))


# ---------------------------------------------------------------------------
# Spinners / progress
# ---------------------------------------------------------------------------


@contextmanager
def spinner(label: str):
    """Run a block with an animated spinner in the terminal."""
    spinner_console = Console(theme=THEME, highlight=False)
    with spinner_console.status(Text(f"{label}…", style="step")):
        yield


def progress_bar(total: int, description: str = "Working"):
    """Return a rich Progress bar configured for batch operations."""
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeElapsedColumn(),
        console=console,
    )
    task_id = progress.add_task(description, total=total)
    return progress, task_id


def spinner_for(label: str, seconds: float = 1.2):
    """Minimal blocking spinner — handy for demos & tests."""
    with console.status(Text(f"{label}…", style="step")):
        time.sleep(seconds)


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------


def contracts_table(contracts: Dict[str, Dict[str, Any]], title: str = "Contracts") -> Table:
    """Render the recon contract map."""
    table = Table(
        title=title,
        box=box.ROUNDED,
        border_style="cyan",
        header_style="bold cyan",
        show_lines=False,
    )
    table.add_column("#", style="muted", justify="right")
    table.add_column("Address", style="addr", no_wrap=True)
    table.add_column("Name", style="bold white")
    table.add_column("Symbol", style="bold")
    table.add_column("Code", justify="right")

    for i, (addr, info) in enumerate(contracts.items(), 1):
        name = info.get("name", "Unknown")
        symbol = info.get("symbol") or "—"
        code = info.get("code_size", 0)
        has_code = info.get("has_code", bool(code))
        status = info.get("status")
        if status is not None:
            # github scanner supplies an explicit status string
            code_str = str(status)
            code_style = "ok" if ("bytes" in status or "deployed" in status.lower()) else "warn"
        else:
            code_str = f"{code:,} bytes" if code else ("deployed" if has_code else "no code")
            code_style = "ok" if has_code else "warn"
        table.add_row(
            str(i),
            addr,
            str(name),
            str(symbol),
            Text(code_str, style=code_style),
        )
    return table


def findings_table(findings: Sequence[Dict[str, Any]], title: str = "Findings") -> Table:
    """Render analyzer / simulated findings with colored severity.

    Source-level findings (file/line) get a Location column; address-level
    findings fall back to the endpoint/address. Attack tag shows the chained
    playbook route (e.g. 'mint', 'initialize') when present.
    """
    has_location = any(f.get("file") and f.get("line") for f in findings)
    table = Table(
        title=title,
        box=box.ROUNDED,
        border_style="yellow",
        header_style="bold yellow",
    )
    table.add_column("Severity", style="bold")
    table.add_column("Title", style="bold white")
    if has_location:
        table.add_column("Location", style="addr")
    table.add_column("Attack", style="accent")
    table.add_column("Endpoint / Address", style="addr")

    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        attack = str(f.get("attack") or "-")
        if has_location:
            loc = f"{f.get('file')}:{f.get('line')}" if f.get("file") else "-"
            table.add_row(
                Text(sev, style=f"sev.{sev}"),
                str(f.get("title", "Unknown")),
                loc,
                attack,
                str(f.get("endpoint", f.get("address", "-"))),
            )
        else:
            table.add_row(
                Text(sev, style=f"sev.{sev}"),
                str(f.get("title", "Unknown")),
                attack,
                str(f.get("endpoint", f.get("address", "-"))),
            )
    return table


def templates_table(templates: Dict[str, Dict[str, Any]], title: str = "Attack Templates") -> Table:
    """Render the template library."""
    table = Table(
        title=title,
        box=box.ROUNDED,
        border_style="magenta",
        header_style="bold magenta",
    )
    table.add_column("Template", style="bold white", no_wrap=True)
    table.add_column("Type", style="accent")
    table.add_column("Severity", style="bold")
    table.add_column("Description", overflow="fold", max_width=60)

    for name, tpl in templates.items():
        sev = str(tpl.get("severity", "INFO")).upper()
        table.add_row(
            name,
            str(tpl.get("type", "-")),
            Text(sev, style=f"sev.{sev}"),
            str(tpl.get("description", "")),
        )
    return table


def attack_summary(result: Dict[str, Any], attack: str, target: str) -> Panel:
    """Big success/failure panel for `simulate run`."""
    if result.get("success"):
        profit = result.get("profit", "N/A")
        body = Group(
            Text(f"ATTACK SUCCESSFUL — {attack.upper()}", style="success", justify="center"),
            Text(f"target: {target}", style="addr", justify="center"),
            Text(f"profit: {profit}", style="bold green", justify="center"),
        )
        return Panel(body, border_style="green", box=box.HEAVY)
    error_msg = result.get("error", "Unknown")
    body = Group(
        Text(f"ATTACK FAILED — {attack.upper()}", style="fail", justify="center"),
        Text(f"target: {target}", style="addr", justify="center"),
        Text(f"reason: {error_msg}", style="muted", justify="center"),
    )
    return Panel(body, border_style="red", box=box.HEAVY)


def summary_panel(rows: Iterable[tuple[str, str]], title: str = "Summary") -> Panel:
    """Key/value summary panel (used for verdicts, scan stats)."""
    lines = [Text(f"{k}: ", style="bold white") + Text(v) for k, v in rows]
    return Panel(Group(*lines), title=title, border_style="cyan", box=box.ROUNDED)


# ---------------------------------------------------------------------------
# The world-record visual toolkit 🤘
# Gradient banners, threat-level kill screens, attack-surface gauges,
# severity charts and fork-proof flow diagrams.
# ---------------------------------------------------------------------------

GRADIENT = ("bright_red", "bright_magenta", "bright_cyan", "bright_green",
            "bright_yellow", "bright_cyan", "bright_magenta", "bright_red")

MEGA_BANNER = r"""
 ██████╗ ███████╗███████╗██╗      ██╗  ██╗██╗   ██╗███╗   ██╗████████╗███████╗██████╗
 ██╔══██╗██╔════╝██╔════╝██║      ██║  ██║██║   ██║████╗  ██║╚══██╔══╝██╔════╝██╔══██╗
 ██████╔╝█████╗  █████╗  ██║      ███████║██║   ██║██╔██╗ ██║   ██║   █████╗  ██████╔╝
 ██╔══██╗██╔══╝  ██╔══╝  ██║      ██╔══██║██║   ██║██║╚██╗██║   ██║   ██╔══╝  ██╔══██╗
 ██║  ██║███████╗██║     ███████╗██║  ██║╚██████╔╝██║ ╚████║   ██║   ███████╗██║  ██║
 ╚═╝  ╚═╝╚══════╝╚═╝     ╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═══╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
"""


def mega_banner(version: str = "") -> None:
    """Print the DEFI HUNTER mega-banner with a per-line color gradient.

    The panel hugs the artwork (expand=False) so it never balloons across a
    wide terminal — the tagline lives inside the box as a footer line.
    """
    lines = MEGA_BANNER.strip("\n").splitlines()
    n = len(lines)
    body = Text()
    for i, line in enumerate(lines):
        color = GRADIENT[int(i * len(GRADIENT) / max(n, 1))]
        body.append_text(Text(line.rstrip(), style=f"bold {color}", no_wrap=True))
        body.append_text(Text("\n"))
    tag = Text("⚡ WORLD-CLASS DeFi ATTACK TOOLKIT", style="bold yellow",
               justify="center")
    if version:
        tag.append_text(Text(f"  ·  v{version}", style="muted"))
    console.print(Panel(Group(body, tag), border_style="bright_red",
                        box=box.DOUBLE, expand=False, padding=(0, 1)))
    console.print()


def threat_level(findings: Sequence[Dict[str, Any]]) -> str:
    """Map findings to a threat level (CRITICAL/HIGH/MODERATE/LOW/CLEAN)."""
    if not findings:
        return "CLEAN"
    weight = 0
    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        weight += {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}.get(sev, 0)
    score = weight / max(1, len(findings))
    if score >= 3.2:
        return "CRITICAL"
    if score >= 2.2:
        return "HIGH"
    if score >= 1.2:
        return "MODERATE"
    return "LOW"


def threat_banner(level: str, extra: str = "") -> Panel:
    """Big kill-screen style threat-level banner."""
    glyph = {"CRITICAL": "☠️  ", "HIGH": "🔥 ", "MODERATE": "⚠️ ", "LOW": "🟡",
             "CLEAN": "🛡️  "}.get(level, "❓")
    colors = {"CRITICAL": "red", "HIGH": "bright_red", "MODERATE": "yellow",
              "LOW": "bright_yellow", "CLEAN": "green"}
    style = colors.get(level, "white")
    header = Text(f"{glyph} THREAT LEVEL: {level}", style=f"bold white on {style}",
                  justify="center")
    lines = [header]
    if extra:
        lines.append(Text(extra, style="bold white", justify="center"))
    return Panel(Group(*lines), border_style=style, box=box.DOUBLE)


def attack_surface_gauge(findings: Sequence[Dict[str, Any]]) -> Panel:
    """0–10 attack-surface meter, drawn with unicode blocks."""
    if not findings:
        score, label = 0.0, "CLEAN"
    else:
        weight = sum({"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2,
                      "INFO": 1}.get(str(f.get("severity", "INFO")).upper(), 0)
                     for f in findings)
        score = min(10.0, round(weight / 2.5, 1))
        label = threat_level(findings)
    color = {"CRITICAL": "red", "HIGH": "bright_red", "MODERATE": "yellow",
             "LOW": "bright_yellow", "CLEAN": "green"}.get(label, "white")
    filled = int(score)
    bar = "█" * filled + "░" * (10 - filled)
    body = Text(f"ATTACK SURFACE  {bar}  {score:.1f}/10", style=f"bold {color}")
    sub = Text(f"threat: {label}", style=f"{color}", justify="center")
    return Panel(Group(body, sub), title="EXPOSURE METER", border_style=color,
                 box=box.ROUNDED)


def severity_chart(findings: Sequence[Dict[str, Any]]) -> Panel:
    """Horizontal bar chart of findings by severity."""
    counts = {s: 0 for s in SEVERITY_ORDER}
    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        counts[sev] = counts.get(sev, 0) + 1
    total = max(1, len(findings))
    max_c = max(1, max(counts.values()))
    width = 20
    lines = []
    for sev in SEVERITY_ORDER:
        c = counts.get(sev, 0)
        if c == 0:
            continue
        bar_len = max(1, int(c * width / max_c))
        color = {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow",
                 "LOW": "cyan", "INFO": "dim"}.get(sev, "white")
        lines.append(Text(f"{sev:<9} ", style="bold white") +
                     Text("█" * bar_len, style=color) +
                     Text(f" {c} ({c*100//total}%)", style="muted"))
    if not lines:
        lines.append(Text("no findings — clean repo", style="green"))
    return Panel(Group(*lines), title="FINDINGS BY SEVERITY", border_style="cyan",
                 box=box.ROUNDED)


def attack_flow(findings: Sequence[Dict[str, Any]],
                fork_results: Sequence[Dict[str, Any]] = ()) -> Panel:
    """Visual chain: FINDING → ROUTE → FORK STATUS.

    ✅ EXPLOITABLE   — fork-proven callable by an arbitrary account
    ⚠️ POSSIBLE      — static hit, not (or not yet) fork-proven
    ⚪ NOT VERIFIED  — source hint with no direct exploit route
    """
    status_by_fileline: Dict[tuple, str] = {}
    for r in fork_results:
        sf = r.get("source_finding") or {}
        key = (sf.get("file"), sf.get("line"))
        if r.get("success"):
            status_by_fileline[key] = "✅ EXPLOITABLE"
        else:
            status_by_fileline.setdefault(key, "⚠️ POSSIBLE")
    for f in findings:
        key = (f.get("file"), f.get("line"))
        if key not in status_by_fileline:
            status_by_fileline[key] = "⚠️ POSSIBLE" if f.get("attack") else "⚪ NOT VERIFIED"

    table = Table(box=box.ROUNDED, border_style="magenta", header_style="bold magenta",
                  expand=True, show_edge=True)
    table.add_column("FINDING", style="bold white", max_width=46, overflow="fold")
    table.add_column("ROUTE", style="accent", justify="center")
    table.add_column("FORK STATUS", justify="center")
    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        title = str(f.get("title", "Unknown"))
        loc = f"{f.get('file')}:{f.get('line')}" if f.get("file") else "-"
        route = str(f.get("attack") or "-")
        status = status_by_fileline.get((f.get("file"), f.get("line")),
                                        "⚪ NOT VERIFIED")
        status_style = ("success" if "EXPLOITABLE" in status else
                        "warn" if "POSSIBLE" in status else "muted")
        cell = Text()
        cell.append(Text(f"[{sev}] {title}", style=f"sev.{sev}"))
        cell.append(Text("\n"))
        cell.append(Text(loc, style="dim"))
        table.add_row(
            cell,
            Text(route, style="accent"),
            Text(status, style=status_style),
        )
    return Panel(table, title="ATTACK FLOW", border_style="magenta", box=box.DOUBLE)


def hunt_complete(rows: Iterable[tuple[str, str]], level: str = "LOW") -> None:
    """Final kill-screen: verdict header + key/value stats."""
    console.print()
    console.print(threat_banner(level, extra="TARGET ASSESSED · REPORT READY"))
    console.print(ui_summary_table(rows, title="HUNT COMPLETE 🏆"))


def ui_summary_table(rows: Iterable[tuple[str, str]], title: str = "Summary") -> Table:
    """Key/value summary as a table (denser than the panel)."""
    table = Table(box=box.ROUNDED, border_style="cyan", header_style="bold cyan",
                  show_header=False, title=title, title_style="bold white")
    table.add_column("key", style="bold white", justify="right", no_wrap=True)
    table.add_column("value", style="white")
    for k, v in rows:
        table.add_row(k, v)
    return table
