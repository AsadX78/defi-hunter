"""DeFi Hunter -- UI layer.

Central place for all terminal output: colors, panels, tables, spinners and
the CLI banner. Every command in cli.py should render through here so the
look & feel stays consistent while the rest of the toolkit grows.

Depends only on `rich` -- no core logic lives here.
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
from rich.columns import Columns
from rich.align import Align
from rich.rule import Rule

# ---------------------------------------------------------------------------
# Theme -- Muted hacker terminal aesthetic
# CRT phosphor green, amber, dim red -- no bright neons
# ---------------------------------------------------------------------------
THEME = Theme(
    {
        "banner": "bold green",
        "cmd": "bold white",
        "step": "bold green",
        "ok": "bold green",
        "warn": "bold yellow",
        "err": "bold red",
        "muted": "dim white",
        "addr": "green",
        "accent": "bold yellow",
        "success": "bold green",
        "fail": "bold red",
        "highlight": "bold white",
        "fire": "bold red on dark_red",
        "neon": "bold green",
        "cyber": "bold green",
        # severity colors -- muted, no bright neons
        "sev.CRITICAL": "bold white on red",
        "sev.HIGH": "bold red",
        "sev.MEDIUM": "bold yellow",
        "sev.LOW": "green",
        "sev.INFO": "dim white",
    }
)

console = Console(theme=THEME, highlight=False, force_terminal=True)
err_console = Console(theme=THEME, stderr=True, force_terminal=True)

# ---------------------------------------------------------------------------
# Hacker ASCII Banner -- box-drawing double-line style
# ---------------------------------------------------------------------------

BANNER = r"""
  ╔═╗╦ ╦╦═╗╔═╗╔╦╗╔═╗╔╦╗  ╔═╗╦ ╦╔═╗╔╗ ╔═╗╔═╗╦═╗╔╦╗
  ╠═╣║ ║╠╦╝╠═╣ ║ ╠═╣ ║║  ║  ╠═╣║╣ ╠╩╗║╣ ║╣ ╠╦╝║║║
  ╩ ╩╚═╝╩╚═╩ ╩ ╩ ╩ ╩═╩╝  ╚═╝╩ ╩╚═╝╚═╝╚═╝╚═╝╩╚═╩ ╩"""

TAGLINE = ":: DEFi EXPLOIT TOOLKIT ::"
SUBTITLE = "fork-proves every finding on a live mainnet clone"

SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")

# Hacker symbols -- no emojis
SEV_ICONS = {
    "CRITICAL": "!!!",
    "HIGH": "!! ",
    "MEDIUM": "!  ",
    "LOW": ".  ",
    "INFO": "-  ",
}


# ---------------------------------------------------------------------------
# Basic output helpers
# ---------------------------------------------------------------------------


def banner(version: str = "") -> None:
    """Print the DeFi Hunter banner + tagline."""
    console.print()
    console.print(Panel(
        Text(BANNER.strip("\n"), style="banner"),
        border_style="green",
        box=box.SIMPLE,
        padding=(0, 1),
    ))

    # Tagline
    tagline_text = Text()
    tagline_text.append(f"  {TAGLINE}", style="bold yellow")
    if version:
        tagline_text.append(f"  // v{version}", style="dim white")
    console.print(Align.center(tagline_text))

    # Subtitle
    console.print(Align.center(Text(f"  {SUBTITLE}", style="dim green")))
    console.print()

    # Stats bar -- minimal, no emojis
    stats = Table.grid(padding=(0, 3))
    stats.add_column(style="dim")
    stats.add_column(style="bold green")
    stats.add_column(style="dim")
    stats.add_column(style="bold yellow")
    stats.add_column(style="dim")
    stats.add_column(style="bold green")
    stats.add_row(
        ">>>", "20 ATTACKS",
        ">>>", "LIVE FORK",
        ">>>", "EXPLOITS",
    )
    console.print(Align.center(stats))
    console.print()


def scan_header(protocol: str = "", chain: str = "") -> None:
    """Print a scan header with protocol info."""
    console.print()
    console.rule(Text(f">>> SCANNING: {protocol}", style="bold green"))
    if chain:
        console.print(f"  [dim]chain:[/] [bold]{chain}[/]")
    console.print()


def vuln_header(count: int = 0, severity: str = "") -> None:
    """Print vulnerability discovery header."""
    console.print()
    if count > 0:
        style = "bold red" if severity in ("CRITICAL", "HIGH") else "bold yellow"
        console.print(Panel(
            f"[{style}]!!! FOUND {count} VULNERABILITY(IES)[/]",
            border_style=style.split()[-1],
            box=box.HEAVY,
        ))
    else:
        console.print(Panel(
            "[bold green][+] NO VULNERABILITIES FOUND[/]",
            border_style="green",
            box=box.HEAVY,
        ))
    console.print()


def exploit_header(attack_type: str = "", target: str = "") -> None:
    """Print exploit generation header."""
    console.print()
    console.rule(Text(f">>> GENERATING EXPLOIT: {attack_type.upper()}", style="bold red"))
    if target:
        console.print(f"  [dim]target:[/] [bold green]{target}[/]")
    console.print()


def success_box(message: str) -> None:
    """Print a success box."""
    console.print(Panel(
        f"[bold green][+] {message}[/]",
        border_style="green",
        box=box.SIMPLE,
        padding=(0, 2),
    ))


def error_box(message: str) -> None:
    """Print an error box."""
    console.print(Panel(
        f"[bold red][-] {message}[/]",
        border_style="red",
        box=box.SIMPLE,
        padding=(0, 2),
    ))


def warning_box(message: str) -> None:
    """Print a warning box."""
    console.print(Panel(
        f"[bold yellow][!] {message}[/]",
        border_style="yellow",
        box=box.SIMPLE,
        padding=(0, 2),
    ))


def info_box(message: str) -> None:
    """Print an info box."""
    console.print(Panel(
        f"[bold green][*] {message}[/]",
        border_style="green",
        box=box.SIMPLE,
        padding=(0, 2),
    ))


def ok(msg: str) -> None:
    console.print(f"[ok][+][/] {msg}")


def warn(msg: str) -> None:
    console.print(f"[warn][!][/] {msg}")


def error(msg: str) -> None:
    err_console.print(f"[err][-][/] {msg}")


def info(msg: str) -> None:
    console.print(f"[muted]...[/] {msg}")


def step(label: str, msg: str = "") -> None:
    """Print a step header, e.g. '[1/4] Reconnaissance'."""
    text = f"[step]>>>[/] [bold]{label}[/]"
    if msg:
        text += f"  [muted]<-[/] [white]{msg}[/]"
    console.print(text)


def rule(title: str = "") -> None:
    console.rule(Text(title, style="accent"))


def divider() -> None:
    """Print a visual divider."""
    console.print(Text("─" * 70, style="dim"))


def progress_header(current: int, total: int, label: str = "") -> None:
    """Print progress header."""
    pct = int((current / total) * 100) if total > 0 else 0
    bar = "█" * (pct // 5) + "░" * (20 - pct // 5)
    console.print(f"  [dim]{label}[/] [{bar}] [bold]{pct}%[/] ({current}/{total})")


# ---------------------------------------------------------------------------
# Spinners / progress
# ---------------------------------------------------------------------------


@contextmanager
def spinner(label: str):
    """Run a block with an animated spinner + live elapsed timer."""
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    )
    progress.add_task(f"{label}...", total=None)
    with progress:
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
    """Minimal blocking spinner -- handy for demos & tests."""
    progress = Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        TimeElapsedColumn(),
        console=console,
    )
    progress.add_task(f"{label}...", total=None)
    with progress:
        time.sleep(seconds)


# ---------------------------------------------------------------------------
# Tables
# ---------------------------------------------------------------------------


def contracts_table(contracts: Dict[str, Dict[str, Any]], title: str = "Contracts") -> Table:
    """Render the recon contract map."""
    table = Table(
        title=title,
        box=box.SIMPLE_HEAVY,
        border_style="green",
        header_style="bold green",
        show_lines=False,
    )
    table.add_column("#", style="muted", justify="right")
    table.add_column("Address", style="addr", no_wrap=True)
    table.add_column("Name", style="bold white")
    table.add_column("Symbol", style="bold")
    table.add_column("Code", justify="right")

    for i, (addr, info) in enumerate(contracts.items(), 1):
        name = info.get("name", "Unknown")
        symbol = info.get("symbol") or "---"
        code = info.get("code_size", 0)
        has_code = info.get("has_code", bool(code))
        status = info.get("status")
        if status is not None:
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
    """Render analyzer / simulated findings with colored severity."""
    has_location = any(f.get("file") and f.get("line") for f in findings)
    table = Table(
        title=title,
        box=box.SIMPLE_HEAVY,
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
        box=box.SIMPLE_HEAVY,
        border_style="green",
        header_style="bold green",
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
            Text(f"EXPLOIT SUCCESSFUL // {attack.upper()}", style="success", justify="center"),
            Text(f"target: {target}", style="addr", justify="center"),
            Text(f"profit: {profit}", style="bold green", justify="center"),
        )
        return Panel(body, border_style="green", box=box.HEAVY)
    error_msg = result.get("error", "Unknown")
    body = Group(
        Text(f"EXPLOIT FAILED // {attack.upper()}", style="fail", justify="center"),
        Text(f"target: {target}", style="addr", justify="center"),
        Text(f"reason: {error_msg}", style="muted", justify="center"),
    )
    return Panel(body, border_style="red", box=box.HEAVY)


def summary_panel(rows: Iterable[tuple[str, str]], title: str = "Summary") -> Panel:
    """Key/value summary panel (used for verdicts, scan stats)."""
    lines = [Text(f"{k}: ", style="bold white") + Text(v) for k, v in rows]
    return Panel(Group(*lines), title=title, border_style="green", box=box.SIMPLE_HEAVY,
                 expand=False)


# ---------------------------------------------------------------------------
# Visual toolkit -- threat levels, gauges, severity charts, attack flow
# ---------------------------------------------------------------------------

GRADIENT = ("green", "yellow", "green", "yellow",
            "green", "yellow", "green", "yellow")

MEGA_BANNER = r"""
  ╔═╗╦ ╦╦═╗╔═╗╔╦╗╔═╗╔╦╗  ╔═╗╦ ╦╔═╗╔╗ ╔═╗╔═╗╦═╗╔╦╗
  ╠═╣║ ║╠╦╝╠═╣ ║ ╠═╣ ║║  ║  ╠═╣║╣ ╠╩╗║╣ ║╣ ╠╦╝║║║
  ╩ ╩╚═╝╩╚═╩ ╩ ╩ ╩ ╩═╩╝  ╚═╝╩ ╩╚═╝╚═╝╚═╝╚═╝╩╚═╩ ╩"""


def mega_banner(version: str = "") -> None:
    """Print the DEFI HUNTER mega-banner with a per-line color gradient."""
    lines = MEGA_BANNER.strip("\n").splitlines()
    n = len(lines)
    body = Text()
    for i, line in enumerate(lines):
        color = GRADIENT[int(i * len(GRADIENT) / max(n, 1))]
        body.append_text(Text(line.rstrip(), style=f"bold {color}", no_wrap=True))
        body.append_text(Text("\n"))
    tag = Text(":: DEFi EXPLOIT TOOLKIT ::", style="bold yellow",
               justify="center")
    if version:
        tag.append_text(Text(f"  // v{version}", style="muted"))
    hook = Text("fork-proves every finding on a live mainnet clone",
                style="italic muted",
                justify="center")
    console.print(Panel(Group(body, tag, hook), border_style="green",
                        box=box.DOUBLE, expand=False, padding=(0, 1)))
    console.print()


def intro(version: str = "") -> None:
    """Full-screen animated boot intro (terminal only).

    Sequence:
        1. RADAR -- spinning target-acquisition sweep
        2. REVEAL -- the DEFI HUNTER block art draws line-by-line under a
           bright scanline while status messages cycle
        3. HOLD -- full artwork, then the boxed static banner with tagline

    Degrades to a plain static banner when stdout isn't a terminal
    (pipes/tests/CI) or when DEFIHUNTER_NO_INTRO=1 is set -- the wizard never
    blocks on animation.
    """
    import os as _os
    import time as _time

    if not console.is_terminal or _os.environ.get("DEFIHUNTER_NO_INTRO"):
        mega_banner(version)
        return

    from rich.live import Live

    lines = MEGA_BANNER.strip("\n").splitlines()
    n = len(lines)
    radar = ["[+]", "[.]", "[*]", "[.]"]
    statuses = ["ACQUIRING TARGET", "ANALYZING ATTACK SURFACE",
                "ARMING FORK SIMULATOR", "HUNTING MODE: ENGAGED"]
    art_width = max(len(l.rstrip()) for l in lines)

    def frame_text(revealed: int, status: str) -> Text:
        body = Text()
        for j in range(n):
            color = GRADIENT[int(j * len(GRADIENT) / max(n, 1))]
            line = lines[j].rstrip()
            if j < revealed:
                body.append_text(Text(line, style=f"bold {color}", no_wrap=True))
            else:
                body.append_text(Text(line, style="dim", no_wrap=True))
            body.append_text(Text("\n"))
        body.append_text(Text("─" * art_width, style="yellow", no_wrap=True))
        body.append_text(Text("\n"))
        body.append_text(Text(status, style="bold green", justify="center"))
        return body

    t0 = _time.time()
    with Live(console=console, refresh_per_second=30, transient=True,
              vertical_overflow="visible") as live:
        # 1. radar sweep (~0.9s)
        while _time.time() - t0 < 0.9:
            frame = radar[int((_time.time() - t0) * 30) % len(radar)]
            live.update(Group(
                Text(f"{frame}  TARGET ACQUISITION", style="bold green",
                     justify="center"),
                Text("sweeping attack surface...", style="dim", justify="center"),
            ))
            _time.sleep(1 / 30)
        # 2. line-by-line reveal (~0.13s/line)
        t1 = _time.time()
        revealed = 0
        while revealed < n:
            revealed = min(n, int((_time.time() - t1) / 0.13))
            status = statuses[min(revealed, len(statuses) - 1)]
            live.update(frame_text(revealed, status))
            _time.sleep(1 / 30)
        # final full frame, held a beat
        live.update(frame_text(n, statuses[-1]))
        _time.sleep(0.6)
    # final static, boxed banner for the wizard to continue under
    mega_banner(version)


def threat_level(findings: Sequence[Dict[str, Any]], analyzed: bool = True) -> str:
    """Map findings to a threat level.

    Returns INCONCLUSIVE when there are no findings AND nothing was actually
    analyzed -- a security tool must never claim CLEAN on no data.
    """
    if not findings:
        return "CLEAN" if analyzed else "INCONCLUSIVE"
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
    glyph = {"CRITICAL": "[!]  ", "HIGH": "[!!] ", "MODERATE": "[!] ", "LOW": "[.] ",
             "CLEAN": "[+]  ", "INCONCLUSIVE": "[?] "}.get(level, "[?] ")
    colors = {"CRITICAL": "red", "HIGH": "bright_red", "MODERATE": "yellow",
              "LOW": "yellow", "CLEAN": "green",
              "INCONCLUSIVE": "green"}
    style = colors.get(level, "white")
    header = Text(f"{glyph} THREAT LEVEL: {level}", style=f"bold white on {style}",
                  justify="center")
    lines = [header]
    if extra:
        lines.append(Text(extra, style="bold white", justify="center"))
    return Panel(Group(*lines), border_style=style, box=box.DOUBLE, expand=False)


def attack_surface_gauge(findings: Sequence[Dict[str, Any]],
                         analyzed: bool = True) -> Panel:
    """0-10 attack-surface meter, drawn with unicode blocks."""
    if not findings:
        if not analyzed:
            body = Text("ATTACK SURFACE  ░░░░░░░░░░  N/A", style="bold green")
            sub = Text("no data -- analysis skipped", style="green",
                       justify="center")
            return Panel(Group(body, sub), title="EXPOSURE METER",
                         border_style="green", box=box.SIMPLE_HEAVY, expand=False)
        score, label = 0.0, "CLEAN"
    else:
        weight = sum({"CRITICAL": 10, "HIGH": 7, "MEDIUM": 4, "LOW": 2,
                      "INFO": 1}.get(str(f.get("severity", "INFO")).upper(), 0)
                     for f in findings)
        score = min(10.0, round(weight / 2.5, 1))
        label = threat_level(findings)
    color = {"CRITICAL": "red", "HIGH": "red", "MODERATE": "yellow",
             "LOW": "yellow", "CLEAN": "green"}.get(label, "white")
    filled = int(score)
    bar = "█" * filled + "░" * (10 - filled)
    body = Text(f"ATTACK SURFACE  {bar}  {score:.1f}/10", style=f"bold {color}")
    sub = Text(f"threat: {label}", style=f"{color}", justify="center")
    return Panel(Group(body, sub), title="EXPOSURE METER", border_style=color,
                 box=box.SIMPLE_HEAVY, expand=False)


def severity_chart(findings: Sequence[Dict[str, Any]],
                   analyzed: bool = True) -> Panel:
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
        color = {"CRITICAL": "red", "HIGH": "red", "MEDIUM": "yellow",
                 "LOW": "green", "INFO": "dim"}.get(sev, "white")
        lines.append(Text(f"{sev:<9} ", style="bold white") +
                     Text("█" * bar_len, style=color) +
                     Text(f" {c} ({c*100//total}%)", style="muted"))
    if not lines:
        if not analyzed:
            lines.append(Text("no data -- analysis skipped", style="green"))
        else:
            lines.append(Text("no findings -- clean repo", style="green"))
    return Panel(Group(*lines), title="FINDINGS BY SEVERITY", border_style="green",
                 box=box.SIMPLE_HEAVY, expand=False)


def attack_flow(findings: Sequence[Dict[str, Any]],
                fork_results: Sequence[Dict[str, Any]] = ()) -> Panel:
    """Visual chain: FINDING -> ROUTE -> FORK STATUS.

    [+] EXPLOITABLE   -- fork-proven callable by an arbitrary account
    [~] POSSIBLE      -- static hit, not (or not yet) fork-proven
    [-] NOT VERIFIED  -- source hint with no direct exploit route
    """
    status_by_fileline: Dict[tuple, str] = {}
    for r in fork_results:
        sf = r.get("source_finding") or {}
        key = (sf.get("file"), sf.get("line"))
        if r.get("success"):
            status_by_fileline[key] = "[+] EXPLOITABLE"
        else:
            status_by_fileline.setdefault(key, "[~] POSSIBLE")
    for f in findings:
        key = (f.get("file"), f.get("line"))
        if key not in status_by_fileline:
            status_by_fileline[key] = "[~] POSSIBLE" if f.get("attack") else "[-] NOT VERIFIED"

    table = Table(box=box.SIMPLE_HEAVY, border_style="green", header_style="bold green",
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
                                        "[-] NOT VERIFIED")
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
    return Panel(table, title="ATTACK FLOW", border_style="green", box=box.DOUBLE,
                 expand=False)


def ui_summary_table(rows: Iterable[tuple[str, str]], title: str = "Summary") -> Table:
    """Key/value summary as a table (denser than the panel)."""
    table = Table(box=box.SIMPLE_HEAVY, border_style="green", header_style="bold green",
                  show_header=False, title=title, title_style="bold white")
    table.add_column("key", style="bold white", justify="right", no_wrap=True)
    table.add_column("value", style="white")
    for k, v in rows:
        table.add_row(k, v)
    return table


def hunt_complete(rows: Iterable[tuple[str, str]], level: str = "LOW") -> None:
    """Final kill-screen: verdict header + key/value stats."""
    console.print()
    console.print(threat_banner(level, extra="TARGET ASSESSED // REPORT READY"))
    console.print(ui_summary_table(rows, title="HUNT COMPLETE"))
