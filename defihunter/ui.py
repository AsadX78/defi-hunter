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
    table.add_column("Code", justify="right")

    for i, (addr, info) in enumerate(contracts.items(), 1):
        name = info.get("name", "Unknown")
        code = info.get("code_size", 0)
        has_code = info.get("has_code", bool(code))
        code_str = f"{code:,} bytes" if code else ("deployed" if has_code else "no code")
        code_style = "ok" if has_code else "warn"
        table.add_row(
            str(i),
            addr,
            str(name),
            Text(code_str, style=code_style),
        )
    return table


def findings_table(findings: Sequence[Dict[str, Any]], title: str = "Findings") -> Table:
    """Render analyzer / simulated findings with colored severity."""
    table = Table(
        title=title,
        box=box.ROUNDED,
        border_style="yellow",
        header_style="bold yellow",
    )
    table.add_column("Severity", style="bold")
    table.add_column("Title", style="bold white")
    table.add_column("Endpoint / Address", style="addr")

    for f in findings:
        sev = str(f.get("severity", "INFO")).upper()
        table.add_row(
            Text(sev, style=f"sev.{sev}"),
            str(f.get("title", "Unknown")),
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
