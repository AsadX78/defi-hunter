"""Interactive wizard — guided DeFi protocol check.

`defihunter` with no arguments boots this. It walks a first-time user
through the whole hunt:

    1. GitHub repo link of the protocol   → clone + extract contract addresses
    2. RPC URL                            → verify which addresses have code
    3. Vulnerability check type           → static analysis / attack simulation / both
    4. (simulation) attack types          → pick from the 18 built-in attacks
    5. Run + optional HTML report
"""
from __future__ import annotations

import json
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich.prompt import Confirm, Prompt

from defihunter import ui
from defihunter.core import config, github
from defihunter.core.analyzer import ContractAnalyzer
from defihunter.core.reporter import ReportGenerator
from defihunter.core.simulator import AttackSimulator

ALL_ATTACKS = [
    "inflation", "admin", "governance", "oracle", "reentrancy", "bridge",
    "sandwich", "twap", "flashloan", "withdraw", "initialize", "permit",
    "liquidation", "forcesend", "peg", "crossfunc", "delegatecall", "mint",
]
RECOMMENDED_ATTACKS = ["initialize", "admin", "mint", "inflation", "withdraw", "permit"]


# ---------------------------------------------------------------------------
# Prompt helpers
# ---------------------------------------------------------------------------


def ask_repo_url() -> str:
    """Q1: GitHub repo, local folder, or raw 0x addresses (no GitHub needed)."""
    ui.console.print()
    ui.console.print(ui.summary_panel([
        ("Step 1 of 5", "Protocol source"),
        ("What we need", "A GitHub repo link, a local folder, OR 0x contract addresses"),
        ("No GitHub?", "Paste addresses directly (comma/space separated), e.g. 0x6B17…,0xCdFd…"),
        ("Example", "https://github.com/Layr-Labs/eigenlayer-contracts"),
    ], title="Protocol Source"))
    while True:
        answer = Prompt.ask(
            "[step]GitHub repo URL, local folder, or addresses[/]"
            + " [muted](comma/space separated)[/]"
        ).strip()
        if not answer:
            ui.error("Empty input — paste a repo link, a folder path, or addresses.")
            continue
        if github.is_repo_dir(answer):
            return answer
        if github.looks_like_git_url(answer):
            return answer
        if github.is_address_list(answer):
            return answer
        ui.warn("That doesn't look like a GitHub/git URL, a folder, or 0x addresses")
        if Confirm.ask("[warn]Continue anyway?[/]", default=False):
            return answer


def ask_rpc() -> Optional[str]:
    """Q2: RPC URL. Reuse $RPC_URL if set, else prompt with the saved
    default ($DEFIHUNTER_RPC > config.local.yaml > built-in default).
    Newly entered URLs can be saved for future hunts."""
    env_rpc = os.getenv("RPC_URL")
    if env_rpc:
        ui.info(f"Using RPC_URL from environment: {env_rpc}")
        return env_rpc
    saved_rpc = config.get_default_rpc()
    is_saved = saved_rpc != config.DEFAULT_RPC
    ui.console.print()
    ui.console.print(ui.summary_panel([
        ("Why", "Lets us check which addresses are real contracts and pull names"),
        ("Tip", "Enter your own RPC for the protocol's chain (e.g. an Alchemy key)"),
        ("Saved", f"Your saved RPC will be used as the default{'' if is_saved else ' (none yet — save one with: defihunter config set-rpc <url>)'}"),
        ("Skip", "Type 'skip' to list addresses without on-chain verification"),
    ], title="RPC Endpoint"))
    answer = Prompt.ask(
        f"[step]RPC URL[/] [muted](Enter = {saved_rpc})[/]", default=saved_rpc
    ).strip()
    if answer.lower() in ("skip", "s", "none"):
        return None
    if answer and answer != saved_rpc:
        # New custom URL — offer to persist it for future projects.
        if Confirm.ask("[step]Save this RPC for future hunts?[/]", default=True):
            path = config.save_rpc(answer)
            ui.ok(f"Saved RPC to {path} — it will pre-fill next time.")
    return answer or saved_rpc


def ask_check_type() -> str:
    """Q3: which kind of vulnerability check."""
    ui.console.print()
    ui.console.print(ui.summary_panel([
        ("1", "Static analysis — scan each contract for known bad patterns"),
        ("2", "Attack simulation — try to actually exploit them on a fork"),
        ("3", "Both (recommended)"),
    ], title="Vulnerability Check Type"))
    while True:
        answer = Prompt.ask("[step]What type of vulnerability check?[/]", default="3").strip()
        if answer in ("1", "2", "3"):
            return {"1": "static", "2": "simulate", "3": "both"}[answer]
        ui.warn("Enter 1, 2 or 3.")


def ask_attacks() -> List[str]:
    """Q4: which attack simulations to run (only for simulate/both)."""
    ui.console.print()
    rows = []
    for i, name in enumerate(ALL_ATTACKS, 1):
        mark = "*" if name in RECOMMENDED_ATTACKS else " "
        rows.append(f"  [{i:>2}] {name:<14} {mark}")
    menu = "\n".join("".join(rows[i:i + 3]) for i in range(0, len(rows), 3))
    ui.console.print(ui.summary_panel(
        [("* = recommended set", "initialize, admin, mint, inflation, withdraw, permit")],
        title="Attack Menu (comma-separated numbers, or 'all')",
    ))
    ui.console.print(menu)
    ui.console.print()
    while True:
        answer = Prompt.ask(
            "[step]Pick attacks[/] [muted](Enter = recommended)[/]", default="1-6"
        ).strip().lower()
        if answer in ("all", "a", "*"):
            return list(ALL_ATTACKS)
        if answer in ("1-6", "rec", "recommended", ""):
            return list(RECOMMENDED_ATTACKS)
        # parse numbers
        picks: List[str] = []
        try:
            for token in re.split(r"[,\s]+", answer):
                if not token:
                    continue
                if "-" in token:
                    lo, hi = token.split("-", 1)
                    picks.extend(range(int(lo), int(hi) + 1))
                else:
                    picks.append(int(token))
        except ValueError:
            ui.warn("Couldn't parse that — use numbers like '1,3,5' or 'all'.")
            continue
        if not picks or any(p < 1 or p > len(ALL_ATTACKS) for p in picks):
            ui.warn(f"Pick numbers between 1 and {len(ALL_ATTACKS)}.")
            continue
        return [ALL_ATTACKS[p - 1] for p in sorted(set(picks))]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def _run_static(contracts: Dict[str, Dict], rpc: Optional[str] = None) -> List[Dict]:
    """Run ContractAnalyzer against every verified contract."""
    ui.rule("STATIC ANALYSIS")
    analyzer = ContractAnalyzer(rpc_url=rpc)
    findings: List[Dict] = []
    progress, task = ui.progress_bar(len(contracts), "Analyzing contracts")
    with progress:
        for addr in contracts:
            result = analyzer.analyze(addr)
            for f in result:
                f.setdefault("endpoint", addr)
            findings.extend(result)
            progress.advance(task)
    if findings:
        ui.warn(f"{len(findings)} finding(s):")
        ui.console.print(ui.findings_table(findings))
    else:
        ui.ok("No obvious vulnerabilities found")
    return findings


def _run_simulate(contracts: Dict[str, Dict], attacks: List[str], rpc: Optional[str] = None) -> List[Dict]:
    """Run AttackSimulator for every attack × verified contract."""
    ui.rule("ATTACK SIMULATION")
    simulator = AttackSimulator(rpc_url=rpc)
    results: List[Dict] = []
    total = len(attacks) * len(contracts)
    progress, task = ui.progress_bar(total, "Running attacks")
    with progress:
        for addr in contracts:
            for attack in attacks:
                res = simulator.run(attack, addr)
                res.update({"address": addr, "attack": attack})
                results.append(res)
                progress.advance(task)

    ok_count = sum(1 for r in results if r.get("success"))
    if ok_count:
        ui.warn(f"{ok_count} attack(s) succeeded — investigate these:")
    # compact results table
    from rich.table import Table
    from rich import box as rich_box
    t = Table(title="Simulation Results", box=rich_box.ROUNDED, border_style="magenta",
              header_style="bold magenta")
    t.add_column("Attack", style="bold white")
    t.add_column("Address", style="addr", no_wrap=True)
    t.add_column("Result", style="bold")
    for r in results:
        result_txt = "SUCCESS ✔" if r.get("success") else "failed"
        style = "success" if r.get("success") else "muted"
        t.add_row(r["attack"], r["address"], f"[{style}]{result_txt}[/]")
    ui.console.print(t)
    if ok_count:
        ui.warn("Remember: simulator hits are selector-based — verify each success "
                "with `cast call` or an anvil fork before reporting.")
    return results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def run_wizard(
    verbose: bool = False,
    repo_url: Optional[str] = None,
    check: Optional[str] = None,
    attacks: Optional[List[str]] = None,
) -> None:
    """Boot the guided hunt. Pass repo_url/check/attacks to skip those prompts."""
    ui.banner()

    # --- 1. Repo -----------------------------------------------------------
    if repo_url:
        ui.step("Protocol source", repo_url)
    else:
        repo_url = ask_repo_url()

    # --- 2. RPC ------------------------------------------------------------
    rpc = ask_rpc()

    # --- scan --------------------------------------------------------------
    ui.rule("EXTRACTING CONTRACTS")
    with ui.spinner(f"Scanning {repo_url}"):
        try:
            if github.is_address_list(repo_url):
                scan = github.scan_addresses(repo_url, rpc_url=rpc)
            else:
                scan = github.scan_repo(repo_url, rpc_url=rpc)
        except RuntimeError as e:
            ui.error(str(e))
            return

    contracts = scan["contracts"]
    if not contracts:
        ui.warn("No 0x addresses found in the repo. Try a repo that includes "
                "deployment files/README tables (e.g. Layr-Labs/eigenlayer-contracts).")
        return

    ui.ok(f"Found {len(contracts)} candidate address(es) in {scan['repo_dir']}")

    # keep only verified contracts for the checks when RPC was used
    if rpc:
        verified = {a: i for a, i in contracts.items() if i.get("verified")}
        if not verified:
            ui.warn("None of the addresses have deployed code on this RPC. "
                    "Either the repo is testnet-only, or the RPC check failed "
                    "(network/DNS hiccups make every address look like 'no code'). "
                    "Verify with: cast code <addr> --rpc-url <rpc>. "
                    "Continuing with all addresses.")
        else:
            ui.info(f"{len(verified)} verified contract(s) with code")
            contracts = verified

    # preview table (top 20 — repos can contain hundreds of mock/test addrs)
    items = list(contracts.items())
    preview = dict(items[:20])
    ui.console.print(ui.contracts_table(preview, title="Discovered Contracts (preview)"))
    if len(items) > 20:
        ui.info(f"… and {len(items) - 20} more (count-ordered: most-referenced first)")

    # how many to actually check
    if len(items) > 20:
        while True:
            ans = Prompt.ask(
                "[step]How many contracts to check?[/] [muted](default 20, or 'all')[/]",
                default="20",
            ).strip().lower()
            if ans in ("all", "*"):
                check_limit = len(items)
                break
            try:
                check_limit = int(ans)
                if 1 <= check_limit <= len(items):
                    break
                ui.warn(f"Pick a number between 1 and {len(items)}.")
            except ValueError:
                ui.warn("Enter a number or 'all'.")
        contracts = dict(items[:check_limit])
        ui.info(f"Checking {len(contracts)} contract(s).")

    # --- 3. Check type -----------------------------------------------------
    if check in ("static", "simulate", "both"):
        ui.step("Vulnerability check", check)
    else:
        check = ask_check_type()

    # --- 4. Attacks (if simulating) ----------------------------------------
    if check in ("simulate", "both"):
        if attacks is None:
            attacks = ask_attacks()
        ui.info(f"Attacks: {', '.join(attacks)}")

    # --- 5. Run ------------------------------------------------------------
    findings: List[Dict] = []
    sim_results: List[Dict] = []

    if check in ("static", "both"):
        findings = _run_static(contracts, rpc=rpc)
    if check in ("simulate", "both"):
        sim_results = _run_simulate(contracts, attacks, rpc=rpc)

    # --- Report ------------------------------------------------------------
    ui.console.print()
    if Confirm.ask("[step]Generate an HTML report?[/]", default=True):
        _write_report(scan, findings, sim_results)

    sim_successes = sum(1 for r in sim_results if r.get("success"))
    ui.console.print(ui.summary_panel([
        ("repo", repo_url),
        ("addresses", str(scan["total_addresses"])),
        ("contracts checked", str(len(contracts))),
        ("static findings", str(len(findings))),
        ("simulations", f"{len(sim_results)} run, {sim_successes} succeeded"),
    ], title="Hunt Complete"))
    ui.ok("Done. Happy hunting!")


def _write_report(scan: Dict, findings: List[Dict], sim_results: List[Dict]) -> None:
    """Persist findings JSON + HTML report into ./output."""
    out_dir = Path("output")
    out_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    payload = {
        "target": scan.get("repo_url", "wizard"),
        "contracts": scan.get("contracts", {}),
        "vulnerabilities": findings,
        "simulations": sim_results,
    }
    json_path = out_dir / f"wizard_{ts}.json"
    json_path.write_text(json.dumps(payload, indent=2))

    html_path = out_dir / f"wizard_{ts}.html"
    try:
        ReportGenerator().generate(payload, format="html", output=str(html_path))
    except Exception as e:  # reporter failure shouldn't kill the wizard
        ui.warn(f"HTML report failed ({e}) — JSON kept.")
        html_path = json_path

    with ui.spinner("Saving report"):
        pass
    ui.ok(f"Report saved: {html_path}")
