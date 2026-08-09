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
import subprocess
import os
import re
from datetime import datetime
from pathlib import Path
from typing import Dict, List, Optional

from rich.prompt import Confirm, Prompt
from rich.text import Text

from defihunter import ui
from defihunter.core import config, github
from defihunter.core.analyzer import ContractAnalyzer, analyze_repo_dir
from defihunter.core.reporter import ReportGenerator
from defihunter.core.simulator import AttackSimulator, ForkSimulator

ALL_ATTACKS = [
    "inflation", "admin", "governance", "oracle", "reentrancy", "bridge",
    "sandwich", "twap", "flashloan", "withdraw", "initialize", "permit",
    "liquidation", "forcesend", "peg", "crossfunc", "delegatecall", "mint",
]
RECOMMENDED_ATTACKS = ["initialize", "admin", "mint", "inflation", "withdraw", "permit"]


def _norm_identity(value: Optional[str]) -> str:
    """Normalize a name/symbol for comparison: lowercase, strip quotes/spaces."""
    return re.sub(r"\s+", " ", (value or "").strip().strip('"')).lower()


def identity_match(expected: str, name: Optional[str], symbol: Optional[str]) -> str:
    """Compare an expected protocol name to the anchor's on-chain name/symbol.

    Returns one of:
      "match"    — on-chain identity contains/equals the expected name
      "mismatch" — contract responds to name()/symbol() but nothing matches
      "unknown"  — no expected name, or the contract has no ERC20 metadata
    Used to flag wrong anchors (e.g. DefiLlama resolves 'eigenlayer' to
    EigenCloud but the token says 'EigenLayer' — code exists, identity doesn't).
    """
    exp = _norm_identity(expected)
    candidates = [c for c in (_norm_identity(name), _norm_identity(symbol)) if c]
    if not exp or not candidates:
        return "unknown"
    for c in candidates:
        if c == exp or exp in c:
            return "match"
    return "mismatch"


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
        ("Only a name?", "Just type the protocol name (e.g. spark, aave, lido) — we resolve it via DefiLlama"),
        ("Example", "https://github.com/Layr-Labs/eigenlayer-contracts"),
    ], title="Protocol Source"))
    while True:
        answer = Prompt.ask(
            "[step]GitHub repo URL, local folder, addresses, or protocol name[/]"
            + " [muted](comma/space separated)[/]"
        ).strip()
        if not answer:
            ui.error("Empty input — paste a repo link, a folder path, addresses, or a protocol name.")
            continue
        if github.is_repo_dir(answer):
            return answer
        if github.looks_like_git_url(answer):
            return answer
        if github.is_address_list(answer):
            return answer
        if answer.lower().startswith("llama:"):
            return answer  # explicit protocol-name request (don't re-prefix)
        if Confirm.ask(
            f"[warn]Not a repo/folder/addresses — look up '{answer}' as a "
            "protocol name on DefiLlama?[/]",
            default=True,
        ):
            return f"llama:{answer}"
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
    while True:
        answer = Prompt.ask(
            f"[step]RPC URL[/] [muted](Enter = {saved_rpc})[/]", default=saved_rpc
        ).strip()
        if answer.lower() in ("skip", "s", "none"):
            return None
        if not answer:
            return saved_rpc
        if not config.looks_like_rpc(answer):
            ui.warn("That doesn't look like an RPC URL (http:// or https://). "
                    "Try again, or type 'skip' to skip verification.")
            continue
        if answer != saved_rpc and Confirm.ask(
                "[step]Save this RPC for future hunts?[/]", default=True):
            path = config.save_rpc(answer)
            ui.ok(f"Saved RPC to {path} — it will pre-fill next time.")
        return answer


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


def _run_static(scan: Dict, contracts: Dict[str, Dict], rpc: Optional[str] = None) -> List[Dict]:
    """Run static analysis.

    Source-level first: when the scan produced a local clone (repo_dir is a
    real directory), every protocol-owned .sol file is analyzed line-by-line
    with file:line evidence — no Etherscan key needed. Address-level analysis
    (Etherscan source) only kicks in for address-list scans, where there is
    no local source to read.

    Sets scan["_analysis_status"] so the verdict can be honest: 'skipped'
    when nothing was actually analyzed (never claim CLEAN on no data),
    'clean' when analysis ran and found nothing, 'findings' otherwise.
    """
    ui.rule("STATIC ANALYSIS")
    findings: List[Dict] = []
    scan["_analysis_status"] = "skipped"

    repo_dir = scan.get("repo_dir", "")
    local = Path(repo_dir).expanduser().resolve() if repo_dir else None
    if local and local.is_dir():
        with ui.spinner(f"Analyzing Solidity source in {repo_dir}"):
            findings = analyze_repo_dir(str(local), repo_label=scan.get("repo_url", repo_dir))
        ui.info(f"Analyzed {len({f['file'] for f in findings})} source file(s) "
                f"({len(findings)} hit(s))")
        scan["_analysis_status"] = "findings" if findings else "clean"
        if findings:
            ui.console.print(ui.findings_table(findings, title="Source Findings"))
            _print_attack_routes(findings)
        else:
            ui.ok("No obvious vulnerabilities found in source.")
        return findings

    # Address-list fallback: no local source, use the Etherscan-backed analyzer.
    import os as _os
    if not _os.getenv("ETHERSCAN_API_KEY"):
        ui.warn("No source to analyze: address-only scan without ETHERSCAN_API_KEY "
                "and no repo clone. Set ETHERSCAN_API_KEY or scan a repo to get "
                "real static findings — verdict will be INCONCLUSIVE, not CLEAN.")
        return findings

    analyzer = ContractAnalyzer(rpc_url=rpc)
    progress, task = ui.progress_bar(len(contracts), "Analyzing contracts")
    with progress:
        for addr in contracts:
            result = analyzer.analyze(addr)
            for f in result:
                f.setdefault("endpoint", addr)
            findings.extend(result)
            progress.advance(task)
    scan["_analysis_status"] = "findings" if findings else "clean"
    if findings:
        ui.warn(f"{len(findings)} finding(s):")
        ui.console.print(ui.findings_table(findings))
        _print_attack_routes(findings)
    else:
        ui.ok("No obvious vulnerabilities found")
    return findings


# Attack tags → short exploitation route, so each finding chains straight
# into the wizard's simulation menu (option 4 of the hunt).
ATTACK_ROUTES = {
    "mint": "mint — call mint() as an attacker on an anvil fork; if it succeeds, supply is unbounded",
    "initialize": "initialize — first-caller proxy takeover; replay initialize() on a fork from a fresh account",
    "delegatecall": "delegatecall — point the target at attacker logic and confirm storage/balance impact on a fork",
    "reentrancy": "reentrancy — chain a callback (receive/onFlashLoan) around the external call and double-drain",
    "oracle": "oracle — flash-loan swap the spot pair, then call the pricing function to prove distortion",
    "admin": "admin — verify the privileged role is timelocked/DAO-gated; key compromise = full drain",
}


def _print_attack_routes(findings: List[Dict]) -> None:
    """Show the attack path chained to each static finding."""
    routes = []
    for f in findings:
        tag = f.get("attack")
        if tag and tag in ATTACK_ROUTES:
            routes.append(f"{f.get('title', 'finding')} → {ATTACK_ROUTES[tag]}")
    if routes:
        ui.console.print()
        ui.console.print(ui.summary_panel(
            [(f"attack route", r) for r in sorted(set(routes))],
            title="Chained Attack Routes",
        ))


def _run_fork_verify(findings: List[Dict], contracts: Dict[str, Dict],
                     rpc: Optional[str], repo_dir: Optional[str] = None) -> List[Dict]:
    """Prove the callable-by-anyone findings on a real anvil fork.

    Static analysis says *possible*; an eth_call from an attacker account on
    a mainnet fork says *provable*. The source findings carry a relative file
    path, so we resolve them to live addresses two ways:

      1. recon source-mention mapping: which deployed address was declared in
         the same file (works when the repo inlines addresses in source), and
      2. deployment-artifact mapping (new): contract name → address from
         script/configs/*.json, foundry broadcast/run-latest.json and
         hardhat-deploy deployments/ — the layouts that actually ship live
         mainnet addresses (e.g. eigenlayer's mainnet.json deployment map).
    """
    ui.rule("FORK VERIFICATION")
    verifiable = [f for f in findings
                  if f.get("attack") in ("mint", "initialize", "delegatecall",
                                         "reentrancy", "arbitrarycall",
                                         "approve", "selfdestruct")]
    if not verifiable:
        ui.info("No fork-verifiable findings: every finding needs a callable-"
                "by-anyone attack route (mint/initialize/delegatecall/"
                "reentrancy/…) on a known address. Run a repo scan or scan "
                "verified source to get provable routes.")
        return []

    # 1) file (repo-relative) -> deployed addresses that mention it in source
    by_file: Dict[str, List[str]] = {}
    for addr, info in contracts.items():
        for src in info.get("sources") or []:
            by_file.setdefault(str(src), []).append(addr)

    # 2) contract name -> deployed addresses from deployment artifacts
    deployments: Dict[str, List[str]] = {}
    if repo_dir and Path(repo_dir).is_dir():
        deployments = github.extract_deployments(Path(repo_dir))
        if deployments:
            ui.info(f"Resolved {len(deployments)} contract(s) to live address(es) "
                    "from deployment artifacts (configs/broadcast/deployments).")

    resolved = []
    for f in verifiable:
        # 0) address-scan findings already KNOW their live address — prove
        #    them straight away, no repo mapping needed
        faddrs = [f["address"]] if f.get("address") else []
        if faddrs:
            for a in faddrs:
                resolved.append((f, a.lower()))
            continue
        fname = str(f.get("file", ""))
        addrs = sorted(set(by_file.get(fname, [])))
        norm = github._norm_name(Path(fname).stem)
        addrs += deployments.get(norm, [])
        # strip dupes, keep order, cap at 3 deployments per finding
        seen, ordered = set(), []
        for a in addrs:
            a = a.lower()
            if a not in seen:
                seen.add(a)
                ordered.append(a)
        for addr in ordered[:3]:
            resolved.append((f, addr))
    if not resolved:
        ui.info("No deployed addresses found for the flagged files or their "
                "contract names — fork verification needs a live address to call.")
        return []

    results: List[Dict] = []
    with ui.spinner("Booting anvil mainnet fork — first state fetch can take ~20s"):
        with ForkSimulator(rpc_url=rpc) as fork:
            if not fork.available:
                ui.warn(fork.why_not)
                return results
            ui.info(f"Anvil fork live on {fork.rpc_url} — verifying {len(resolved)} finding→address hit(s)")
            for f, addr in resolved:
                res = fork.run(f["attack"], addr, source_finding=f)
                results.append(res)
    ui.console.print(ui.attack_flow(findings, results))
    ok = sum(1 for r in results if r.get("success"))
    if ok:
        ui.warn(f"{ok} finding(s) CONFIRMED callable by an arbitrary account — "
                "these are real attack surfaces, not heuristics.")
    return results


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
                progress.update(task, description=f"Running {attack} on {addr[:10]}…")
                res = simulator.run(attack, addr)
                res.update({"address": addr, "attack": attack})
                results.append(res)
                progress.advance(task)

    ok_count = sum(1 for r in results if r.get("success"))
    if ok_count:
        ui.warn(f"{ok_count} attack(s) succeeded — investigate these:")
    # compact results table: only signal, no 36-row failure grid
    from rich.table import Table
    from rich import box as rich_box
    hits = [r for r in results if r.get("success")]
    if hits:
        t = Table(title="Simulation Hits", box=rich_box.ROUNDED,
                  border_style="magenta", header_style="bold magenta")
        t.add_column("Attack", style="bold white")
        t.add_column("Address", style="addr", no_wrap=True)
        t.add_column("Result", style="bold")
        for r in hits:
            t.add_row(r["attack"], r["address"], "[success]SUCCESS ✔[/]")
        ui.console.print(t)
    else:
        ui.info(f"{len(results)} attack simulation(s) run, 0 succeeded — "
                "selectors absent or guarded on these contracts.")
    if ok_count:
        ui.warn("Remember: simulator hits are selector-based — verify each success "
                "with `cast call` or an anvil fork before reporting.")
    return results


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def _ask_org_repo(org: str) -> bool:
    """Offer to scan a repo from the protocol's GitHub org (deeper than anchor)."""
    return Confirm.ask(
        f"[step]Also scan a repo from github.com/{org}?[/] "
        "[muted](the anchor is often just the token — "
        "real contracts usually live in a repo)[/]",
        default=False,
    )


def _rate_limit_hint() -> str:
    """Explain a failed GitHub org listing based on whether a token is loaded.

    The most common cause is a stale shell: GITHUB_TOKEN lives in ~/.zshrc
    but the running terminal predates the export, so the process never saw it.
    """
    if os.getenv("GITHUB_TOKEN") or os.getenv("GH_TOKEN"):
        return ("GITHUB_TOKEN is set but GitHub still refused — the token may "
                "be expired, revoked, or missing public-repo read access. "
                "Paste a repo URL manually, or fix the token and retry.")
    return ("No GITHUB_TOKEN in this shell. If you exported it in ~/.zshrc, "
            "open a NEW terminal (or 'source ~/.zshrc'), or run: "
            "export GITHUB_TOKEN=<token>. Until then, paste a repo URL manually.")


def _pick_org_repo(org: str) -> Optional[str]:
    """List the org's repos, auto-rank by deployed-address likelihood, let the
    user pick one. Returns 'org/repo' or None."""
    repos = github.list_org_repos(org)
    if not repos:
        ui.warn(f"Couldn't list repos for {org}. {_rate_limit_hint()}")
        return None
    # Auto-detect which repos hold the deployed contract addresses, so the
    # user doesn't have to guess from names/descriptions. Source-code repos
    # (Solidity/Vyper) sort first — the codebase IS the attack surface for a
    # security hunt, even when a deployer tool matches more tree signals.
    with ui.spinner(f"Scanning {len(repos[:15])} repos for deployed addresses…"):
        scores = github.detect_ca_repos(repos)
    top = sorted(
        repos[:15],
        key=lambda r: (not github.is_source_repo(r), -scores.get(r["name"], 0)),
    )
    ca_count = sum(1 for r in top if scores.get(r["name"], 0) >= 4)
    ui.console.print()
    ui.console.print(ui.summary_panel([
        (f"{'✓' if scores.get(r['name'], 0) >= 4 else ' '} {i}. {r['name']}",
         f"{r['language']} · ★{r['stars']} · updated {r['updated']}"
         + (f" — {r['description']}" if r["description"] else ""))
        for i, r in enumerate(top, 1)
    ], title=f"Repos in {org} (✓ = contains deployed addresses — auto-detected)"))
    if ca_count:
        ui.info(f"✓ marked {ca_count} repo(s) likely to contain the deployed "
                "contract addresses (deployments/, broadcast/, addresses.json…). "
                "Solidity/Vyper source repos rank higher, so the canonical "
                "contracts repo usually floats to the top.")
    while True:
        ans = Prompt.ask(
            "[step]Pick a repo number[/] [muted](or 'skip')[/]", default="skip"
        ).strip().lower()
        if ans in ("skip", "", "n", "no"):
            return None
        try:
            idx = int(ans)
            if 1 <= idx <= len(top):
                return top[idx - 1]["name"]
        except ValueError:
            pass
        ui.warn("Enter a number from the list or 'skip'.")


def _scan_llama_protocol(source: str, rpc: Optional[str]) -> Dict:
    """Resolve 'llama:<name>' via DefiLlama, scan the anchor addresses, and
    optionally go deeper by scanning a repo from the protocol's GitHub org."""
    from defihunter.core import protocols

    name = source.split(":", 1)[1].strip()
    ui.info(f"Resolving '{name}' on DefiLlama…")
    info = protocols.resolve_protocol(name)
    if info is None:
        raise RuntimeError(
            f"Couldn't find '{name}' on DefiLlama. Try the exact protocol name "
            "(e.g. spark, aave, lido, makerdao), or paste a repo/addresses instead."
        )
    ui.ok(f"Found: {info['name']}")
    if info["url"]:
        ui.info(f"Website: {info['url']}")
    if info["chains"]:
        ui.info("Chains: " + ", ".join(info["chains"]))
    orgs = info.get("github_orgs") or []
    if orgs:
        ui.info("GitHub: " + ", ".join(
            f"https://github.com/{org}" for org in orgs))
    if not info["addresses"]:
        raise RuntimeError(
            f"DefiLlama has no on-chain addresses for '{info['name']}'. "
            "Check the protocol's GitHub (above) or paste addresses manually."
        )
    ui.info(f"Anchor address(es): {len(info['addresses'])}")

    with ui.spinner(f"Scanning {len(info['addresses'])} anchor address(es)"):
        scan = github.scan_addresses(", ".join(info["addresses"]), rpc_url=rpc)
    scan["repo_url"] = f"DefiLlama: {info['name']}"

    # Anchor identity check: 'code exists' isn't enough — confirm the on-chain
    # name/symbol matches what DefiLlama resolved. Catches wrong anchors the
    # sims would otherwise burn hours on.
    verified_anchors = {a: i for a, i in scan["contracts"].items() if i.get("verified")}
    if verified_anchors:
        from rich.table import Table as RichTable
        from rich import box as rich_box
        t = RichTable(
            title=f"Anchor identity vs '{info['name']}'",
            box=rich_box.ROUNDED, border_style="cyan", header_style="bold cyan",
        )
        t.add_column("Address", style="addr", no_wrap=True)
        t.add_column("On-chain name", style="bold white")
        t.add_column("Symbol", style="bold")
        t.add_column("Verdict", style="bold")
        for addr, entry in verified_anchors.items():
            name, symbol = entry.get("name", "Unknown"), entry.get("symbol")
            verdict = identity_match(info["name"], name, symbol)
            if verdict == "match":
                v_txt, v_style = "✓ matches", "success"
            elif verdict == "unknown":
                v_txt, v_style = "? no metadata", "muted"
            else:
                v_txt, v_style = "✗ MISMATCH", "error"
            entry["identity"] = verdict
            t.add_row(addr, str(name), str(symbol or "—"),
                      Text(v_txt, style=v_style))
        ui.console.print(t)
        verdicts = [e.get("identity") for e in verified_anchors.values()]
        if "mismatch" in verdicts:
            ui.warn("Anchor identity doesn't match the resolved protocol name. "
                    "DefiLlama may have mapped a different protocol (e.g. a "
                    "same-name fork) — double-check before trusting the sims.")
        elif "match" in verdicts:
            ui.ok("Anchor identity confirmed on-chain.")
        else:
            ui.info("Anchors expose no ERC20 metadata — proceeding on code check only.")

    # Depth: the anchor is often just the token — offer to scan a real repo.
    if orgs and _ask_org_repo(orgs[0]):
        repo = _pick_org_repo(orgs[0])
        if repo:
            ui.info(f"Also scanning https://github.com/{repo} …")
            deep = None
            try:
                with ui.spinner(f"Scanning {repo}"):
                    deep = github.scan_repo(f"https://github.com/{repo}", rpc_url=rpc)
            except RuntimeError as e:
                # transient clone/network failure — don't kill the hunt
                ui.warn(f"Couldn't scan {repo} ({e}). Continuing with the "
                        "anchor scan only.")
            if deep:
                scan["contracts"].update(deep["contracts"])
                scan["total_addresses"] += deep["total_addresses"]
                scan["repo_dir"] = f"DefiLlama: {info['name']} + github.com/{repo}"
                scan["deep_repo"] = repo
    return scan


def run_wizard(
    verbose: bool = False,
    repo_url: Optional[str] = None,
    check: Optional[str] = None,
    attacks: Optional[List[str]] = None,
    version: str = "",
) -> None:
    """Boot the guided hunt. Pass repo_url/check/attacks to skip those prompts."""
    ui.intro(version)

    # --- 1. Repo -----------------------------------------------------------
    if repo_url:
        ui.step("Protocol source", repo_url)
    else:
        repo_url = ask_repo_url()

    # --- 2. RPC ------------------------------------------------------------
    rpc = ask_rpc()

    # --- scan --------------------------------------------------------------
    ui.rule("EXTRACTING CONTRACTS")
    try:
        if repo_url.startswith("llama:"):
            scan = _scan_llama_protocol(repo_url, rpc)
        elif github.is_address_list(repo_url):
            with ui.spinner(f"Scanning {repo_url}"):
                scan = github.scan_addresses(repo_url, rpc_url=rpc)
        else:
            with ui.spinner(f"Scanning {repo_url}"):
                scan = github.scan_repo(repo_url, rpc_url=rpc)
    except (RuntimeError, subprocess.TimeoutExpired) as e:
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
    fork_results: List[Dict] = []

    if check in ("static", "both"):
        findings = _run_static(scan, contracts, rpc=rpc)
        if findings and not os.environ.get("DEFIHUNTER_SKIP_FORK"):
            fork_results = _run_fork_verify(findings, contracts, rpc=rpc,
                                            repo_dir=scan.get("repo_dir"))
    if check in ("simulate", "both"):
        sim_results = _run_simulate(contracts, attacks, rpc=rpc)

    # --- Report ------------------------------------------------------------
    ui.console.print()
    if Confirm.ask("[step]Generate an HTML report?[/]", default=True):
        _write_report(scan, findings, sim_results, fork_results)

    sim_successes = sum(1 for r in sim_results if r.get("success"))
    fork_successes = sum(1 for r in fork_results if r.get("success"))
    all_findings = list(findings) + [{
        "severity": "CRITICAL" if r.get("success") else "MEDIUM",
        "title": f"fork-confirmed {r.get('attack', '')} on {r.get('target', '')[:12]}…",
        "endpoint": r.get("target", ""),
    } for r in fork_results if r.get("success")]
    analyzed = scan.get("_analysis_status") != "skipped"
    level = ui.threat_level(all_findings, analyzed=analyzed)
    ui.console.print()
    ui.console.print(ui.attack_surface_gauge(all_findings, analyzed=analyzed))
    ui.console.print(ui.severity_chart(all_findings, analyzed=analyzed))
    if not analyzed:
        ui.warn("Verdict is INCONCLUSIVE — no source was analyzed (no repo clone "
                "and no ETHERSCAN_API_KEY). Re-run scanning a repo for a real verdict.")
    ui.hunt_complete([
        ("repo", scan.get("repo_url", repo_url)),
        ("addresses", str(scan["total_addresses"])),
        ("contracts checked", str(len(contracts))),
        ("static findings", str(len(findings))),
        ("fork-verified", f"{len(fork_results)} run, {fork_successes} exploitable"),
        ("simulations", f"{len(sim_results)} run, {sim_successes} succeeded"),
    ], level=level)
    ui.ok("Done. Happy hunting! 🏆")


def _write_report(scan: Dict, findings: List[Dict], sim_results: List[Dict],
                  fork_results: Optional[List[Dict]] = None) -> None:
    """Persist findings JSON + HTML report into ./output."""
    out_dir = Path("output")
    out_dir.mkdir(exist_ok=True)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")

    payload = {
        "target": scan.get("repo_url", "wizard"),
        "contracts": scan.get("contracts", {}),
        "vulnerabilities": findings,
        "simulations": sim_results,
        "fork_verified": fork_results or [],
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
