"""Sentinel Service -- the always-running monitoring daemon.

Ties together the database, watcher, scanner, and alerts into a
continuous monitoring loop.

Usage:
    from defihunter.sentinel.service import SentinelService
    service = SentinelService(rpc_url="https://ethereum-rpc.publicnode.com")
    service.add_protocol("Morpho", addresses=["0x..."])
    service.start()  # blocks, runs monitoring loop
"""
from __future__ import annotations

import json
import time
from typing import Any, Dict, List, Optional

from defihunter.sentinel.database import SentinelDB
from defihunter.sentinel.watcher import DeploymentWatcher
from defihunter.sentinel.alerts import AlertManager
from defihunter.sentinel.scheduler import parse_schedule


class SentinelService:
    """The Sentinel monitoring service.

    Continuously watches for:
        1. New contract deployments on monitored chains
        2. Changes in protocol health (new vulns, regressions)
        3. Threat intelligence from on-chain activity
    """

    def __init__(
        self,
        rpc_url: Optional[str] = None,
        db_path: Optional[str] = None,
        scan_interval: int = 3600,  # 1 hour (legacy, used if no schedule)
        watch_interval: int = 300,  # 5 minutes (deployment check interval)
        scan_schedule: Optional[str] = None,  # cron expression for rescanning
    ):
        self.rpc_url = rpc_url
        self.db = SentinelDB(db_path)
        self.watcher = DeploymentWatcher()
        self.alerts = AlertManager()
        self.scan_interval = scan_interval
        self.watch_interval = watch_interval
        self._running = False
        self._last_scan: Dict[int, float] = {}

        # Cron-based scheduling
        self._cron = None
        if scan_schedule:
            self._cron = parse_schedule(scan_schedule)
            print(f"[SENTINEL] Cron schedule: {scan_schedule} -> {self._cron}")

    def start(self) -> None:
        """Start the monitoring loop (blocks)."""
        self._running = True
        self.db.connect()

        print("[SENTINEL] Starting monitoring service...")
        print(f"[SENTINEL] RPC: {self.rpc_url or 'default'}")
        print(f"[SENTINEL] Watch interval: {self.watch_interval}s")
        if self._cron:
            print(f"[SENTINEL] Scan cron: {self._cron.expr}")
        else:
            print(f"[SENTINEL] Scan interval: {self.scan_interval}s")

        protocols = self.db.list_protocols()
        print(f"[SENTINEL] Monitoring {len(protocols)} protocol(s)")

        while self._running:
            try:
                self._tick()
            except KeyboardInterrupt:
                break
            except Exception as e:
                print(f"[SENTINEL] Error: {e}")

            time.sleep(self.watch_interval)

        print("[SENTINEL] Stopped.")

    def stop(self) -> None:
        self._running = False

    def _tick(self) -> None:
        """Single monitoring tick."""
        # 1. Check for new deployments on monitored chains
        self._check_deployments()

        # 2. Re-scan protocols that are due
        self._check_rescan()

        # 3. Deliver pending alerts
        self._deliver_alerts()

    def _check_deployments(self) -> None:
        """Check for new contract deployments on chains we're watching."""
        protocols = self.db.list_protocols()
        chains_seen = set()
        for p in protocols:
            chains_seen.add(p.get("chain", "ethereum"))

        for chain in chains_seen:
            try:
                # Get last block we checked
                last_block = self.watcher._last_blocks.get(chain, 0)

                # Check for new deployments
                deployments = self.watcher.check_new_deployments(chain, last_block)

                if deployments:
                    print(f"[SENTINEL] {len(deployments)} new deployment(s) on {chain}")

                    # Filter to DeFi contracts
                    if self.rpc_url:
                        deployments = self.watcher.filter_defi_contracts(
                            deployments, self.rpc_url
                        )

                    # Auto-scan interesting deployments
                    for dep in deployments[:5]:  # limit per tick
                        self._auto_scan_deployment(dep)

                    # Update last block
                    max_block = max(d.get("block", 0) for d in deployments)
                    if max_block > last_block:
                        self.watcher._last_blocks[chain] = max_block

            except Exception as e:
                print(f"[SENTINEL] Deployment check failed for {chain}: {e}")

    def _auto_scan_deployment(self, deployment: Dict) -> None:
        """Automatically scan a newly deployed contract."""
        addr = deployment.get("address", "")
        chain = deployment.get("chain", "ethereum")
        factory = deployment.get("factory_name", "")

        print(f"[SENTINEL] Auto-scanning new deployment: {addr} ({factory or 'unknown'})")

        # Find or create protocol entry
        name = factory or f"Auto-{addr[:8]}"
        protocol = self.db.get_protocol_by_name(name, chain)
        if not protocol:
            protocol_id = self.db.add_protocol(
                name=name,
                chain=chain,
                addresses=[addr],
                tags=["auto-detected"],
            )
        else:
            protocol_id = protocol["id"]
            # Add address to existing
            existing = json.loads(protocol.get("addresses", "[]"))
            if addr.lower() not in [a.lower() for a in existing]:
                existing.append(addr)
                self.db.update_protocol(protocol_id, addresses=existing)

        # Trigger scan
        self._scan_protocol(protocol_id)

    def _check_rescan(self) -> None:
        """Re-scan protocols that are due for re-scanning.

        Uses cron schedule if configured, otherwise uses interval.
        """
        now = time.time()
        protocols = self.db.list_protocols()

        # If cron is set, check if cron fires this tick
        if self._cron:
            from datetime import datetime
            if not self._cron.matches(datetime.now()):
                return  # cron doesn't fire this minute

        for p in protocols:
            pid = p["id"]
            last_scan = p.get("last_scan") or 0
            interval = self.scan_interval

            # Auto-detected protocols get scanned less frequently
            tags = json.loads(p.get("tags", "[]"))
            if "auto-detected" in tags:
                interval *= 3

            if now - last_scan >= interval:
                self._scan_protocol(pid)

    def _scan_protocol(self, protocol_id: int) -> None:
        """Run a scan on a protocol and record results."""
        protocol = self.db.get_protocol(protocol_id)
        if not protocol:
            return

        name = protocol["name"]
        chain = protocol.get("chain", "ethereum")
        addresses = json.loads(protocol.get("addresses", "[]"))

        if not addresses:
            return

        print(f"[SENTINEL] Scanning {name} ({len(addresses)} address(es))...")

        t0 = time.time()

        try:
            # Use existing scanner infrastructure
            from defihunter.core.analyzer import ContractAnalyzer

            rpc = self.rpc_url or "https://ethereum-rpc.publicnode.com"
            findings = []

            # Static analysis
            analyzer = ContractAnalyzer(rpc_url=rpc)
            for addr in addresses[:10]:
                try:
                    addr_findings = analyzer.analyze(addr)
                    findings.extend(addr_findings)
                except Exception:
                    continue

            duration = time.time() - t0

            # Get previous scan for comparison
            prev_scan = self.db.get_latest_scan(protocol_id)
            prev_findings = prev_scan["findings_count"] if prev_scan else 0
            prev_score = prev_scan["score"] if prev_scan else 100.0

            # Record scan
            scan_id = self.db.add_scan(
                protocol_id=protocol_id,
                chain=chain,
                findings=findings,
                fork_proven=sum(1 for f in findings if f.get("confirmed")),
                duration_s=duration,
                rpc_url=rpc,
            )

            # Get new scan data
            scan = self.db.get_latest_scan(protocol_id)
            new_score = scan["score"]
            new_findings = scan["findings_count"]
            new_critical = scan["critical"]
            new_high = scan["high"]

            # Check for changes and create alerts
            if new_findings > prev_findings:
                # New vulns found
                new_count = new_findings - prev_findings
                self.db.add_alert(
                    protocol_id=protocol_id,
                    scan_id=scan_id,
                    alert_type="new_vuln",
                    severity="HIGH" if new_critical or new_high else "MEDIUM",
                    message=f"{new_count} new finding(s) detected ({new_findings} total, was {prev_findings})",
                )
                print(f"[SENTINEL] [!!] {name}: {new_count} new finding(s)")

            elif new_findings < prev_findings:
                # Vulns resolved
                resolved = prev_findings - new_findings
                self.db.add_alert(
                    protocol_id=protocol_id,
                    scan_id=scan_id,
                    alert_type="cleanup",
                    severity="LOW",
                    message=f"{resolved} finding(s) resolved ({new_findings} total, was {prev_findings})",
                )
                print(f"[SENTINEL] [+] {name}: {resolved} finding(s) resolved")

            # Check for regression (score dropped)
            if prev_scan and new_score < prev_score - 5:
                self.db.add_alert(
                    protocol_id=protocol_id,
                    scan_id=scan_id,
                    alert_type="regression",
                    severity="HIGH",
                    message=f"Score dropped: {prev_score:.0f} -> {new_score:.0f}",
                )
                print(f"[SENTINEL] [!!] {name}: REGRESSION score {prev_score:.0f} -> {new_score:.0f}")

            print(f"[SENTINEL] {name}: score={new_score:.0f}, findings={new_findings}, duration={duration:.1f}s")

        except Exception as e:
            print(f"[SENTINEL] Scan failed for {name}: {e}")

    def _deliver_alerts(self) -> None:
        """Deliver pending alerts to configured channels."""
        pending = self.db.get_pending_alerts()
        if not pending:
            return

        for alert in pending:
            results = self.alerts.send_alert(
                protocol=alert.get("protocol_name", "Unknown"),
                alert_type=alert["alert_type"],
                severity=alert.get("severity", "INFO"),
                message=alert["message"],
                chain=alert.get("protocol_chain", "ethereum"),
            )

            # Mark as delivered if any channel succeeded
            if any(results.values()):
                channel = next(k for k, v in results.items() if v)
                self.db.mark_alert_sent(alert["id"], channel)

    # ------------------------------------------------------------------
    # Manual operations
    # ------------------------------------------------------------------

    def add_protocol(
        self,
        name: str,
        chain: str = "ethereum",
        addresses: Optional[List[str]] = None,
        website: Optional[str] = None,
        github: Optional[str] = None,
    ) -> int:
        """Add a protocol to monitor."""
        return self.db.add_protocol(
            name=name, chain=chain, addresses=addresses,
            website=website, github=github,
        )

    def scan_now(self, protocol_id: int) -> Dict:
        """Immediately scan a protocol (outside the monitoring loop)."""
        self._scan_protocol(protocol_id)
        return self.db.get_latest_scan(protocol_id) or {}

    def get_status(self) -> Dict[str, Any]:
        """Get current Sentinel status."""
        stats = self.db.get_stats()
        protocols = self.db.list_protocols()

        return {
            "running": self._running,
            "protocols": len(protocols),
            "stats": stats,
            "channels": [c.name for c in self.alerts.channels],
        }
