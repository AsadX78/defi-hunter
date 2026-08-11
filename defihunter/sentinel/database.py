"""Sentinel Database -- SQLite-backed protocol tracking and scan history.

Tables:
    protocols     -- monitored protocols (name, chain, addresses, added_at)
    scans         -- each scan run (protocol_id, timestamp, findings, score)
    findings      -- individual findings per scan (severity, title, attack)
    alerts        -- sent alerts (protocol_id, type, message, sent_at)
    threat_intel  -- ingested attack patterns (type, chain, source, added_at)
"""
from __future__ import annotations

import json
import sqlite3
import time
from pathlib import Path
from typing import Any, Dict, List, Optional

DEFAULT_DB_PATH = Path.home() / ".config" / "defi-hunter" / "sentinel.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS protocols (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    chain       TEXT NOT NULL DEFAULT 'ethereum',
    addresses   TEXT NOT NULL DEFAULT '[]',  -- JSON array of 0x addresses
    website     TEXT,
    github      TEXT,
    added_at    REAL NOT NULL,
    last_scan   REAL,
    status      TEXT NOT NULL DEFAULT 'active',  -- active / paused / archived
    tags        TEXT DEFAULT '[]',  -- JSON array of tags
    UNIQUE(name, chain)
);

CREATE TABLE IF NOT EXISTS scans (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol_id INTEGER NOT NULL REFERENCES protocols(id),
    timestamp   REAL NOT NULL,
    chain       TEXT NOT NULL,
    findings_count INTEGER NOT NULL DEFAULT 0,
    critical    INTEGER NOT NULL DEFAULT 0,
    high        INTEGER NOT NULL DEFAULT 0,
    medium      INTEGER NOT NULL DEFAULT 0,
    low         INTEGER NOT NULL DEFAULT 0,
    info        INTEGER NOT NULL DEFAULT 0,
    score       REAL NOT NULL DEFAULT 100.0,  -- 0-100 security score
    verdict     TEXT NOT NULL DEFAULT 'CLEAN',  -- CLEAN / LOW / MODERATE / HIGH / CRITICAL
    fork_proven INTEGER NOT NULL DEFAULT 0,  -- number of fork-proven findings
    duration_s  REAL NOT NULL DEFAULT 0,
    rpc_url     TEXT,
    report_path TEXT,  -- path to generated HTML report
    raw_findings TEXT DEFAULT '[]',  -- JSON array of finding dicts
    UNIQUE(protocol_id, timestamp)
);

CREATE TABLE IF NOT EXISTS findings (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id     INTEGER NOT NULL REFERENCES scans(id),
    severity    TEXT NOT NULL,
    title       TEXT NOT NULL,
    attack      TEXT,
    endpoint    TEXT,
    file_path   TEXT,
    line        INTEGER,
    confirmed   INTEGER NOT NULL DEFAULT 0,  -- 1 if fork-proven
    description TEXT,
    UNIQUE(scan_id, title, endpoint)
);

CREATE TABLE IF NOT EXISTS alerts (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    protocol_id INTEGER NOT NULL REFERENCES protocols(id),
    scan_id     INTEGER REFERENCES scans(id),
    alert_type  TEXT NOT NULL,  -- new_vuln / regression / launch_ready / cleanup
    severity    TEXT,
    message     TEXT NOT NULL,
    sent_at     REAL,
    channel     TEXT,  -- telegram / discord / webhook / email
    delivered   INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS threat_intel (
    id          INTEGER PRIMARY KEY AUTOINCREMENT,
    attack_type TEXT NOT NULL,
    chain       TEXT NOT NULL,
    tx_hash     TEXT,
    loss_amount TEXT,  -- e.g. "$2.3M"
    source      TEXT,  -- how we found out
    pattern     TEXT,  -- the attack pattern description
    added_at    REAL NOT NULL,
    processed   INTEGER NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_scans_protocol ON scans(protocol_id, timestamp DESC);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_alerts_protocol ON alerts(protocol_id, sent_at DESC);
CREATE INDEX IF NOT EXISTS idx_threat_intel_type ON threat_intel(attack_type, added_at DESC);
"""


class SentinelDB:
    """SQLite database for Sentinel protocol tracking."""

    def __init__(self, db_path: Optional[str] = None):
        self.db_path = Path(db_path) if db_path else DEFAULT_DB_PATH
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._conn: Optional[sqlite3.Connection] = None

    def connect(self) -> None:
        self._conn = sqlite3.connect(str(self.db_path))
        self._conn.row_factory = sqlite3.Row
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        self._conn.executescript(SCHEMA)

    def close(self) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def __enter__(self) -> "SentinelDB":
        self.connect()
        return self

    def __exit__(self, *a) -> None:
        self.close()

    @property
    def conn(self) -> sqlite3.Connection:
        if not self._conn:
            self.connect()
        return self._conn

    # ------------------------------------------------------------------
    # Protocols
    # ------------------------------------------------------------------

    def add_protocol(
        self,
        name: str,
        chain: str = "ethereum",
        addresses: Optional[List[str]] = None,
        website: Optional[str] = None,
        github: Optional[str] = None,
        tags: Optional[List[str]] = None,
    ) -> int:
        """Add a protocol to monitor. Returns protocol_id."""
        cur = self.conn.execute(
            "INSERT OR IGNORE INTO protocols (name, chain, addresses, website, github, added_at, tags) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (name, chain, json.dumps(addresses or []), website, github,
             time.time(), json.dumps(tags or [])),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_protocol(self, protocol_id: int) -> Optional[Dict]:
        row = self.conn.execute("SELECT * FROM protocols WHERE id=?", (protocol_id,)).fetchone()
        return dict(row) if row else None

    def get_protocol_by_name(self, name: str, chain: str = "ethereum") -> Optional[Dict]:
        row = self.conn.execute(
            "SELECT * FROM protocols WHERE name=? AND chain=?", (name, chain)
        ).fetchone()
        return dict(row) if row else None

    def list_protocols(self, status: str = "active") -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM protocols WHERE status=? ORDER BY name", (status,)
        ).fetchall()
        return [dict(r) for r in rows]

    def update_protocol(self, protocol_id: int, **kwargs) -> None:
        allowed = {"name", "chain", "addresses", "website", "github", "status", "tags", "last_scan"}
        sets = []
        vals = []
        for k, v in kwargs.items():
            if k not in allowed:
                continue
            if k in ("addresses", "tags"):
                v = json.dumps(v)
            sets.append(f"{k}=?")
            vals.append(v)
        if not sets:
            return
        vals.append(protocol_id)
        self.conn.execute(f"UPDATE protocols SET {', '.join(sets)} WHERE id=?", vals)
        self.conn.commit()

    def remove_protocol(self, protocol_id: int) -> None:
        self.conn.execute("UPDATE protocols SET status='archived' WHERE id=?", (protocol_id,))
        self.conn.commit()

    def delete_protocol(self, protocol_id: int) -> None:
        """Permanently delete a protocol and all its scans/findings/alerts."""
        scans = self.conn.execute(
            "SELECT id FROM scans WHERE protocol_id=?", (protocol_id,)
        ).fetchall()
        for scan in scans:
            self.conn.execute("DELETE FROM findings WHERE scan_id=?", (scan["id"],))
        self.conn.execute("DELETE FROM scans WHERE protocol_id=?", (protocol_id,))
        self.conn.execute("DELETE FROM alerts WHERE protocol_id=?", (protocol_id,))
        self.conn.execute("DELETE FROM protocols WHERE id=?", (protocol_id,))
        self.conn.commit()

    def search_protocols(
        self, name: Optional[str] = None, chain: Optional[str] = None
    ) -> List[Dict]:
        """Search protocols by name (case-insensitive) and/or chain."""
        if name and chain:
            rows = self.conn.execute(
                "SELECT * FROM protocols WHERE LOWER(name) LIKE ? AND chain=?",
                (f"%{name.lower()}%", chain),
            ).fetchall()
        elif name:
            rows = self.conn.execute(
                "SELECT * FROM protocols WHERE LOWER(name) LIKE ?",
                (f"%{name.lower()}%",),
            ).fetchall()
        elif chain:
            rows = self.conn.execute(
                "SELECT * FROM protocols WHERE chain=?", (chain,)
            ).fetchall()
        else:
            return self.list_protocols()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Scans
    # ------------------------------------------------------------------

    def add_scan(
        self,
        protocol_id: int,
        chain: str,
        findings: List[Dict],
        fork_proven: int = 0,
        duration_s: float = 0,
        rpc_url: Optional[str] = None,
        report_path: Optional[str] = None,
    ) -> int:
        """Record a scan result. Returns scan_id."""
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = str(f.get("severity", "INFO")).upper()
            counts[sev] = counts.get(sev, 0) + 1

        total = len(findings)
        score = self._calc_score(counts)
        verdict = self._score_to_verdict(score)

        cur = self.conn.execute(
            "INSERT INTO scans (protocol_id, timestamp, chain, findings_count, "
            "critical, high, medium, low, info, score, verdict, fork_proven, "
            "duration_s, rpc_url, report_path, raw_findings) "
            "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            (protocol_id, time.time(), chain, total,
             counts["CRITICAL"], counts["HIGH"], counts["MEDIUM"],
             counts["LOW"], counts["INFO"], score, verdict,
             fork_proven, duration_s, rpc_url, report_path,
             json.dumps(findings)),
        )
        self.conn.commit()

        # Update protocol last_scan
        self.conn.execute(
            "UPDATE protocols SET last_scan=? WHERE id=?",
            (time.time(), protocol_id),
        )
        self.conn.commit()

        scan_id = cur.lastrowid

        # Insert individual findings
        for f in findings:
            try:
                self.conn.execute(
                    "INSERT OR IGNORE INTO findings (scan_id, severity, title, "
                    "attack, endpoint, file_path, line, confirmed, description) "
                    "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                    (scan_id,
                     str(f.get("severity", "INFO")).upper(),
                     f.get("title", "Unknown"),
                     f.get("attack"),
                     f.get("endpoint") or f.get("address"),
                     f.get("file"),
                     f.get("line"),
                     1 if f.get("confirmed") else 0,
                     f.get("description")),
                )
            except sqlite3.IntegrityError:
                pass
        self.conn.commit()

        return scan_id

    def get_latest_scan(self, protocol_id: int) -> Optional[Dict]:
        row = self.conn.execute(
            "SELECT * FROM scans WHERE protocol_id=? ORDER BY timestamp DESC LIMIT 1",
            (protocol_id,),
        ).fetchone()
        return dict(row) if row else None

    def get_scan_history(self, protocol_id: int, limit: int = 30) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM scans WHERE protocol_id=? ORDER BY timestamp DESC LIMIT ?",
            (protocol_id, limit),
        ).fetchall()
        return [dict(r) for r in rows]

    def get_scan_findings(self, scan_id: int) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM findings WHERE scan_id=? ORDER BY severity", (scan_id,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Alerts
    # ------------------------------------------------------------------

    def add_alert(
        self,
        protocol_id: int,
        alert_type: str,
        message: str,
        severity: Optional[str] = None,
        scan_id: Optional[int] = None,
        channel: Optional[str] = None,
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO alerts (protocol_id, scan_id, alert_type, severity, message, channel) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (protocol_id, scan_id, alert_type, severity, message, channel),
        )
        self.conn.commit()
        return cur.lastrowid

    def mark_alert_sent(self, alert_id: int, channel: str) -> None:
        self.conn.execute(
            "UPDATE alerts SET sent_at=?, channel=?, delivered=1 WHERE id=?",
            (time.time(), channel, alert_id),
        )
        self.conn.commit()

    def get_pending_alerts(self) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT a.*, p.name as protocol_name, p.chain as protocol_chain "
            "FROM alerts a JOIN protocols p ON a.protocol_id=p.id "
            "WHERE a.delivered=0 ORDER BY a.id"
        ).fetchall()
        return [dict(r) for r in rows]

    def get_alert_history(self, protocol_id: Optional[int] = None, limit: int = 50) -> List[Dict]:
        if protocol_id:
            rows = self.conn.execute(
                "SELECT a.*, p.name as protocol_name FROM alerts a "
                "JOIN protocols p ON a.protocol_id=p.id "
                "WHERE a.protocol_id=? ORDER BY a.sent_at DESC LIMIT ?",
                (protocol_id, limit),
            ).fetchall()
        else:
            rows = self.conn.execute(
                "SELECT a.*, p.name as protocol_name FROM alerts a "
                "JOIN protocols p ON a.protocol_id=p.id "
                "ORDER BY a.sent_at DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Threat Intel
    # ------------------------------------------------------------------

    def add_threat_intel(
        self,
        attack_type: str,
        chain: str,
        tx_hash: Optional[str] = None,
        loss_amount: Optional[str] = None,
        source: Optional[str] = None,
        pattern: Optional[str] = None,
    ) -> int:
        cur = self.conn.execute(
            "INSERT INTO threat_intel (attack_type, chain, tx_hash, loss_amount, source, pattern, added_at) "
            "VALUES (?, ?, ?, ?, ?, ?, ?)",
            (attack_type, chain, tx_hash, loss_amount, source, pattern, time.time()),
        )
        self.conn.commit()
        return cur.lastrowid

    def get_recent_threats(self, limit: int = 20) -> List[Dict]:
        rows = self.conn.execute(
            "SELECT * FROM threat_intel ORDER BY added_at DESC LIMIT ?", (limit,)
        ).fetchall()
        return [dict(r) for r in rows]

    # ------------------------------------------------------------------
    # Statistics
    # ------------------------------------------------------------------

    def get_stats(self) -> Dict[str, Any]:
        """Get overall Sentinel statistics."""
        stats = {}
        stats["protocols"] = self.conn.execute(
            "SELECT COUNT(*) FROM protocols WHERE status='active'"
        ).fetchone()[0]
        stats["total_scans"] = self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        stats["total_findings"] = self.conn.execute("SELECT COUNT(*) FROM findings").fetchone()[0]
        stats["total_alerts"] = self.conn.execute("SELECT COUNT(*) FROM alerts WHERE delivered=1").fetchone()[0]
        stats["pending_alerts"] = self.conn.execute(
            "SELECT COUNT(*) FROM alerts WHERE delivered=0"
        ).fetchone()[0]

        # Last 7 days
        week_ago = time.time() - 7 * 86400
        stats["scans_this_week"] = self.conn.execute(
            "SELECT COUNT(*) FROM scans WHERE timestamp>?", (week_ago,)
        ).fetchone()[0]
        stats["findings_this_week"] = self.conn.execute(
            "SELECT COUNT(*) FROM scans WHERE timestamp>?", (week_ago,)
        ).fetchone()[0]

        # Severity breakdown
        for sev in ("critical", "high", "medium", "low", "info"):
            stats[f"{sev}_total"] = self.conn.execute(
                f"SELECT COALESCE(SUM({sev}), 0) FROM scans"
            ).fetchone()[0]

        return stats

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _calc_score(counts: Dict[str, int]) -> float:
        """Calculate security score (0-100) from finding counts."""
        penalty = (
            counts.get("CRITICAL", 0) * 25 +
            counts.get("HIGH", 0) * 15 +
            counts.get("MEDIUM", 0) * 8 +
            counts.get("LOW", 0) * 3 +
            counts.get("INFO", 0) * 1
        )
        return max(0.0, min(100.0, 100.0 - penalty))

    @staticmethod
    def _score_to_verdict(score: float) -> str:
        if score >= 90:
            return "CLEAN"
        if score >= 75:
            return "LOW"
        if score >= 50:
            return "MODERATE"
        if score >= 25:
            return "HIGH"
        return "CRITICAL"
