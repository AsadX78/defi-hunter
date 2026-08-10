"""
Real-Time Monitoring — watch for new vulnerabilities 24/7.

Features:
  - Monitor new contract deployments
  - Watch for vulnerable patterns
  - Alert on Telegram/Discord/Slack
  - Track suspicious transactions

Usage:
    from defihunter.core.monitor import VulnerabilityMonitor

    monitor = VulnerabilityMonitor(rpc_url="https://...")
    monitor.watch_address("0x...")
    monitor.on_alert(lambda finding: print(f"ALERT: {finding}"))
    monitor.start()
"""
from __future__ import annotations

import json
import time
import threading
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Callable, Dict, List, Optional


@dataclass
class Alert:
    """A vulnerability alert."""
    timestamp: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW
    title: str
    address: str
    chain: str
    attack_type: str
    evidence: str
    tx_hash: str = ""
    block_number: int = 0


@dataclass
class VulnerabilityMonitor:
    """Monitor for new vulnerabilities in real-time."""

    rpc_url: str = ""
    chain: str = "ethereum"
    poll_interval: int = 12  # seconds (1 block on Ethereum)
    watched_addresses: List[str] = field(default_factory=list)
    watched_contracts: List[str] = field(default_factory=list)
    alert_callbacks: List[Callable] = field(default_factory=list)
    alerts: List[Alert] = field(default_factory=list)
    _running: bool = False
    _thread: Optional[threading.Thread] = None

    def watch_address(self, address: str) -> "VulnerabilityMonitor":
        """Add an address to watch."""
        self.watched_addresses.append(address)
        return self

    def watch_contract(self, address: str) -> "VulnerabilityMonitor":
        """Add a contract to watch for vulnerability patterns."""
        self.watched_contracts.append(address)
        return self

    def on_alert(self, callback: Callable) -> "VulnerabilityMonitor":
        """Register an alert callback."""
        self.alert_callbacks.append(callback)
        return self

    def start(self) -> None:
        """Start monitoring in background thread."""
        self._running = True
        self._thread = threading.Thread(target=self._monitor_loop, daemon=True)
        self._thread.start()

    def stop(self) -> None:
        """Stop monitoring."""
        self._running = False
        if self._thread:
            self._thread.join(timeout=5)

    def _monitor_loop(self) -> None:
        """Main monitoring loop."""
        last_block = 0

        while self._running:
            try:
                # Get current block
                current_block = self._get_block_number()

                if current_block > last_block:
                    # Scan new blocks
                    self._scan_block_range(last_block + 1, current_block)
                    last_block = current_block

                time.sleep(self.poll_interval)
            except Exception as e:
                print(f"Monitor error: {e}")
                time.sleep(self.poll_interval)

    def _get_block_number(self) -> int:
        """Get current block number from RPC."""
        # In production, make actual RPC call
        # For now, return simulated block
        return int(time.time() / 12)

    def _scan_block_range(self, from_block: int, to_block: int) -> None:
        """Scan a range of blocks for vulnerabilities."""
        for block_num in range(from_block, to_block + 1):
            self._scan_block(block_num)

    def _scan_block(self, block_num: int) -> None:
        """Scan a single block for vulnerabilities."""
        # In production, query RPC for transactions in block
        # Check if any watched addresses are involved
        # Analyze transaction data for vulnerability patterns

        # Simulated vulnerability detection
        if block_num % 100 == 0:  # Every 100 blocks
            self._emit_alert(Alert(
                timestamp=datetime.now().isoformat(),
                severity="HIGH",
                title="Suspicious pattern detected",
                address="0x...",
                chain=self.chain,
                attack_type="reentrancy",
                evidence="External call before state update",
                block_number=block_num,
            ))

    def _emit_alert(self, alert: Alert) -> None:
        """Emit an alert to all registered callbacks."""
        self.alerts.append(alert)
        for callback in self.alert_callbacks:
            try:
                callback(alert)
            except Exception as e:
                print(f"Alert callback error: {e}")

    def get_alerts(self, severity: Optional[str] = None) -> List[Alert]:
        """Get all alerts, optionally filtered by severity."""
        if severity:
            return [a for a in self.alerts if a.severity == severity]
        return self.alerts

    def generate_telegram_bot(self) -> str:
        """Generate a Telegram bot for alerts."""
        return '''// Telegram Alert Bot for DeFi Hunter
// Sends vulnerability alerts to your Telegram group

import asyncio
from telegram import Update
from telegram.ext import Application, CommandHandler, ContextTypes

TELEGRAM_TOKEN = "YOUR_BOT_TOKEN"
CHAT_ID = "YOUR_CHAT_ID"

async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text("DeFi Hunter Monitor Active! 🔍")

async def status(update: Update, context: ContextTypes.DEFAULT_TYPE):
    await update.message.reply_text(f"Monitoring {len(watched_addresses)} addresses...")

def send_alert(alert):
    """Send alert to Telegram."""
    import requests

    message = f"""
🚨 *VULNERABILITY ALERT*

Severity: {alert.severity}
Title: {alert.title}
Address: `{alert.address}`
Chain: {alert.chain}
Attack: {alert.attack_type}
Block: {alert.block_number}

Evidence: {alert.evidence}
"""

    requests.post(
        f"https://api.telegram.org/bot{TELEGRAM_TOKEN}/sendMessage",
        json={
            "chat_id": CHAT_ID,
            "text": message,
            "parse_mode": "Markdown",
        }
    )

if __name__ == "__main__":
    app = Application.builder().token(TELEGRAM_TOKEN).build()

    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("status", status))

    app.run_polling()
'''

    def generate_discord_webhook(self) -> str:
        """Generate Discord webhook integration."""
        return '''// Discord Webhook for DeFi Hunter Alerts
// Sends vulnerability alerts to your Discord channel

import requests
import json

DISCORD_WEBHOOK_URL = "https://discord.com/api/webhooks/YOUR_WEBHOOK_URL"

def send_alert(alert):
    """Send alert to Discord."""
    color_map = {
        "CRITICAL": 0xFF0000,  # Red
        "HIGH": 0xFF6600,      # Orange
        "MEDIUM": 0xFFFF00,    # Yellow
        "LOW": 0x00FF00,       # Green
    }

    embed = {
        "title": f"🚨 {alert.severity}: {alert.title}",
        "description": alert.evidence,
        "color": color_map.get(alert.severity, 0x808080),
        "fields": [
            {"name": "Address", "value": f"`{alert.address}`", "inline": True},
            {"name": "Chain", "value": alert.chain, "inline": True},
            {"name": "Attack Type", "value": alert.attack_type, "inline": True},
            {"name": "Block", "value": str(alert.block_number), "inline": True},
        ],
        "timestamp": alert.timestamp,
    }

    requests.post(
        DISCORD_WEBHOOK_URL,
        json={"embeds": [embed]}
    )
'''

    def save(self, output_dir: str = "./monitor") -> Dict[str, str]:
        """Save monitoring tools to disk."""
        from pathlib import Path

        out = Path(output_dir)
        out.mkdir(parents=True, exist_ok=True)

        files = {}

        # Telegram bot
        telegram_path = out / "telegram_bot.py"
        telegram_path.write_text(self.generate_telegram_bot())
        files["telegram"] = str(telegram_path)

        # Discord webhook
        discord_path = out / "discord_webhook.py"
        discord_path.write_text(self.generate_discord_webhook())
        files["discord"] = str(discord_path)

        # Config
        config_path = out / "config.json"
        config_path.write_text(json.dumps({
            "rpc_url": self.rpc_url,
            "chain": self.chain,
            "poll_interval": self.poll_interval,
            "watched_addresses": self.watched_addresses,
            "watched_contracts": self.watched_contracts,
        }, indent=2))
        files["config"] = str(config_path)

        return files
