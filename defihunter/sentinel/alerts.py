"""Alert System -- send notifications via Telegram, Discord, webhook, email.

When the Sentinel finds new vulnerabilities or detects regressions,
the alert system delivers notifications to configured channels.
"""
from __future__ import annotations

import json
import subprocess
from typing import Dict, List, Optional

# Telegram Bot API
TELEGRAM_API = "https://api.telegram.org/bot{token}/sendMessage"


class AlertChannel:
    """Base class for alert channels."""
    name: str = "base"

    def send(self, message: str, **kwargs) -> bool:
        raise NotImplementedError


class ConsoleAlert(AlertChannel):
    """Print alerts to stdout (for testing and development)."""

    name = "console"

    def send(self, message: str, **kwargs) -> bool:
        print(f"\n[SENTINEL ALERT]\n{message}\n")
        return True


class TelegramAlert(AlertChannel):
    """Send alerts via Telegram bot."""

    name = "telegram"

    def __init__(self, bot_token: str, chat_id: str):
        self.bot_token = bot_token
        self.chat_id = chat_id

    def send(self, message: str, parse_mode: str = "HTML", **kwargs) -> bool:
        url = TELEGRAM_API.format(token=self.bot_token)
        payload = json.dumps({
            "chat_id": self.chat_id,
            "text": message,
            "parse_mode": parse_mode,
            "disable_web_page_preview": True,
        })
        try:
            proc = subprocess.run(
                ["curl", "-s", "-X", "POST",
                 "-H", "Content-Type: application/json",
                 "-d", payload, url],
                capture_output=True, text=True, timeout=15,
            )
            data = json.loads(proc.stdout)
            return data.get("ok", False)
        except Exception:
            return False


class DiscordAlert(AlertChannel):
    """Send alerts via Discord webhook."""

    name = "discord"

    def __init__(self, webhook_url: str):
        self.webhook_url = webhook_url

    def send(self, message: str, **kwargs) -> bool:
        # Discord has 2000 char limit
        if len(message) > 1900:
            message = message[:1900] + "..."

        payload = json.dumps({"content": message})
        try:
            proc = subprocess.run(
                ["curl", "-s", "-X", "POST",
                 "-H", "Content-Type: application/json",
                 "-d", payload, self.webhook_url],
                capture_output=True, text=True, timeout=15,
            )
            return proc.returncode == 0 and "4" not in proc.stdout[:10]
        except Exception:
            return False


class WebhookAlert(AlertChannel):
    """Send alerts via generic webhook (POST JSON)."""

    name = "webhook"

    def __init__(self, url: str, headers: Optional[Dict[str, str]] = None):
        self.url = url
        self.headers = headers or {}

    def send(self, message: str, severity: str = "info",
             protocol: str = "", **kwargs) -> bool:
        payload = json.dumps({
            "message": message,
            "severity": severity,
            "protocol": protocol,
            "source": "defihunter-sentinel",
        })
        cmd = ["curl", "-s", "-X", "POST",
               "-H", "Content-Type: application/json"]
        for k, v in self.headers.items():
            cmd.extend(["-H", f"{k}: {v}"])
        cmd.extend(["-d", payload, self.url])
        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
            return proc.returncode == 0
        except Exception:
            return False


class AlertManager:
    """Manage multiple alert channels and deliver notifications.

    Usage:
        manager = AlertManager()
        manager.add_channel(TelegramAlert(bot_token="...", chat_id="..."))
        manager.add_channel(DiscordAlert(webhook_url="..."))

        manager.send_alert(
            protocol="Morpho Blue",
            alert_type="new_vuln",
            severity="HIGH",
            message="2 new HIGH vulnerabilities found",
        )
    """

    def __init__(self):
        self.channels: List[AlertChannel] = []
        self._sent: List[Dict] = []

    def add_channel(self, channel: AlertChannel) -> None:
        self.channels.append(channel)

    def send_alert(
        self,
        protocol: str,
        alert_type: str,
        severity: str,
        message: str,
        chain: str = "ethereum",
        details: Optional[Dict] = None,
    ) -> Dict[str, bool]:
        """Send alert to all configured channels. Returns {channel: success}."""
        # Build formatted message
        formatted = self._format_message(
            protocol=protocol,
            alert_type=alert_type,
            severity=severity,
            message=message,
            chain=chain,
            details=details,
        )

        results = {}
        for channel in self.channels:
            try:
                success = channel.send(
                    formatted,
                    severity=severity,
                    protocol=protocol,
                )
                results[channel.name] = success
            except Exception:
                results[channel.name] = False

        self._sent.append({
            "protocol": protocol,
            "type": alert_type,
            "severity": severity,
            "results": results,
        })

        return results

    def _format_message(
        self,
        protocol: str,
        alert_type: str,
        severity: str,
        message: str,
        chain: str = "ethereum",
        details: Optional[Dict] = None,
    ) -> str:
        """Format alert message for delivery."""
        sev_icon = {
            "CRITICAL": "!!!",
            "HIGH": "!!",
            "MEDIUM": "!",
            "LOW": ".",
            "INFO": "-",
        }.get(severity, "?")

        alert_labels = {
            "new_vuln": "NEW VULNERABILITY",
            "regression": "REGRESSION DETECTED",
            "launch_ready": "LAUNCH READINESS",
            "cleanup": "CLEANUP",
            "threat_intel": "THREAT INTELLIGENCE",
        }
        label = alert_labels.get(alert_type, alert_type.upper())

        lines = [
            f"[SENTINEL] {sev_icon} {label}",
            "",
            f"Protocol: {protocol}",
            f"Chain: {chain}",
            f"Severity: {severity}",
            "",
            message,
        ]

        if details:
            lines.append("")
            for k, v in details.items():
                lines.append(f"  {k}: {v}")

        lines.append("")
        lines.append("Source: defihunter-sentinel")

        return "\n".join(lines)

    def get_sent(self) -> List[Dict]:
        return list(self._sent)


def format_scan_alert(
    protocol: str,
    chain: str,
    old_findings: int,
    new_findings: int,
    new_critical: int,
    new_high: int,
    score: float,
) -> str:
    """Format a scan result alert message."""
    if new_findings > old_findings:
        delta = new_findings - old_findings
        return (
            f"[{protocol}] {delta} new finding(s) detected\n"
            f"  Total: {new_findings} (was {old_findings})\n"
            f"  CRITICAL: {new_critical}  HIGH: {new_high}\n"
            f"  Score: {score:.0f}/100"
        )
    elif new_findings < old_findings:
        delta = old_findings - new_findings
        return (
            f"[{protocol}] {delta} finding(s) resolved\n"
            f"  Total: {new_findings} (was {old_findings})\n"
            f"  Score: {score:.0f}/100"
        )
    else:
        return (
            f"[{protocol}] No change — {new_findings} finding(s)\n"
            f"  Score: {score:.0f}/100"
        )


def format_regression_alert(
    protocol: str,
    chain: str,
    new_findings: List[Dict],
    score_before: float,
    score_after: float,
) -> str:
    """Format a regression alert (score got worse)."""
    lines = [
        f"[{protocol}] REGRESSION — security score dropped",
        f"  Score: {score_before:.0f} -> {score_after:.0f}",
        "  New findings:",
    ]
    for f in new_findings[:5]:
        sev = f.get("severity", "?")
        title = f.get("title", "Unknown")
        lines.append(f"    [{sev}] {title}")
    if len(new_findings) > 5:
        lines.append(f"    ... and {len(new_findings) - 5} more")
    return "\n".join(lines)
