"""Sentinel -- continuous DeFi protocol monitoring and threat detection.

The Sentinel watches new deployments, tracks protocol health over time,
and alerts on new vulnerabilities. It's always watching.
"""
from defihunter.sentinel.database import SentinelDB
from defihunter.sentinel.watcher import DeploymentWatcher
from defihunter.sentinel.alerts import AlertManager
from defihunter.sentinel.service import SentinelService

__all__ = ["SentinelDB", "DeploymentWatcher", "AlertManager", "SentinelService"]
