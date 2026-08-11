#!/usr/bin/env python3
"""
DeFi Hunter — Open Source DeFi Security Toolkit
===============================================

A comprehensive framework for discovering, analyzing, and simulating
attacks on DeFi protocols.

Usage:
    defihunter recon --target sky.money
    defihunter analyze --address 0x1234...
    defihunter simulate --attack inflation --target 0x1234...
    defihunter report --output report.html
    defihunter fuzz generate --attacks mint --target 0x1234...
    defihunter diagram -k attack_flow -i findings.json -o flow.mmd
    defihunter sarif -i findings.json -o results.sarif
    defihunter sync -i findings.json -t github --repo owner/name

Advanced analysis engine: line-aware static analysis + Slither (90+ detectors)
+ governance/oracle/upgradability/cross-chain scanners + Foundry fuzz/invariant
testing, with Mermaid diagrams, SARIF export, and GitHub/Jira issue sync.

Author: DeFi Hunter Community
License: MIT
Version: 1.6.0
"""

__version__ = "1.6.0"
__author__ = "DeFi Hunter Community"
