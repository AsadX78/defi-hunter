#!/bin/bash
# DeFi Hunter — Quick Start Script
# Usage: ./scan.sh <target> [rpc_url]

set -e

TARGET=${1:-"sky.money"}
RPC=${2:-""}
SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"

# Use Alchemy key if available
if [ -z "$RPC" ] && [ -n "$ALCHEMY_KEY" ]; then
    RPC="https://eth-mainnet.g.alchemy.com/v2/$ALCHEMY_KEY"
fi

echo "========================================"
echo "  DeFi Hunter — Security Analysis"
echo "  Target: $TARGET"
echo "  RPC: ${RPC:-none}"
echo "========================================"
echo ""

# Check dependencies
command -v cast >/dev/null 2>&1 || { echo "ERROR: cast not found. Install Foundry."; exit 1; }
command -v forge >/dev/null 2>&1 || { echo "ERROR: forge not found. Install Foundry."; exit 1; }
command -v python3 >/dev/null 2>&1 || { echo "ERROR: python3 not found."; exit 1; }

cd "$SCRIPT_DIR"

# Run the scan
echo "[*] Starting scan..."
python3 run.py --target "$TARGET" --rpc "$RPC" --output "$SCRIPT_DIR/output"

echo ""
echo "[*] Scan complete!"
echo "[*] Check output/ directory for results"
