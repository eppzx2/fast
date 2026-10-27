#!/usr/bin/env bash
set -Eeuo pipefail

[[ $# -eq 1 && -n "${1:-}" ]] || {
    echo "Usage: $0 <target_ip>" >&2
    exit 1
}

TARGET_HOST="$1"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
SIM_DIR="$SCRIPT_DIR/"

echo "[1/2] Starting port scan..."
"$SIM_DIR/simulate_port_scan.sh" "$TARGET_HOST"

echo "[2/2] Starting brute force..."
"$SIM_DIR/simulate_brute_force.sh" "$TARGET_HOST"

echo "[OK] Both simulations completed."
