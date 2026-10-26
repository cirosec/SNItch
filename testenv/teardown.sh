#!/usr/bin/env bash
# Stop and remove the SNItch test environment (dnsmasq + nginx/Caddy).
set -euo pipefail

TESTENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$TESTENV_DIR"

docker compose --profile nginx --profile caddy down --remove-orphans
echo "==> Test environment stopped"
