#!/usr/bin/env bash
# Set up the SNItch test environment (nginx or Caddy) on 127.0.42.0/24.
#
# Usage:
#   ./setup.sh [nginx|caddy]     # default: nginx
#
# Steps:
#   1. Render configs from sites.json          (scripts/render.py)
#   2. Generate self-signed certificates       (scripts/generate-certs.sh)
#   3. Stop any running stack
#   4. Start dnsmasq + the selected TLS stack  (docker compose profile)
#
# Environment:
#   FORCE=1     regenerate certificates even if they exist
set -euo pipefail

TESTENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$TESTENV_DIR"

STACK="${1:-nginx}"
case "$STACK" in
    nginx|caddy) ;;
    *)
        echo "usage: $0 [nginx|caddy]" >&2
        exit 1
        ;;
esac

if ! docker info >/dev/null 2>&1; then
    echo "error: cannot talk to the Docker daemon" >&2
    exit 1
fi

echo "==> Rendering configuration from sites.json"
python3 scripts/render.py

echo "==> Generating self-signed certificates"
bash scripts/generate-certs.sh

echo "==> Stopping any running stack"
docker compose --profile nginx --profile caddy down --remove-orphans >/dev/null 2>&1 || true

echo "==> Starting dnsmasq + $STACK"
docker compose --profile "$STACK" up -d --build

echo "==> Waiting for $STACK to accept connections on 127.0.42.10:443"
for _ in $(seq 1 30); do
    if ss -ltn 2>/dev/null | grep -q "127.0.42.10:443"; then
        break
    fi
    sleep 0.5
done

echo "==> Waiting for DNS on 127.0.0.1:5353"
for _ in $(seq 1 30); do
    if ss -lun 2>/dev/null | grep -q "127.0.0.1:5353"; then
        break
    fi
    sleep 0.5
done

echo
echo "Test environment is up ($STACK)."
echo "  TLS servers : 127.0.42.10 .. 127.0.42.14 (ports 443 + 80)"
echo "  DNS server  : 127.0.0.1:5353"
echo
echo "Run a scan:      ./run-snitch.sh"
echo "Verify results:  ./verify.sh"
echo "Tear down:       ./teardown.sh"
