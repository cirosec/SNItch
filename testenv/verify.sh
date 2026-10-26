#!/usr/bin/env bash
# Run SNItch against the test environment and verify the results.
#
# Usage: ./verify.sh [nginx|caddy]
set -euo pipefail

TESTENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$TESTENV_DIR/.." && pwd)"
SNITCH="$REPO_DIR/SNItch"
STACK="${1:-nginx}"

if [[ ! -f "$TESTENV_DIR/generated/snitch-targets.txt" ]]; then
    echo "error: generated inputs not found; run ./setup.sh first" >&2
    exit 1
fi

if [[ ! -x "$SNITCH" ]]; then
    echo "==> Building SNItch"
    ( cd "$REPO_DIR" && go build -o SNItch . )
fi

RESULT="$(mktemp -t snitch-testenv-XXXXXX.jsonl)"
RESULT_HARDENED="$(mktemp -t snitch-testenv-hardened-XXXXXX.jsonl)"
RESULT_LEAK="$(mktemp -t snitch-testenv-leak-XXXXXX.jsonl)"
RESULT_LEAK_NOSEARCH="$(mktemp -t snitch-testenv-leak-nosearch-XXXXXX.jsonl)"
RESULT_IGNORE="$(mktemp -t snitch-testenv-ignore-XXXXXX.jsonl)"
RESULT_REQUIRE="$(mktemp -t snitch-testenv-require-XXXXXX.jsonl)"
RESULT_NORECON="$(mktemp -t snitch-testenv-norecon-XXXXXX.jsonl)"
RESULT_STDOUT="$(mktemp -t snitch-testenv-stdout-XXXXXX.jsonl)"
trap 'rm -f "$RESULT" "$RESULT_HARDENED" "$RESULT_LEAK" "$RESULT_LEAK_NOSEARCH" "$RESULT_IGNORE" "$RESULT_REQUIRE" "$RESULT_NORECON" "$RESULT_STDOUT"' EXIT

echo "==> Running SNItch scan (JSONL -> $RESULT)"
# -e 3: the portal.test -> hop.test -> final.test redirect chain needs three
# epochs (scan supplied names, scan hop.test, scan final.test).
"$SNITCH" \
    --target-list "$TESTENV_DIR/generated/snitch-targets.txt" \
    --host-list "$TESTENV_DIR/generated/snitch-hosts.txt" \
    --dns 127.0.0.1:5353 \
    --no-crtlog \
    --search-headers \
    -e 3 \
    --jsonl "$RESULT" >/dev/null

echo "==> Running hardened IP-only scan (no hostnames; must reveal nothing)"
"$SNITCH" \
    --target-list "$TESTENV_DIR/generated/snitch-targets-hardened.txt" \
    --dns 127.0.0.1:5353 \
    --no-crtlog \
    --jsonl "$RESULT_HARDENED" >/dev/null

echo "==> Running header-leak IP-only scan (--search-headers; must discover the vhost)"
"$SNITCH" \
    --target-list "$TESTENV_DIR/generated/snitch-targets-header-leak.txt" \
    --dns 127.0.0.1:5353 \
    --no-crtlog \
    --search-headers \
    --jsonl "$RESULT_LEAK" >/dev/null

echo "==> Running default header-leak IP-only scan (must reveal nothing)"
"$SNITCH" \
    --target-list "$TESTENV_DIR/generated/snitch-targets-header-leak.txt" \
    --dns 127.0.0.1:5353 \
    --no-crtlog \
    --jsonl "$RESULT_LEAK_NOSEARCH" >/dev/null

echo "==> Running ignore-list scan (-i portal.test,beta.test; those rows must vanish)"
"$SNITCH" \
    --target-list "$TESTENV_DIR/generated/snitch-targets.txt" \
    --host-list "$TESTENV_DIR/generated/snitch-hosts.txt" \
    --dns 127.0.0.1:5353 \
    --no-crtlog \
    --ignore portal.test,beta.test \
    --jsonl "$RESULT_IGNORE" >/dev/null

echo "==> Running require-list scan (-r ^nomatch; discovered hosts filtered, supplied survive)"
"$SNITCH" \
    --target-list "$TESTENV_DIR/generated/snitch-targets.txt" \
    --host-list "$TESTENV_DIR/generated/snitch-hosts.txt" \
    --dns 127.0.0.1:5353 \
    --no-crtlog \
    --search-headers \
    --require "^nomatch" \
    --jsonl "$RESULT_REQUIRE" >/dev/null

echo "==> Running no-recon/no-ip-sni scan (--no-recon --no-ip-sni; discovery and (IP as SNI) rows must vanish)"
"$SNITCH" \
    --target-list "$TESTENV_DIR/generated/snitch-targets.txt" \
    --host-list "$TESTENV_DIR/generated/snitch-hosts.txt" \
    --dns 127.0.0.1:5353 \
    --no-crtlog \
    --search-headers \
    --no-recon \
    --no-ip-sni \
    --jsonl "$RESULT_NORECON" >/dev/null

echo "==> Running stdout JSONL scan (--jsonl -; stdout must be valid JSONL)"
"$SNITCH" \
    --target-list "$TESTENV_DIR/generated/snitch-targets-hardened.txt" \
    --dns 127.0.0.1:5353 \
    --no-crtlog \
    --jsonl - > "$RESULT_STDOUT" 2>/dev/null

echo "==> Checking plaintext HTTP on the HTTPS port (responds + no leak)"
python3 "$TESTENV_DIR/scripts/probe-http-tls.py"

echo "==> Verifying results"
python3 "$TESTENV_DIR/scripts/verify.py" \
    "$RESULT" "$STACK" "$RESULT_HARDENED" "$RESULT_LEAK" "$RESULT_LEAK_NOSEARCH" \
    "$RESULT_IGNORE" "$RESULT_REQUIRE" "$RESULT_NORECON" "$RESULT_STDOUT"
