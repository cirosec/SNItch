#!/usr/bin/env bash
# Run SNItch against the running test environment.
#
# Builds ./SNItch in the repository root if it does not exist, then scans the
# test IPs with the generated host list, using the local dnsmasq resolver and
# disabling the external crt.name lookups so the run is hermetic. --search-headers
# is enabled so the header-leak server's vhost is discovered from its response
# header rather than being supplied. Hidden servers' names are deliberately not
# in the host list.
#
# Any extra arguments are forwarded to SNItch, e.g.:
#   ./run-snitch.sh --jsonl out.jsonl
#   ./run-snitch.sh -t 127.0.42.0/28:443 --no-ptr
set -euo pipefail

TESTENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_DIR="$(cd "$TESTENV_DIR/.." && pwd)"
SNITCH="$REPO_DIR/SNItch"

if [[ ! -f "$TESTENV_DIR/generated/snitch-targets.txt" ]]; then
    echo "error: generated inputs not found; run ./setup.sh first" >&2
    exit 1
fi

if [[ ! -x "$SNITCH" ]]; then
    echo "==> Building SNItch"
    ( cd "$REPO_DIR" && go build -o SNItch . )
fi

exec "$SNITCH" \
    --target-list "$TESTENV_DIR/generated/snitch-targets.txt" \
    --host-list "$TESTENV_DIR/generated/snitch-hosts.txt" \
    --dns 127.0.0.1:5353 \
    --no-crtlog \
    --search-headers \
    -e 3 \
    "$@"
# (-e 3: the portal.test -> hop.test -> final.test redirect chain needs
#  three scan epochs to complete.)
