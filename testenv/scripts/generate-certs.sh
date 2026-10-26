#!/usr/bin/env bash
# Generate the self-signed certificates for the SNItch test environment.
#
# The inventory is written to generated/certs.manifest by scripts/render.py,
# one line per certificate:  name|dns-san-1,dns-san-2|ip-san-1,...
#
# Re-running is a no-op for certificates that already exist. Set FORCE=1 to
# regenerate everything (e.g. after changing sites.json SANs).
set -euo pipefail

TESTENV_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
MANIFEST="$TESTENV_DIR/generated/certs.manifest"
CERT_DIR="$TESTENV_DIR/certs"

if [[ ! -f "$MANIFEST" ]]; then
    echo "error: $MANIFEST not found; run scripts/render.py first" >&2
    exit 1
fi

mkdir -p "$CERT_DIR"

echo "==> Generating self-signed certificates in certs/"

while IFS='|' read -r name dns_sans ip_sans expired; do
    [[ -z "${name// }" ]] && continue

    crt="$CERT_DIR/$name.crt"
    key="$CERT_DIR/$name.key"

    if [[ -f "$crt" && -f "$key" && "${FORCE:-0}" != "1" ]]; then
        echo "  [skip] $name (already present)"
        continue
    fi

    san=""
    if [[ -n "${dns_sans// }" ]]; then
        IFS=',' read -ra parts <<< "$dns_sans"
        for p in "${parts[@]}"; do
            [[ -z "$p" ]] && continue
            san+="${san:+,}DNS:$p"
        done
    fi
    if [[ -n "${ip_sans// }" ]]; then
        IFS=',' read -ra iparts <<< "$ip_sans"
        for ip in "${iparts[@]}"; do
            [[ -z "$ip" ]] && continue
            san+="${san:+,}IP:$ip"
        done
    fi

    cn="${dns_sans%%,*}"
    cn="${cn#\*.}"

    if [[ "$expired" == "expired" ]]; then
        # A deliberately expired certificate (fixed past validity window).
        # Requires OpenSSL 3.4+ for -not_before/-not_after.
        if ! openssl req -x509 -not_after 250101000000Z -help >/dev/null 2>&1 \
           && ! openssl req -help 2>&1 | grep -q -- -not_after; then
            echo "error: certificate $name is marked expired but this OpenSSL" >&2
            echo "       does not support -not_before/-not_after (need 3.4+)" >&2
            exit 1
        fi
        echo "  [gen ] $name (CN=$cn, SAN=$san, EXPIRED)"
        openssl req -x509 -newkey rsa:2048 -sha256 -nodes \
            -not_before 240101000000Z -not_after 240201000000Z \
            -keyout "$key" -out "$crt" \
            -subj "/C=DE/O=SNItch Testenv/OU=tls/CN=$cn" \
            -addext "subjectAltName=$san" \
            -addext "basicConstraints=critical,CA:FALSE" \
            -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
            -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
        # -checkend 0 exits non-zero once the certificate has expired, which
        # is exactly the expected outcome here.
        if openssl x509 -in "$crt" -noout -checkend 0 >/dev/null 2>&1; then
            echo "  [FAIL] $name was supposed to be expired but is still valid" >&2
            exit 1
        fi
        continue
    fi

    echo "  [gen ] $name (CN=$cn, SAN=$san)"

    openssl req -x509 -newkey rsa:2048 -sha256 -nodes -days 825 \
        -keyout "$key" -out "$crt" \
        -subj "/C=DE/O=SNItch Testenv/OU=tls/CN=$cn" \
        -addext "subjectAltName=$san" \
        -addext "basicConstraints=critical,CA:FALSE" \
        -addext "keyUsage=critical,digitalSignature,keyEncipherment" \
        -addext "extendedKeyUsage=serverAuth" >/dev/null 2>&1
done < "$MANIFEST"

chmod 644 "$CERT_DIR"/*.crt 2>/dev/null || true
chmod 600 "$CERT_DIR"/*.key 2>/dev/null || true

echo "==> Certificates ready"
