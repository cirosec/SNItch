#!/usr/bin/env python3
"""Assert that the TLS ports answer plaintext HTTP without leaking a hostname.

Sends a raw plaintext HTTP request to <ip>:443 of every server in sites.json and
checks that:

  a) the server responds with an HTTP status (proving it speaks HTTP on its
     HTTPS port), and
  b) the response leaks none of the hostnames defined in sites.json.

Both the nginx and Caddy stacks answer plaintext-on-TLS with a 400 and leak
nothing, so the SNItch plaintext-on-TLS probe must not produce a finding here.

Usage: probe-http-tls.py
"""

from __future__ import annotations

import json
import os
import socket
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTENV = os.path.dirname(HERE)
TLS_PORT = 443

failures: list[str] = []
checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        failures.append(message)


def load_sites() -> dict:
    with open(os.path.join(TESTENV, "sites.json"), "r", encoding="utf-8") as fh:
        return json.load(fh)


def manifest_hostnames(sites: dict) -> set[str]:
    names: set[str] = set()
    for cert in sites["certificates"]:
        names.add(cert["name"])
        for name in cert.get("sans", []):
            names.add(name)
    for server in sites["servers"]:
        for site in server["sites"]:
            for name in site["server_names"]:
                names.add(name)
    # Wildcards and IP literals are not hostnames that could appear verbatim.
    return {
        n.lstrip("*.").lower()
        for n in names
        if n and not n.startswith("*.") and not n.startswith("127.")
    }


def probe(ip: str, timeout: float = 5.0) -> str:
    request = (
        "GET / HTTP/1.1\r\n"
        "Host: probe.invalid.example\r\n"
        "User-Agent: snitch-testenv\r\n"
        "Connection: close\r\n"
        "\r\n"
    ).encode()
    with socket.create_connection((ip, TLS_PORT), timeout=timeout) as sock:
        sock.sendall(request)
        chunks = []
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            chunks.append(chunk)
    return b"".join(chunks).decode("latin-1", "replace")


def main() -> int:
    sites = load_sites()
    secrets = manifest_hostnames(sites)

    for server in sites["servers"]:
        ip = server["ip"]
        target = f"{ip}:{TLS_PORT}"
        try:
            response = probe(ip)
        except OSError as exc:
            check(False, f"{target} did not answer plaintext HTTP on its HTTPS port: {exc}")
            continue

        status_line = response.splitlines()[0] if response else ""
        check(
            status_line.startswith("HTTP/"),
            f"{target} did not return an HTTP status line (got {status_line!r})",
        )
        check(
            " 400 " in status_line,
            f"{target} answered plaintext HTTP with {status_line!r}, expected a 400 rejection",
        )
        lowered = response.lower()
        for name in sorted(secrets):
            check(
                name not in lowered,
                f"{target} plaintext HTTP response leaked hostname {name!r}",
            )

    print()
    if failures:
        print(f"FAILED: {len(failures)} of {checks} checks failed")
        for f in failures:
            print(f"  - {f}")
        return 1
    print(f"PASSED: {checks} checks")
    return 0


if __name__ == "__main__":
    sys.exit(main())
