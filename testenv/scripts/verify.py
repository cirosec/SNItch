#!/usr/bin/env python3
"""Verify a SNItch JSONL result against the test environment manifest.

Usage: verify.py <results.jsonl> [nginx|caddy] [ip-only.jsonl]
                 [header-leak.jsonl] [header-leak-nosearch.jsonl]
                 [ignore.jsonl] [require.jsonl] [norecon.jsonl] [stdout.jsonl]
"""

from __future__ import annotations

import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
TESTENV = os.path.dirname(HERE)

failures: list[str] = []
checks = 0


def check(condition: bool, message: str) -> None:
    global checks
    checks += 1
    if not condition:
        failures.append(message)


def is_ip(value: str) -> bool:
    parts = value.split(".")
    if len(parts) != 4:
        return False
    try:
        return all(0 <= int(p) <= 255 for p in parts)
    except ValueError:
        return False


def load_jsonl(path: str) -> list[dict]:
    records = []
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            records.append(json.loads(line))
    return records


def main() -> int:
    if len(sys.argv) < 2:
        print("usage: verify.py <results.jsonl> [nginx|caddy]", file=sys.stderr)
        return 2
    results_path = sys.argv[1]
    stack = sys.argv[2] if len(sys.argv) > 2 else "nginx"

    with open(os.path.join(TESTENV, "sites.json"), "r", encoding="utf-8") as fh:
        sites = json.load(fh)

    records = load_jsonl(results_path)
    config = [r for r in records if r.get("type") == "config"]
    certs = [r for r in records if r.get("type") == "certificate"]
    hosts = [r for r in records if r.get("type") == "host"]
    summary = [r for r in records if r.get("type") == "summary"]

    check(len(config) == 1, "expected exactly one config record")
    check(len(summary) == 1, "expected exactly one summary record")
    if config:
        check(
            config[0].get("dns_server") == "127.0.0.1:5353",
            f"config dns_server is {config[0].get('dns_server')!r}, expected 127.0.0.1:5353",
        )
        # Hidden servers are absent from DNS; their names must not be handed to
        # SNItch via the host list either, so it has to discover them itself.
        supplied_hosts = {h.lower() for h in config[0].get("hosts", [])}
        for server in sites["servers"]:
            for site in server["sites"]:
                for name in site["server_names"]:
                    if is_ip(name):
                        continue
                    hidden = server.get("no_dns") or site.get("no_dns") or site.get("no_supply")
                    check(
                        not hidden or name.lower() not in supplied_hosts,
                        f"discoverable hostname {name} was supplied via the host list; "
                        "SNItch must discover it itself",
                    )

    # Index host rows.
    by_host: dict[tuple[str, str], dict] = {}
    by_alt: dict[tuple[str, str], dict] = {}
    for row in hosts:
        if row.get("hostname"):
            by_host[(row["target"], row["hostname"])] = row
        if row.get("alternate_text"):
            by_alt[(row["target"], row["alternate_text"])] = row

    # Certificate names observed by SNItch.
    observed_cert_names: set[str] = set()
    for cert in certs:
        for name in cert.get("names", []):
            observed_cert_names.add(name)

    # 1. Every certificate defined in the manifest must be observed, except a
    #    certificate served only on a fully hardened server: its hostname is not
    #    published in DNS, not supplied and not discoverable, so its certificate
    #    is never observed by design.
    served_by: dict[str, list[dict]] = {}
    for server in sites["servers"]:
        if server.get("fallback_cert"):
            served_by.setdefault(server["fallback_cert"], []).append(server)
        for site in server["sites"]:
            served_by.setdefault(site["cert"], []).append(server)
    undiscoverable_certs = {
        name
        for name, servers in served_by.items()
        if all(s.get("expect_no_findings") for s in servers)
    }
    for cert in sites["certificates"]:
        name = cert["name"]
        if name in undiscoverable_certs:
            continue
        check(
            name in observed_cert_names,
            f"certificate {name} was not observed (names={sorted(observed_cert_names)})",
        )

    # 2. Every served hostname resolves to its server IP, has a valid cert and
    #    a successful HTTP response.
    for server in sites["servers"]:
        if server.get("expect_no_findings"):
            # Fully hardened: its hostname is neither supplied nor discoverable,
            # so the main scan must produce no row for it at all.
            main_rows = [h for h in hosts if h["target"] == f"{server['ip']}:443"]
            check(
                len(main_rows) == 0,
                f"hardened {server['ip']}:443 leaked {len(main_rows)} host row(s) in the main scan",
            )
            continue
        for site in server["sites"]:
            if site.get("ip_sni"):
                continue
            site_target = f"{server['ip']}:{site.get('port', 443)}"
            status = site.get("status", 200)
            redirect = site.get("redirect")
            for name in site["server_names"]:
                if name.startswith("*."):
                    row = next(
                        (
                            h
                            for h in hosts
                            if h["target"] == site_target
                            and h.get("wildcard")
                            and h["hostname"] == name
                        ),
                        None,
                    )
                    check(row is not None, f"missing wildcard row {name} on {site_target}")
                    if row:
                        check(
                            row.get("cert_valid") is True,
                            f"wildcard {name} on {site_target}: cert_valid={row.get('cert_valid')}",
                        )
                    continue

                row = by_host.get((site_target, name))
                check(row is not None, f"missing host row {name} on {site_target}")
                if row is None:
                    continue
                no_dns = server.get("no_dns") or site.get("no_dns")
                if no_dns:
                    # A hidden hostname must not resolve to the target; the
                    # resolver may report either "unresolved" or (after an empty
                    # result is cached) "resolves_elsewhere".
                    check(
                        row.get("dns") in ("unresolved", "resolves_elsewhere"),
                        f"{name} on {site_target}: dns={row.get('dns')!r}, expected unresolved/resolves_elsewhere",
                    )
                else:
                    check(
                        row.get("dns") == "resolves_to_target",
                        f"{name} on {site_target}: dns={row.get('dns')!r}, expected resolves_to_target",
                    )
                check(
                    row.get("cert_valid") is True,
                    f"{name} on {site_target}: cert_valid={row.get('cert_valid')}",
                )
                if 300 <= status < 400 and redirect:
                    check(
                        redirect in (row.get("http_redirect") or ""),
                        f"{name} on {site_target}: http_redirect={row.get('http_redirect')!r}, expected {redirect}",
                    )
                else:
                    check(
                        row.get("http_status") == status,
                        f"{name} on {site_target}: http_status={row.get('http_status')}, expected {status}",
                    )

    # 3. The fallback certificate must be observed as the random-SNI fallback.
    fallback_certs = {s["fallback_cert"] for s in sites["servers"] if s.get("fallback_cert")}
    for name in fallback_certs:
        check(
            name in observed_cert_names,
            f"fallback certificate {name} was not observed",
        )

    # 4. IP-as-SNI: the .12 server presents a certificate whose SAN carries the
    #    target IP, which must surface as an "(IP as SNI)" row.
    for server in sites["servers"]:
        if not any(s.get("ip_sni") for s in server["sites"]):
            continue
        target = f"{server['ip']}:443"
        row = by_alt.get((target, "(IP as SNI)"))
        check(row is not None, f"missing (IP as SNI) row on {target}")
        if row:
            check(
                row.get("cert_valid") is True,
                f"(IP as SNI) on {target}: cert_valid={row.get('cert_valid')}",
            )

    # 5. A hardened IP-only scan (no supplied hostnames) must reveal nothing:
    #    zero host rows for the hardened target(s).
    ip_only_path = sys.argv[3] if len(sys.argv) > 3 else None
    if ip_only_path:
        ip_hosts = [r for r in load_jsonl(ip_only_path) if r.get("type") == "host"]
        check(
            len(ip_hosts) == 0,
            f"hardened IP-only scan revealed {len(ip_hosts)} host row(s), expected 0",
        )

    # 6. The plaintext-HTTP-on-TLS-port probe must not fabricate findings on the
    #    test servers: they answer with the standard 400 rejection and leak no
    #    hostname, so no plain_http_tls row may appear. A leak detected on the
    #    TLS port is exercised by the Go unit tests.
    tls_rows = [h for h in hosts if h.get("plain_http_tls")]
    check(
        len(tls_rows) == 0,
        f"plaintext-on-TLS probe produced {len(tls_rows)} row(s), expected 0 (no leak)",
    )

    # 7. Header-leak test: the hardened, DNS-less header-leak server leaks its
    #    canonical hostname only in a plaintext-HTTP response header (not in the
    #    Location header, not in DNS/PTR, not over TLS). An IP-only scan with
    #    --search-headers must discover the vhost purely from that leak: the
    #    hostname appears with an unresolved DNS state, a valid certificate and a
    #    200, and the (HTTP ...) pseudo-host row proves the plain HTTP probe
    #    found the name in a header.
    header_leak_path = sys.argv[4] if len(sys.argv) > 4 else None
    if header_leak_path:
        leak_hosts = [r for r in load_jsonl(header_leak_path) if r.get("type") == "host"]
        for server in sites["servers"]:
            if not server.get("http_header_leak"):
                continue
            target = f"{server['ip']}:443"
            names = [n for n in server["sites"][0]["server_names"] if not is_ip(n)]
            name = names[0]
            row = next(
                (
                    h
                    for h in leak_hosts
                    if h["target"] == target and h.get("hostname") == name
                ),
                None,
            )
            check(
                row is not None,
                f"header-leak scan did not discover {name} on {target} "
                f"(hostnames={[h.get('hostname') for h in leak_hosts]})",
            )
            if row:
                check(
                    row.get("cert_valid") is True,
                    f"header-leak {name} on {target}: cert_valid={row.get('cert_valid')}",
                )
                check(
                    row.get("dns") in ("unresolved", "resolves_elsewhere"),
                    f"header-leak {name} on {target}: dns={row.get('dns')!r}, "
                    "expected unresolved/resolves_elsewhere",
                )
                check(
                    row.get("http_status") == 200,
                    f"header-leak {name} on {target}: http_status={row.get('http_status')}, "
                    "expected 200",
                )
            check(
                any(
                    h["target"] == target
                    and str(h.get("alternate_text", "")).startswith("(HTTP ")
                    for h in leak_hosts
                ),
                f"header-leak scan produced no (HTTP ...) row on {target}",
            )

    # 8. The same IP-only scan without --search-headers must reveal nothing: the
    #    TLS layer is hardened and the header leak is not parsed by default.
    leak_nosearch_path = sys.argv[5] if len(sys.argv) > 5 else None
    if leak_nosearch_path:
        nosearch_hosts = [
            r for r in load_jsonl(leak_nosearch_path) if r.get("type") == "host"
        ]
        check(
            len(nosearch_hosts) == 0,
            f"default header-leak scan revealed {len(nosearch_hosts)} host row(s), expected 0",
        )

    # 9. Summary and IP records: the main scan must report at least one
    #    iteration, not be cancelled, and emit one IP record per target with
    #    the well-formed whois (UNKNOWN) state.
    if summary:
        check(
            isinstance(summary[0].get("iterations"), int) and summary[0]["iterations"] >= 1,
            f"summary iterations = {summary[0].get('iterations')!r}, expected >= 1",
        )
        check(
            summary[0].get("cancelled") is False,
            f"summary cancelled = {summary[0].get('cancelled')!r}, expected False",
        )
    ip_records = [r for r in records if r.get("type") == "ip"]
    observed_ips = {r.get("ip") for r in ip_records}
    for server in sites["servers"]:
        check(
            server["ip"] in observed_ips,
            f"missing ip record for {server['ip']} (records: {sorted(observed_ips)})",
        )
    expired_manifest_names = {
        c["name"] for c in sites["certificates"] if c.get("expired")
    }
    for cert in certs:
        cert_expired = bool(expired_manifest_names & set(cert.get("names", [])))
        check(
            cert.get("expired") is cert_expired,
            f"certificate {cert.get('serial')} expired={cert.get('expired')}, "
            f"expected {cert_expired}",
        )

    # 10. Ignore list (-i): supplied hosts matching the ignore pattern must be
    #     filtered from the scan entirely; everything else must survive.
    ignore_path = sys.argv[6] if len(sys.argv) > 6 else None
    if ignore_path:
        ignore_hosts = [r for r in load_jsonl(ignore_path) if r.get("type") == "host"]
        ignored_names = {"portal.test", "beta.test"}
        for row in ignore_hosts:
            check(
                row.get("hostname") not in ignored_names,
                f"-i scan still produced a row for ignored host {row.get('hostname')!r}",
            )
        by_host_ignore = {(h["target"], h.get("hostname")) for h in ignore_hosts}
        check(
            ("127.0.42.10:443", "alpha.test") in by_host_ignore,
            "-i scan lost alpha.test, which is not ignored",
        )

    # 11. Require list (-r "^nomatch"): recon-discovered hostnames that match
    #     none of the require patterns must be dropped even though the probe
    #     that finds them still runs ((HTTP ...) row present, hostname row
    #     absent), while supplied hosts are handed to the scan explicitly and
    #     survive the filter.
    require_path = sys.argv[7] if len(sys.argv) > 7 else None
    if require_path:
        require_hosts = [r for r in load_jsonl(require_path) if r.get("type") == "host"]
        leaked = {
            row.get("hostname")
            for row in require_hosts
            if row.get("hostname") in ("hop.test", "final.test", "legacy.alpha.test", "hidden.test")
        }
        check(
            not leaked,
            f"-r scan still produced rows for recon-discovered hosts: {sorted(leaked)}",
        )
        by_host_require = {(h["target"], h.get("hostname")) for h in require_hosts}
        check(
            ("127.0.42.10:443", "alpha.test") in by_host_require,
            "-r scan lost supplied host alpha.test",
        )
        check(
            any(
                h["target"] == "127.0.42.14:443"
                and str(h.get("alternate_text", "")).startswith("(HTTP ")
                for h in require_hosts
            ),
            "-r scan lost the (HTTP 127.0.42.14) probe row; the header probe must still run",
        )

    # 12. --no-recon --no-ip-sni: redirect/header-based discovery must be
    #     disabled (sso.test and hidden.test must never be queued) and the
    #     (IP as SNI) row must not be produced.
    norecon_path = sys.argv[8] if len(sys.argv) > 8 else None
    if norecon_path:
        norecon_hosts = [r for r in load_jsonl(norecon_path) if r.get("type") == "host"]
        for row in norecon_hosts:
            check(
                row.get("hostname") not in ("hop.test", "final.test", "legacy.alpha.test", "hidden.test"),
                f"--no-recon scan still discovered {row.get('hostname')!r}",
            )
            check(
                row.get("alternate_text") != "(IP as SNI)",
                "--no-ip-sni scan still produced an (IP as SNI) row",
            )
        by_host_norecon = {(h["target"], h.get("hostname")) for h in norecon_hosts}
        check(
            ("127.0.42.10:443", "alpha.test") in by_host_norecon,
            "--no-recon scan lost supplied host alpha.test",
        )

    # 13. --jsonl -: stdout must contain only valid JSONL records with the
    #     expected envelope (config first, summary last).
    stdout_path = sys.argv[9] if len(sys.argv) > 9 else None
    if stdout_path:
        stdout_records = load_jsonl(stdout_path)
        check(len(stdout_records) >= 2, "stdout JSONL produced too few records")
        if stdout_records:
            check(
                stdout_records[0].get("type") == "config",
                f"stdout JSONL must start with a config record, got {stdout_records[0].get('type')!r}",
            )
            check(
                stdout_records[-1].get("type") == "summary",
                f"stdout JSONL must end with a summary record, got {stdout_records[-1].get('type')!r}",
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
