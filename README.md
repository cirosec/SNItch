# SNItch

SNItch is an SNI-based virtual host (**vhost**) discovery tool for TLS-layer reconnaissance. It fuzzes the Server Name Indication (SNI) extension in TLS ClientHello messages to enumerate virtual hosts and find where FQDNs are really hosted — catching misconfigurations and unmanaged or hidden services that HTTP-layer tools like ffuf, gobuster, and wfuzz cannot overcome due to their architecture.

Read more in the [blog post](https://cirosec.de/blog/snitch).

## Why SNItch?

Traditional vhost enumeration tools (ffuf, gobuster, wfuzz) operate at the HTTP layer by iterating `Host` header values. This has two fundamental problems:

1. **TLS-level rejection is invisible**: Servers configured to reject unknown SNI values terminate the connection before HTTP is reached. HTTP-layer tools never see a response and cannot detect these services.
2. **Connection pooling produces domain-fronted requests**: Commonly used vhost enumeration tools reuse TLS connections for performance. The SNI is set once during the handshake and stays fixed, while the `Host` header changes per request. Servers enforcing SNI-Host consistency reject every candidate, producing uniform responses that hide valid hosts.

SNItch avoids both problems by establishing a fresh TLS handshake per candidate hostname with the correct SNI value, using [uTLS](https://github.com/refraction-networking/utls) for full control over the ClientHello.

## Installation

Requires Go 1.26+.

```bash
# From source (binary named SNItch)
git clone https://github.com/cirosec/SNItch.git
cd SNItch
go build -o SNItch .

# Or install with Go (binary named lowercase "snitch")
go install github.com/cirosec/snitch@latest
```

## Quick Start

```bash
# Scan a domain — resolves DNS automatically, scans port 443, queries crt.name and PTR records
SNItch example.com
```

Sample output (`SNItch example.com`, abridged):

```
$ SNItch example.com
🎩 SNItch 1.4-dev - © cirosec GmbH
[config] Hosts: example.com
[config] Targets: [2606:4700:10::6814:179a]:443, [2606:4700:10::ac42:93f3]:443, 104.20.23.154:443, 172.66.147.243:443
[reverseip] Found 0 hostnames via PTR lookups
[crt.name] ⚡ example.com
[scan] 🔥 Not all identified hosts have been scanned. You can increase the number of iterations using the CLI flag -e (e.g. -e 3).
[scan] 🔥 Unscanned hosts (increase epochs): [...]

───────────── Observed Certificates ──────────────
2569673129 [2026-12-25] (example.com, *.example.com)  [SSL Corporation]
⤷ [2606:4700:10::6814:179a]:443, 104.20.23.154:443, [2606:4700:10::ac42:93f3]:443, 172.66.147.243:443

                                 104.20.23.154:443
                              HOSTNAME   DNS  CERT
                           example.com    ✅   ✅    [200]   Example Domain
                         *.example.com         ✅    [530]   
[... one block per target ...]

────────────────── Observed IPs ──────────────────
(UNKNOWN)
⤷ 2606:4700:10::ac42:93f3
Cloudflare, Inc. (CLOUD14)
⤷ 104.20.23.154, 172.66.147.243, 2606:4700:10::6814:179a
```

### Reading the output

Each target block is a table of rows; one row per hostname (or pseudo-host) probed against that IP.

| Column / token | Meaning |
|----------------|---------|
| `HOSTNAME` | The probed name, an encoding variant, or a pseudo-host label (see below) |
| `DNS` | `✅` resolves to this target IP, `❌` resolves elsewhere, `❔` could not be resolved, blank = not applicable (wildcard/pseudo-host) |
| `CERT` | `✅` the certificate is valid for the name, `❌` no valid certificate. No full browser-like validation is done |
| `[NNN]` | HTTP status code returned for the probe. `[0]` indicates no usable HTTP response |
| trailing text | The page title, or `➤ URL` for a redirect |

Pseudo-hosts and flags you may see in the `HOSTNAME`/first column:

- `(EMPTY SNI)` — the server answered a handshake with no SNI at all
- `(IP as SNI)` — the server accepted the target IP address as the SNI value
- `(HTTP <host>)` — a hostname revealed by the plaintext HTTP probe on the HTTP port, using the named `Host` variant
- `(HTTP/TLS <host>)` — a hostname revealed by the plaintext HTTP probe sent to the target's own TLS port
- `(RANDOM CERT)` — the server mints a certificate per SNI value (echoing the requested name); hostnames from it are reflections, not real vhosts

A block from the self-contained [test environment](#testing) exercises several of these pseudo-hosts at once:

```
                                   127.0.42.12:443  (multi.test)
                              HOSTNAME   DNS  CERT
                    (HTTP 127.0.42.12)               [301] ➤ https://portal.test/
                           (EMPTY SNI)               [200]   IP Service
                           (IP as SNI)         ✅         
                          generic.test    ❌   ✅    [200]   Fallback Service
                            multi.test    ✅   ✅    [200]   Multi Service
                          service.test    ✅   ✅    [200]   Multi Service
```

The interesting finding is a hostname that returns a `200` (or any real service) while its `DNS` column is `❌`: the name does not resolve to the scanned IP, yet that IP serves it — a likely misconfiguration or hidden vhost.

Because SNItch feeds newly discovered hostnames back into the queue, a single run may not exhaust every name. The `[scan] 🔥 Unscanned hosts` warning lists the remainder; raise `-e` (epochs) to keep scanning, or add `-r`/`-i` to bound the search space.

## Usage

```bash
# Scan specific hostnames against specific IPs
SNItch -t 8.8.8.8,1.1.1.1:443,10.0.0.0/24 -d api.example.com,mail.example.com

# Scan a CIDR range with a hostname list from file
SNItch -t 10.11.10.0/24:443 --host-list hostnames.txt

# Non-standard and multiple ports
SNItch -t 10.0.0.0/24:8443 -t 10.0.0.0/24:443 -d api.example.com

# Feed a candidate-vhost list of FQDNs and skip automated recon. Note that
# SecLists DNS lists (e.g. subdomains-top1million-5000.txt) hold bare labels,
# not FQDNs, so append the domain first — SNItch sends each entry as-is as SNI.
awk '{print $0".example.com"}' /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt > hosts.txt
SNItch -t example.com --host-list hosts.txt --no-recon

# Disable all recon, only test supplied hostnames against supplied targets
SNItch -t images.google.com -d maps.google.com --no-recon

# Custom DNS server, reduced threads, increased timeout (stealthy / rate-limited)
SNItch -t 10.0.0.0/24:443 -d example.com --dns 1.1.1.1 -p 5 --timeout 30

# Ignore specific domains, require regex match on discovered FQDNs
SNItch example.com -i cdn.example.com -r ".*\.example\.com$"

# Windows
SNItch.exe example.com
```

### All Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--targets` | `-t` | Comma separated targets: domain, IP, CIDR, with optional port | (none; port `443` assumed) |
| `--hosts` | `-d` | Comma separated hostnames/wildcards to test | |
| `--target-list` | | File with targets (one per line) | |
| `--host-list` | | File with hostnames (one per line) | |
| `--epochs` | `-e` | Maximum scan iterations | `2` |
| `--threads` | `-p` | Concurrent probe threads | `50` |
| `--timeout` | | Timeout in seconds for all network operations | `10` |
| `--dns` | | Custom DNS server (e.g. `8.8.8.8` or `1.1.1.1:53`) | system resolver |
| `--ignore` | `-i` | FQDNs/wildcards to exclude from scanning | |
| `--require` | `-r` | Regex filters: only scan FQDNs matching all patterns | |
| `--no-recon` | | Disable all recon (crt.name, PTR, certificate extraction) | |
| `--no-crtlog` | | Disable crt.name certificate transparency queries | |
| `--no-ptr` | | Disable reverse IP (PTR) hostname discovery | |
| `--no-ip-sni` | | Disable sending IP as SNI value (use for Cloudflare-style targets that block non-RFC SNI) | |
| `--no-http` | | Disable plaintext HTTP probing of each target IP and of its TLS port | |
| `--http-port` | | Port used for plaintext HTTP probing | `80` |
| `--search-headers` | | Search all HTTP response headers for domains, not just Location redirects | |
| `--crtlog-db` | | Path to the local crt.name cache directory | `/tmp/crtlog` |
| `--user-agent` | | Custom User-Agent header for HTTP requests | generic browser-like SNItch UA |
| `--jsonl` | | Write machine-readable results as JSONL to a file. Use `-` for stdout | |
| `--debug` | | Write detailed debug output to log file | |

### Machine-readable output

Pass `--jsonl <file>` to additionally write results as newline-delimited JSON
(one object per line), suitable for `jq` or further tooling. The human-readable
report is still written to stdout.

```bash
# JSONL to a file, human report still on stdout
SNItch example.com --jsonl results.jsonl

# JSONL on stdout: human/progress output moves to stderr, stdout stays pure JSONL
SNItch example.com --jsonl - | jq -c 'select(.type=="host")'
```

Records are discriminated by a `type` field:

| `type` | Contents |
|--------|----------|
| `config` | version, targets, hosts, ignored/required host filters, DNS server |
| `certificate` | serial, not_after, expired, names, email addresses, organizations, targets the certificate was seen on |
| `host` | one table row: target, hostname, wildcard, DNS state, cert validity, HTTP status/title/redirect, `alternate_text` for pseudo-hosts, `plain_http_tls` when revealed on the TLS port |
| `ip` | one unique target IP with WHOIS name and net range, plus `dynamic_certificates` when the IP mints per-SNI certificates |
| `summary` | iterations, cancelled flag, and hosts left unscanned |

The `host` records are generated from the same built rows as the printed
tables, so the two outputs cannot diverge.

## Features

- **SNI fuzzing** — injects candidate hostnames into the TLS ClientHello SNI extension
- **Encoding and structural probes** — per-hostname variants (trailing dot, uppercase, IDN A-label/U-label) plus RFC 6066 multi-name and duplicate `server_name` extension probes, which also feed the per-SNI reflection detection
- **Iterative recon** — hostnames from certificates (CN, SAN and email domains), crt.name CT logs and reverse-DNS (PTR) lookups are fed back into the scan queue across multiple epochs
- **Cross-IP validation** — every discovered hostname is validated against every target IP; a single misconfigured server leaking a hostname exposes it across the entire range
- **DNS-aware wildcard handling** — structures FQDNs and certificates using DNS hierarchy to detect and handle wildcard domains
- **Non-RFC SNI probes** — sends IP addresses as SNI values to test server behavior; disable with `--no-ip-sni` (recommended for Cloudflare-style targets that block non-RFC SNI)
- **Plaintext HTTP host discovery** — probes each target IP over plain HTTP on `--http-port` (default 80) and on the target's own TLS port, with three `Host` variants (the IP, a random hostname and an invalid hostname such as `$`), revealing hostnames from HTTP→HTTPS redirects and catch-all servers even when the TLS layer is hardened; with `--search-headers` hostnames are also extracted from any other response header (e.g. a `Content-Security-Policy`), so an HTTP header leak exposes a vhost on an otherwise hardened service; disable with `--no-http`
- **Per-SNI dynamic certificate detection** — flags servers that echo the requested SNI back in a freshly minted certificate (a `(RANDOM CERT)` row and `dynamic_certificates` in JSONL) and refuses to treat the reflected names as real vhosts
- **Reflection and sanitization guards** — catch-all servers that echo the requested `Host` into redirects no longer produce false wildcard rows, and malformed names never enter the queue
- **WHOIS annotation** — annotates every observed target IP with its WHOIS organization and net range
- **CIDR and IPv6 support** — accepts targets as domains, IPs, CIDR ranges, and IPv6 bracket notation
- **Configurable threading and timeouts** — adjust concurrency (`-p`) and timeouts (`--timeout`) for rate-limited environments
- **Graceful shutdown** — `Ctrl+C` stops the scan and still prints partial results; press it a second time to force an immediate exit
- **Hardening signal** — when an IP-only scan (no hostnames) reveals nothing, it is a good indicator that the TLS layer is properly hardened

## Testing

A self-contained Docker test environment lives in [`testenv/`](testenv/README.md).
It stands up several TLS servers on `127.0.42.0/24` with self-signed
certificates and a local DNS server, so the scanner can be exercised hermetically
(no internet, no `crt.name`) and the results verified against expectations:

```bash
cd testenv
./setup.sh nginx      # render configs, generate certs, start the stack
./run-snitch.sh       # scan the environment and print the report
./verify.sh nginx     # scan and assert the expected findings
./teardown.sh
```

The environment models a shared multi-tenant server, an SNI-strict server, a
catch-all fallback server, a fully hardened server, and a **header-leak** server:
the last is hardened at the TLS layer (unknown/absent SNI rejected, no fallback
certificate, no DNS/PTR) yet leaks its hostname in a `Content-Security-Policy`
response header on plain HTTP. Its name is deliberately **not** supplied on the
CLI or published in DNS, so the scan discovers it by itself from that header with
`--search-headers` (and finds nothing without the flag). The fully hardened
server's name is likewise withheld and no scan reveals it. See
[`testenv/README.md`](testenv/README.md) for the full scenario table and expected
results.

## Limitations

- **One TLS handshake per candidate**: By design, SNItch cannot reuse connections. Scanning is slower than HTTP-layer tools that benefit from connection pooling.
- **No HTTP-layer Host header fuzzing**: SNItch operates at the TLS layer and does not fuzz the HTTP `Host` header against a candidate wordlist. The optional plaintext HTTP probe (`--http-port`) sends only three fixed `Host` variants (IP, random, invalid) to observe server behavior, not an enumeration.
- **Host lists are FQDNs, not labels**: Every `--host-list` entry is sent verbatim as the SNI value, so a bare-label wordlist (such as the SecLists DNS lists) must be turned into FQDNs first; prefixing the domain is enough.
- **No proxy or SOCKS support**: SNItch connects directly; it has no built-in proxy, SOCKS or Tor routing, so it must be run from a host with the reachability and opsec posture you need.
- **External service dependencies**: crt.name, DNS and WHOIS queries depend on third-party services. Disable the first two with `--no-crtlog`, `--no-ptr`, or `--no-recon`; WHOIS lookups (for the Observed IPs section) are always attempted.
- **crt.name cache persistence**: CT lookups are cached on disk under `--crtlog-db` (default `/tmp/crtlog`). The cache persists between runs; delete the directory to force fresh lookups.
- **JSONL only**: Machine-readable output is JSONL via `--jsonl`; there is no CSV or XML export. For a quick file dump of the human report use `| tee`, keeping in mind it contains emoji and ANSI colors.
- **Detectable at volume**: A burst of TLS handshakes from a single source with rapidly changing SNI values is anomalous and detectable.

## Authorized use

SNItch is intended for authorized security testing only. Scanning hosts without
prior permission may be illegal in your jurisdiction. You are responsible for
ensuring you have explicit authorization for every target you scan.

## License

(c) cirosec GmbH - GNU Affero General Public License v3.0 (AGPL-3.0)
