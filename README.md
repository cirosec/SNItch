# SNItch

SNI-based host discovery tool for TLS layer reconnaissance. SNItch fuzzes the Server Name Indication (SNI) extension in TLS ClientHello messages to enumerate virtual hosts, bypassing HTTP-layer limitations that tools like ffuf, gobuster, and wfuzz cannot overcome due to their architecture.

Read more in the [blog post](https://cirosec.de/blog/snitch).

## Installation

```bash
git clone https://github.com/cirosec/SNItch.git
cd SNItch
go build -o SNItch .
```

Requires Go 1.24+.

## Quick Start

```bash
# Scan a domain — resolves DNS automatically, scans port 443, queries crt.sh and PTR records
SNItch example.com

# Scan a CIDR range with candidate hostnames
SNItch -t 10.11.10.0/24:443 -d api.example.com,mail.example.com

# Only test supplied hostnames, no automated recon
SNItch -t 10.0.0.1:443 -d admin.example.com,staging.example.com --no-recon
```

Sample output:

```
$ SNItch "example.com"                                                                                                                                                                                                                                                                                            
🎩 SNItch 1.3 - © cirosec GmbH
[config] Hosts: example.com
[config] Targets: 104.18.26.120:443, 104.18.27.120:443, [2606:4700::6812:1b78]:443, [2606:4700::6812:1a78]:443
[config] Ignored Hosts: (none) - use -i "*.domain.com" to exclude domains from the search
[config] Required Match: (none) - use -r "regex" to only scan FQDNs matching the pattern
[reverseip] Found 0 hostnames via PTR lookups
[crt.sh] ⚡ example.com
[crt.sh] ⚡ example.com,example.org,jivesoftware.com,testexample.com
[scan] 🔥 Not all identified hosts have been scanned. You can increase the number of iterations using the CLI flag -e (e.g. -e 3).
[scan] 🔥 Unscanned hosts (increase epochs): [...]

───────────── Observed Certificates ──────────────
1085688279 [2026-05-14] (example.com, *.example.com)
⤷ 104.18.26.120:443, 104.18.27.120:443
1162624729 [2026-05-08] (example.org, *.example.org)
⤷ 104.18.26.120:443, 104.18.27.120:443


                                 104.18.26.120:443
                              HOSTNAME   DNS  CERT
                           (EMPTY SNI)               [  0]   
                           example.com    ✅   ✅    [200]   Example Domain
                         *.example.com         ✅    [530]   
                       dev.example.com    ❔   ✅    [530]   
                         m.example.com    ❔   ✅    [530]   
                  products.example.com    ❔   ✅    [530]   
                   support.example.com    ❔   ✅    [530]   
                       www.example.com    ✅   ✅    [200]   Example Domain
                           example.org    ❌   ✅    [200]   Example Domain
                         *.example.org         ✅    [530]   
                       www.example.org    ❌   ✅    [200]   Example Domain

                                 104.18.27.120:443
                              HOSTNAME   DNS  CERT
                           (EMPTY SNI)               [  0]   
                           example.com    ✅   ✅    [200]   Example Domain
                         *.example.com         ✅    [530]   
                       dev.example.com    ❌   ✅    [530]   
                         m.example.com    ❌   ✅    [530]   
                  products.example.com    ❌   ✅    [530]   
                   support.example.com    ❌   ✅    [530]   
                       www.example.com    ✅   ✅    [200]   Example Domain
                           example.org    ❌   ✅    [200]   Example Domain
                         *.example.org         ✅    [530]   
                       www.example.org    ❌   ✅    [200]   Example Domain

─────────────────────── Legend ───────────────────────
DNS:  ✅=Resolves to target IP  ❌=Resolves elsewhere  ❔=DNS entry not resolved
CERT: ✅=Valid certificate for hostname  ❌=Invalid/missing certificate*
      *No full browser-like certificate validation is performed!

────────────────── Observed IPs ──────────────────
Cloudflare, Inc. (CLOUD14) 
⤷ 104.18.26.120, 104.18.27.120


```

## Why SNItch?

Traditional vhost enumeration tools (ffuf, gobuster, wfuzz) operate at the HTTP layer by iterating `Host` header values. This has two fundamental problems:

1. **TLS-level rejection is invisible**: Servers configured to reject unknown SNI values terminate the connection before HTTP is reached. HTTP-layer tools never see a response and cannot detect these services.
2. **Connection pooling produces domain-fronted requests**: Commonly used vhost enumeration tools reuse TLS connections for performance. The SNI is set once during the handshake and stays fixed, while the `Host` header changes per request. Servers enforcing SNI-Host consistency reject every candidate, producing uniform responses that hide valid hosts.

SNItch avoids both problems by establishing a fresh TLS handshake per candidate hostname with the correct SNI value, using [uTLS](https://github.com/refraction-networking/utls) for full control over the ClientHello.

## Features

- **SNI fuzzing** — injects candidate hostnames into the TLS ClientHello SNI extension
- **Iterative discovery** — extracted hostnames from certificates, redirects, and CT logs are fed back into the scan queue across multiple epochs
- **Certificate extraction** — collects hostnames from `Subject.CommonName` and `SubjectAltName` fields
- **CT log queries** — gathers subdomains from crt.sh to enrich the hostname pool
- **PTR record lookups** — discovers hostnames via reverse DNS on target IPs
- **Cross-IP validation** — every discovered hostname is validated against every target IP; a single misconfigured server leaking a hostname exposes it across the entire range
- **DNS-aware wildcard handling** — structures FQDNs and certificates using DNS hierarchy to detect and handle wildcard domains
- **Non-RFC SNI probes** — sends IP addresses as SNI values to test server behavior; disable with `--no-ip-sni`
- **CIDR and IPv6 support** — accepts targets as domains, IPs, CIDR ranges, and IPv6 bracket notation
- **Configurable threading and timeouts** — adjust concurrency (`-p`) and timeouts (`--timeout`) for rate-limited environments
- **Hardening validation** — when SNItch finds nothing from an IP-only scan, the server is properly hardened

## Usage

```bash
# Basic scan: resolves DNS A/AAAA records automatically, scans on port 443
SNItch example.com

# Scan specific hostnames against specific IPs
SNItch -t 8.8.8.8,1.1.1.1:443,10.0.0.0/24 -d api.example.com,mail.example.com

# Scan a CIDR range with a hostname list from file
SNItch -t 10.11.10.0/24:443 --host-list hostnames.txt

# Disable all recon, only test supplied hostnames against supplied targets
SNItch -t images.google.com -d maps.google.com --no-recon

# Custom DNS server, reduced threads, increased timeout
SNItch -t 10.0.0.0/24:443 -d example.com --dns 1.1.1.1 -p 10 --timeout 30

# Ignore specific domains, require regex match on discovered FQDNs
SNItch example.com -i cdn.example.com -r ".*\.example\.com$"
```

### All Flags

| Flag | Short | Description | Default |
|------|-------|-------------|---------|
| `--targets` | `-t` | Comma separated targets: domain, IP, CIDR, with optional port | `443` |
| `--hosts` | `-d` | Comma separated hostnames/wildcards to test | |
| `--target-list` | | File with targets (one per line) | |
| `--host-list` | | File with hostnames (one per line) | |
| `--epochs` | `-e` | Maximum scan iterations | `2` |
| `--threads` | `-p` | Concurrent probe threads | `50` |
| `--timeout` | | Timeout in seconds for all network operations | `10` |
| `--dns` | | Custom DNS server (e.g. `8.8.8.8` or `1.1.1.1:53`) | system resolver |
| `--ignore` | `-i` | FQDNs/wildcards to exclude from scanning | |
| `--require` | `-r` | Regex filters: only scan FQDNs matching all patterns | |
| `--no-recon` | | Disable all recon (crt.sh, PTR, certificate extraction) | |
| `--no-crtsh` | | Disable crt.sh certificate transparency queries | |
| `--no-ptr` | | Disable reverse IP (PTR) hostname discovery | |
| `--no-ip-sni` | | Disable sending IP as SNI value | |
| `--search-headers` | | Search all HTTP response headers for domains, not just Location redirects | |
| `--crtsh-db` | | Path to the local crt.sh cache directory | `/tmp/crtshdb` |
| `--user-agent` | | Custom User-Agent header for HTTP requests | |
| `--debug` | | Write detailed debug output to log file | |

## Limitations

- **One TLS handshake per candidate**: By design, SNItch cannot reuse connections. Scanning is slower than HTTP-layer tools that benefit from connection pooling.
- **No HTTP-layer Host header fuzzing**: SNItch operates at the TLS layer and does not fuzz the HTTP `Host` header independently. 
- **External service dependency**: crt.sh and DNS queries depend on third-party services. Disable with `--no-crtsh`, `--no-ptr`, or `--no-recon`.
- **Detectable at volume**: A burst of TLS handshakes from a single source with rapidly changing SNI values is anomalous and detectable.

## License

(c) cirosec GmbH - GNU Affero General Public License v3.0 (AGPL-3.0)
