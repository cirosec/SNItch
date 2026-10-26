# SNItch Docker test environment

A self-contained, hermetic test bed for **SNItch**. It stands up several
virtual TLS servers on individual `127.0.42.0/24` addresses with self-signed
certificates and a local DNS server, so every feature of the scanner can be
exercised without touching the internet or real infrastructure.

Two interchangeable TLS stacks are provided — **nginx** and **Caddy** — that
implement exactly the same scenarios from a single source of truth
(`sites.json`).

- Linux-only: the containers use `network_mode: host` so the servers can bind
  the individual `127.0.42.x` addresses (the loopback interface owns the whole
  `127.0.0.0/8` range) and DNS can listen on `127.0.0.1:5353`.
- Hermetic: the scan uses the local DNS resolver and disables the external
  `crt.name` lookups (`--no-crtlog`).

> **Octet order:** the addresses are `127.0.42.10`, `127.0.42.11`,
> `127.0.42.12` — i.e. the `127.0.42.0/24` network. (Not `127.42.0.x`.)

## Requirements

| Tool | Purpose |
|------|---------|
| Docker + Compose v2 | run the servers and DNS |
| `openssl` | generate the self-signed certificates (3.4+ required for the deliberately expired `expired.test` certificate, which uses `-not_before`/`-not_after`) |
| `python3` | render configs from `sites.json`, verify results |
| Go (1.26+) | build SNItch (done automatically by the helper scripts) |

## Quick start

```bash
cd testenv

# nginx environment (default)
./setup.sh nginx

# run a scan and print the report
./run-snitch.sh

# run a scan and check it against the expected findings
./verify.sh nginx

# stop everything
./teardown.sh
```

For the Caddy variant:

```bash
./setup.sh caddy
./verify.sh caddy
```

`setup.sh` renders the configuration, generates the certificates, stops any
running stack, and starts the DNS server plus the selected stack. The two
stacks are mutually exclusive (they bind the same addresses), so switching is
just `./setup.sh caddy` / `./setup.sh nginx`.

Set `FORCE=1` to regenerate certificates after changing `sites.json`:

```bash
FORCE=1 ./setup.sh nginx
```

## Layout

```
testenv/
├── sites.json              # single source of truth: servers, certs, DNS
├── setup.sh                # render + certs + bring the stack up
├── teardown.sh             # stop and remove the stack
├── run-snitch.sh           # build (if needed) and scan the environment
├── verify.sh               # scan with JSONL and assert expected findings
├── docker-compose.yml      # dns + nginx / one Caddy per IP (compose profiles)
├── dns/Dockerfile          # dnsmasq on alpine
├── scripts/
│   ├── render.py           # sites.json -> nginx confs, Caddyfiles, dnsmasq.conf
│   ├── generate-certs.sh   # self-signed certificates via openssl
│   ├── verify.py           # JSONL result assertions
│   └── probe-http-tls.py   # raw plaintext-HTTP-on-443 checks (responds + no leak)
├── certs/                  # generated, git-ignored
└── generated/              # generated, git-ignored
```

## What is deployed

Each `127.0.42.x` address models a different real-world misconfiguration so
that a single scan covers the interesting code paths.

| Address | Role | Serves | SNItch behaviour exercised |
|---------|------|--------|----------------------------|
| `127.0.42.10:443` | **shared** | `alpha.test`, `www.alpha.test`, `legacy.alpha.test`, `beta.test`, `wild.test`, `*.wild.test`, `portal.test` (301 → `hop.test` → `final.test`), `hop.test`, `final.test` | SNI virtual-host routing, wildcard certificates, fallback certificate for unknown/absent SNI, redirect-based discovery, a two-hop redirect chain (`portal.test` → `hop.test` → `final.test`, needs `-e 3`), and cert-SAN discovery of a vhost that is neither in DNS nor supplied (`legacy.alpha.test`) |
| `127.0.42.11:443` | **strict** | `strict.test` | SNI-strict server: unknown and absent SNI are rejected with a TLS alert (`SNIDisconnectsOnRandom = true`) |
| `127.0.42.12:443` | **fallback** | `multi.test`, `service.test`, `expired.test`, catch-all fallback, `127.0.42.12` (IP-as-SNI) | catch-all server with a generic fallback certificate, IP-in-SAN certificate for the IP-as-SNI probe, and a deliberately expired certificate whose JSONL record must carry `expired: true` |
| `127.0.42.12:8443` | **alt-port** | `altport.test` | same server on a non-443 TLS port, exercising `IP:port` targets end-to-end |
| `127.0.42.13:443` | **hardened** | `hardened.test` only | fully hardened: unknown/absent SNI rejected, no fallback certificate, plaintext HTTP closes with no response, and no DNS/PTR records. Its name is not supplied on the CLI either, so **no scan reveals anything** |
| `127.0.42.14:443` | **header-leak** | `hidden.test` only | TLS-hardened like `.13` (unknown/absent SNI rejected, no fallback certificate, no DNS/PTR), but its plaintext HTTP service leaks `hidden.test` in a `Content-Security-Policy` response header. The name is not supplied, so SNItch must discover it from that header with `--search-headers`; without the flag it reveals nothing |

Every non-hardened address (`.10`, `.11`, `.12`) also answers plaintext HTTP on
port 80 with a `301` redirect to its canonical hostname (`https://alpha.test`,
`https://strict.test`, `https://portal.test`), which exercises the
plaintext-HTTP host discovery path — notably on the **strict** server, where the
TLS layer reveals nothing. The **hardened** address returns no HTTP response at
all.

The **header-leak** address (`127.0.42.14`) is TLS-hardened exactly like the
hardened one (unknown/absent SNI rejected, no fallback certificate, absent from
DNS/PTR), but its port 80 returns a normal page whose body names no host and
whose `Content-Security-Policy` header leaks the vhost
(`connect-src https://hidden.test`). Because `Location` is the only header
parsed without `--search-headers`, a default scan reveals nothing here. The
`verify.sh` main scan runs with `--search-headers`, so SNItch discovers
`hidden.test` from the header alone (DNS unresolved, valid certificate, HTTP 200)
plus the `(HTTP 127.0.42.14)` pseudo-host row; a dedicated IP-only scan repeats
the discovery from nothing, and a second default scan (no `--search-headers`)
must find nothing. This models a service whose TLS layer is hardened while its
HTTP layer still names it.

Independently, SNItch sends a plaintext HTTP request to each target's own (TLS)
port. All addresses answer that with a `400 Bad Request` ("The plain HTTP
request was sent to HTTPS port" on nginx, "Client sent an HTTP request to an
HTTPS server" on Caddy) and leak no hostname, so this probe produces no rows
here. It exists to catch servers that answer plaintext HTTP on their TLS port
and leak a hostname there; that leak detection is covered by the scanner's unit
tests rather than this environment.

### Certificates

All certificates are self-signed (no CA) and generated by
`scripts/generate-certs.sh` from the inventory in `generated/certs.manifest`.
The SANs intentionally cover the interesting cases:

| Certificate | SANs |
|-------------|------|
| `alpha.test` | `alpha.test`, `www.alpha.test`, `legacy.alpha.test` |
| `wild.test` | `wild.test`, `*.wild.test` |
| `multi.test` | `multi.test`, `service.test` |
| `hop.test` / `final.test` | the two redirect-chain vhosts on the shared server |
| `altport.test` | served only on the non-443 port (8443) |
| `expired.test` | deliberately expired (fixed past validity window); requires OpenSSL 3.4+ to generate |
| `default.test` / `generic.test` | fallback identities (not in DNS) |
| `hardened.test` | served only on the hardened IP; not published in DNS |
| `hidden.test` | served only on the header-leak IP; not published in DNS |
| `ip.test` | `ip.test`, `IP:127.0.42.12` |

### DNS

`dnsmasq` listens on `127.0.0.1:5353`. Forward records map each hostname to its
server IP (so the `DNS` column shows ✅ / ❌), wildcard subdomains
(`*.wild.test`) resolve via an `address=` zone, and `host-record` provides the
matching PTR records so the reverse-IP recon finds `alpha.test`, `strict.test`
and `multi.test`.

## Running scans manually

`run-snitch.sh` is a thin wrapper. The equivalent invocation is:

```bash
./SNItch \
    --target-list testenv/generated/snitch-targets.txt \
    --host-list   testenv/generated/snitch-hosts.txt \
    --dns 127.0.0.1:5353 \
    --no-crtlog \
    --search-headers \
    -e 3
```

Because the whole `/24` is a real subnet you can also scan it as a range; the
populated addresses answer and the rest are refused, demonstrating how SNItch
handles a mixed target set:

```bash
./SNItch -t 127.0.42.0/28:443 --dns 127.0.0.1:5353 --no-crtlog --search-headers
```

## Expected results

A successful run against nginx (identical for Caddy) produces, among others:

```bash
                                 127.0.42.10:443  (alpha.test)
                              HOSTNAME   DNS  CERT
                    (HTTP 127.0.42.10)               [301] ➤ https://alpha.test/
                         (EMPTY SNI)               [200]   Shared Service
                          alpha.test    ✅   ✅    [200]   Alpha Service
                      www.alpha.test    ✅   ✅    [200]   Alpha Service
                  legacy.alpha.test    ❌   ✅    [200]   Legacy Service
                          beta.test    ✅   ✅    [200]   Beta Service
                       default.test    ❌   ✅    [200]   Shared Service
                        portal.test    ✅   ✅    [301] ➤ https://hop.test/login
                           hop.test    ✅   ✅    [301] ➤ https://final.test/login
                         final.test    ✅   ✅    [200]   Final Service
                          wild.test    ✅   ✅    [200]   Wildcard Service
                       *.wild.test         ✅    [200]   Wildcard Service

                                 127.0.42.12:443  (multi.test)
                              HOSTNAME   DNS  CERT
                           (IP as SNI)         ✅
                        generic.test    ❌   ✅    [200]   Fallback Service
                          multi.test    ✅   ✅    [200]   Multi Service
                       service.test    ✅   ✅    [200]   Multi Service
                       expired.test    ✅   ✅    [200]   Expired Cert Service

                                 127.0.42.12:8443  (altport.test)
                              HOSTNAME   DNS  CERT
                        altport.test    ✅   ✅    [200]   Alt Port Service
```

Neither the hardened nor the header-leak names are supplied on the CLI or
published in DNS. The `127.0.42.13` block stays empty — nothing is discoverable
there — while on `127.0.42.14` the plaintext-HTTP probe finds `hidden.test` in
the leaked `Content-Security-Policy` header and feeds it back into recon, so the
vhost is discovered by SNItch itself.

Note the `strict` server has **no** `(EMPTY SNI)` row (absent SNI is rejected)
and no fallback certificate — that is the hardening signal SNItch reports.

`verify.sh` runs several scans against the standing environment:

- the **main scan** (`--search-headers -e 3`) with all supplied targets and
  hosts. The extra epochs are needed for the two-hop redirect chain
  (`portal.test` → `hop.test` → `final.test`): epoch 1 scans the supplied
  names, epoch 2 the redirect-discovered `hop.test`, epoch 3 `final.test`.
- an **IP-only scan of the hardened IP** that must reveal zero host rows;
- an **IP-only scan of the header-leak IP** with `--search-headers` that must
  discover `hidden.test` from the leaked header alone, and one without the
  flag that must reveal nothing;
- an **ignore-list scan** (`-i portal.test,beta.test`) whose results must
  contain no rows for the ignored names;
- a **require-list scan** (`-r "^nomatch"` with `--search-headers`): the
  header probe still runs (the `(HTTP 127.0.42.14)` row appears) but every
  recon-discovered hostname must be filtered, while supplied hosts survive;
- a **no-recon/no-ip-sni scan** (`--no-recon --no-ip-sni`) that must not
  discover `hop.test`, `final.test`, `legacy.alpha.test` or `hidden.test` and
  must not produce an `(IP as SNI)` row;
- a **stdout JSONL scan** (`--jsonl -`) whose stdout must be valid JSONL
  starting with a `config` record and ending with a `summary` record.

The main scan results are checked by ~200 assertions derived from
`sites.json`: every served hostname resolves to its IP with the expected
certificate and HTTP status (including the non-443 port target
`127.0.42.12:8443`), every certificate is observed, the deliberately expired
`expired.test` certificate must be reported with `expired: true` (and every
other with `expired: false`), the fallback certificates are detected, the
IP-as-SNI row is present, summary (iterations, cancelled) and per-IP records
are well-formed, the hidden servers' names are **not** supplied on the CLI,
and the cert-SAN-discovered `legacy.alpha.test` appears with an unresolved
DNS state and a valid certificate. It also runs `probe-http-tls.py`
(100 assertions), which opens a raw plaintext HTTP request against every
`127.0.42.x:443` and checks that the server answers with a `400` and leaks no
hostname from `sites.json`.

## Customising

Edit `sites.json` and re-run `./setup.sh`. Adding a server, hostname or
certificate is a matter of a few JSON entries; `scripts/render.py` regenerates
the nginx server blocks, the Caddyfiles, the dnsmasq records and the SNItch
input files, so both stacks stay in sync automatically.

```jsonc
// sites.json (excerpt)
"certificates": [
  { "name": "wild.test", "sans": ["wild.test", "*.wild.test"] }
],
"servers": [
  {
    "ip": "127.0.42.10",
    "role": "shared",
    "fallback_cert": "default.test",   // null = strict (reject unknown SNI)
    "http_redirect": "https://alpha.test",
    "sites": [
      { "server_names": ["alpha.test", "www.alpha.test"], "cert": "alpha.test",
        "status": 200, "title": "Alpha Service" },
      { "server_names": ["portal.test"], "cert": "portal.test",
        "status": 301, "redirect": "https://sso.test/login" }
    ]
  }
]
```

## Notes and limitations

- **Linux only.** `network_mode: host` and binding `127.0.42.0/24` rely on the
  Linux loopback setup. macOS/Windows Docker Desktop cannot bind these
  addresses.
- **`network_mode: host`** is used deliberately: it is what makes the
  individual `127.0.42.x` addresses reachable from the host where SNItch runs,
  and it keeps source/destination on the loopback path. Do not reuse this
  compose file for anything but the test bed.
- **WHOIS** runs against real WHOIS servers for the `127.0.42.x` addresses and
  therefore reports `(UNKNOWN)`; this is expected for RFC 5735 loopback space.
- **One Caddy instance per IP.** Caddy selects certificates from a
  process-global cache, so a single instance serves any loaded certificate on
  every listener — that would let the hardened IP present other hosts'
  certificates. The compose file therefore runs `caddy10`…`caddy14`, one per
  address. nginx isolates SNI per `listen` socket natively.
- **Hardened IP** (`127.0.42.13`): rejects unknown/absent SNI, closes plaintext
  HTTP with no response, and is absent from DNS/PTR, so an IP-only scan
  (`--target-list generated/snitch-targets-hardened.txt`) produces no findings.
- **Header-leak IP** (`127.0.42.14`): TLS-hardened like `.13` and absent from
  DNS/PTR, but its plaintext HTTP service leaks its vhost in a
  `Content-Security-Policy` header. A default IP-only scan
  (`--target-list generated/snitch-targets-header-leak.txt`) produces no
  findings; adding `--search-headers` discovers `hidden.test` from that header.
- **`crt.name` is disabled** (`--no-crtlog`) so the run is hermetic. Remove the
  flag to also exercise the online CT-log lookup (requires internet).
- The certificates are intentionally not validated by SNItch beyond
  name matching; self-signed is fine.
