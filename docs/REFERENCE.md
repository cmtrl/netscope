# Reference

## Targets and ports

Both `netscope HOST` and `netscope -t HOST` work. Supply exactly one target.
Bare domains, IDNA names, IPv4, IPv6 (optionally bracketed), and HTTP(S) URLs
are accepted. URL paths and explicit ports are preserved. Credentials, query
strings, fragments, scoped IPv6 addresses, CIDR ranges, and wildcard targets are
rejected. Bare `host:port` is ambiguous; use `http://host:port` instead.

Without `-p`, TCP checks use 21, 22, 80, 443, 8080, and 8443. An explicit URL port
is added to that default selection. With `-p`, only the selected ports are probed.
The HTTP request is independent: `-p 22` does not suppress a URL's HTTP check.
Port ranges are inclusive, duplicates are removed, and at most 1024 ports and
16 resolved addresses are selected. Address truncation is shown and recorded.

## DNS and connection resolution

A, AAAA, MX, TXT, and NS queries run concurrently using dnspython. Results have
`ok`, `no_answer`, `nxdomain`, `timeout`, or `error` states. An absent record type
is normal. Successful records include `ttl_seconds` where available.

DNS questions are shared between enumeration, direct TCP probes, and direct
HTTP connections. Hostname resolution uses async DNS, not an uncancellable OS
getaddrinfo thread. Connections also honor the local hosts file. `localhost`
and its subdomains resolve locally; forward DNS enumeration is skipped for
localhost and IP targets. Reverse DNS is not included.

This is DNS plus hosts-file resolution: OS-specific mDNS, LLMNR, and NSS plugins
are not used. HTTP proxies can use a different resolver or network path.

## HTTP behavior

A bare host gets independent GET requests for `https://HOST/` and `http://HOST/`.
A URL gets one request for that exact normalized scheme, host, port, and path.
Only response headers are analyzed; page bodies are not consumed. Any HTTP
status, including 4xx or 5xx, can produce useful results. Redirects are recorded
without being followed. Certificate and hostname verification remain enabled;
there is no insecure fallback.

HSTS applies only to HTTPS. A nonempty security header is `present`, an absent
or whitespace-only value is `missing`, and HSTS on HTTP is `not_applicable`.
These are presence checks, not policy validation: `max-age=0` still counts as
present. CSP `frame-ancestors` can offer framing protection without
X-Frame-Options. Technology hints come from Server, X-Powered-By, X-Generator,
and Via. These values are self-reported.

The default terminal view shows results, security checks, and technology hints.
`-v` / `--verbose` also shows captured response headers. Set-Cookie,
Authorization, Proxy-Authorization, Authentication-Info, and
Proxy-Authentication-Info values are `[redacted]` in every output unless
`--show-sensitive-headers` is set. Other response headers can still contain
site-specific details. Non-UTF-8 header bytes are replaced for UTF-8-safe JSON.

HTTP honors `HTTP_PROXY`, `HTTPS_PROXY`, and `NO_PROXY`, plus aiohttp's normal
environment authentication behavior. TCP probes and DNS queries use direct
connections. They can see a different path from a proxied HTTP request.

## Timeouts and cancellation

`--timeout` is a per-operation limit from 0.1 to 120 seconds, default 5. It covers
each DNS question, TCP connection, or HTTP request, not the whole scan. TCP work
runs in batches up to `--concurrency` (1–256, default 32); the five DNS questions
and up to two HTTP requests are separate. A timeout doesn't prove that a port is
filtered or that a host is down.

A refused TCP connection is `closed`; a successful connection is `open`. Other
socket failures are `error`. Ctrl+C cancels pending tasks and closes owned
sockets, sessions, and DNS queries. An interrupted scan does not produce a report.

## JSON and automation

`--json` writes only the JSON report to stdout. Diagnostics go to stderr, and no
banner, table, terminal wrapping, or ANSI styling is mixed into stdout. The exit
status still matters: a partial report can be useful.

`-o json` writes a file, with `--output-file PATH` choosing its destination.
These switches can be combined with `--json`. Existing files are replaced
atomically; the parent directory must exist. Reports are saved before terminal
rendering, including when a pipe consumer closes early. On POSIX the file mode
is 0600. Default filenames contain a shortened target and UTC timestamp.

Schema 1.1 keeps the sections from schema 1.0 and adds summary counts, selected
HTTP URLs, header-redaction settings, and DNS TTLs. HTTP headers remain an array
of `{ "name": "...", "value": "..." }` objects to preserve duplicates.

| Field | Contents |
| --- | --- |
| `schema_version`, `tool` | Report schema, application name, and version |
| `target`, `target_type` | Normalized hostname/IP and its kind |
| `started_at`, `finished_at`, `duration_seconds` | UTC times and monotonic elapsed duration |
| `status` | `completed`, `partial`, or `failed` |
| `settings` | Timeout, concurrency, selected ports, HTTP URLs, header visibility |
| `summary` | Port states, DNS record count, HTTP response count, missing-header observations |
| `dns` | Section status, per-type records and errors, or skip reason |
| `ports` | Address-resolution details and per-address/port results |
| `http` | Per-endpoint status, headers, presence checks, hints, and errors |

Missing-header counts are observations per endpoint, not a count of proven
vulnerabilities. Failed HTTP requests do not invent missing-header findings.

| Exit code | Meaning |
| --- | --- |
| `0` | Useful results, including partial scans |
| `1` | No usable results, or a local/export error |
| `2` | Invalid arguments |
| `130` | Interrupted with Ctrl+C |

Successful address resolution, any DNS record, or an HTTP response counts as
useful data. Read the report's section states for precise automation. Security
header flags do not change the exit code.
