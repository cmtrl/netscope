# Reference

## Reading the results

DNS records distinguish `ok`, `no_answer`, `nxdomain`, `timeout`, and `error`.
An absent record type is normal and does not by itself indicate a failed scan.
IP targets skip forward DNS enumeration; reverse DNS is outside this tool's scope.

TCP results are per **resolved IP address and port**. `open` means a connection
succeeded, `closed` means it was refused, and `timeout` means it did not complete
within the limit. Other failures, such as an unavailable IPv6 route, are `error`.
Service labels describe conventional port assignments; they do not identify the
actual application. Up to 16 distinct addresses are probed; truncation is recorded
and displayed. TCP concurrency limits do not include the five DNS queries and
two HTTP requests, which are independently bounded.

HTTP uses GET and stops after response headers; it does not parse page content.
All HTTP status codes, including 4xx and 5xx, can yield useful header results.
Redirects are recorded without being followed. HTTPS certificates and hostnames
are verified; TLS failures are reported without an insecure retry. HTTP and HTTPS
are independent observations, so each endpoint gets its own analysis. Ports 8080
and 8443 receive TCP probes only.

A nonempty header is marked `present`; an absent or empty header is `missing`.
HSTS is `not_applicable` on plain HTTP, even if the server sends it there. These
are presence checks, not policy validation: for example, `max-age=0` still counts
as present. CSP `frame-ancestors` may provide framing protection without
X-Frame-Options. Technology headers are self-reported and can be inaccurate.
These observations alone are not vulnerability findings.

HTTP honors standard proxy environment variables (`HTTP_PROXY`, `HTTPS_PROXY`,
`NO_PROXY`) and aiohttp's normal environment authentication behavior. TCP probes
use direct sockets and DNS queries use the system-configured DNS resolvers.
HTTP and TCP can therefore observe different paths or resolved addresses,
especially behind proxies or load balancers. No recursive enumeration, credential
testing, or exploit checks are performed.

## JSON reports and automation

`-o json` writes a file; terminal output remains human-readable. By default the
filename is `netscope-<target>-<UTC timestamp>.json` (IPv6 colons become underscores).
`--output-file` replaces an existing file atomically; its parent directory must
already exist. Files are UTF-8, indented, and use UTC timestamps with timezone
offsets. On POSIX, new report files are private to the current user (`0600`).

The schema version is independent of the application version. Top-level fields:

| Field | Contents |
| --- | --- |
| `schema_version`, `tool` | Schema version plus application name and version |
| `target`, `target_type` | Normalized hostname/IP and its kind |
| `started_at`, `finished_at`, `duration_seconds` | UTC timestamps and monotonic elapsed duration |
| `status` | `completed`, `partial`, or `failed` |
| `settings` | Timeout, TCP concurrency, and port list |
| `dns` | Section status and per-type records (or skip reason) |
| `ports` | Address resolution details and per-address/port results |
| `http` | Per-endpoint headers, security checks, technology hints, and errors |

HTTP `headers` is an array of `{ "name": "...", "value": "..." }` objects so
duplicate response headers are preserved. Failed requests retain their URL,
state, elapsed time, and error; they do not invent missing-header findings.
Expected network failures stay in their respective sections.

| Exit code | Meaning |
| --- | --- |
| `0` | Useful results available, including a partial scan |
| `1` | All checks failed to produce useful results, or a local/export error occurred |
| `2` | Invalid arguments |
| `130` | Interrupted with Ctrl+C |

Successful address resolution, any returned DNS record, or an HTTP response
counts as useful data. Use the report's `status` and individual check states for
more precise automation. Security header flags do not change the process exit code.

## Architecture

```text
netscope/
├── main.py               # Source-checkout entry point
├── netscope/
│   ├── __init__.py       # Public version
│   ├── __main__.py       # python -m netscope
│   ├── cli.py           # argparse, orchestration, Rich presentation
│   ├── scanner.py       # asyncio DNS/TCP/HTTP checks and report assembly
│   └── utils.py         # Validation, safe rendering, atomic JSON export
├── requirements.txt      # Runtime dependencies
├── pyproject.toml        # Packaging and installed CLI entry point
├── tests/                # Standard-library unittest suite and local HTTP fixtures
├── README.md
└── LICENSE
```

Scanner functions return plain JSON-compatible dictionaries and can be reused:

```python
import asyncio
from netscope.scanner import scan_target

report = asyncio.run(scan_target("example.com", timeout=3, concurrency=12))
print(report["status"])
```

The timeout bounds each DNS query, TCP connection, address-resolution await, or
HTTP request, rather than the entire scan. Queued TCP work runs in batches. OS
hostname lookup can continue in an executor thread after an await times out;
resolver configuration can therefore affect shutdown latency. Network failures
produce partial reports, while cancellation propagates and closes network resources.
Ctrl+C does not write a report for an interrupted scan.

