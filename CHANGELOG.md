# Changelog

## 1.1.0

- Accept HTTP(S) URLs and a positional target, preserving `-t` compatibility.
- Add custom TCP ports and ranges with bounded concurrency and selection limits.
- Add `--json` for clean machine-readable stdout and `--verbose` for full headers.
- Show summary counts and keep the normal terminal view shorter.
- Share bounded async DNS queries between enumeration and direct connections.
- Respect hosts-file entries and resolve localhost locally.
- Redact cookie/authentication response headers by default.
- Handle non-UTF-8 headers, long export filenames, and closed output pipes.
- Add a loopback-only `netscope-demo` server for a repeatable first scan.
- Require Python 3.11+ for the patched dnspython dependency.
- Raise aiohttp and dnspython minimums to releases without known advisories at review time.
- Add live local DNS/TLS tests, subprocess tests, and multi-OS/Python CI.
- Update contribution and publishing documentation.

## 1.0.0

Initial release: concurrent DNS enumeration, common TCP probes, HTTP header
checks, a Rich terminal interface, JSON file export, and MIT licensing.
