# Changelog

## 1.2.0

- Add `--only dns`, `--only ports`, `--only http`, and combined selections.
- Add `--open` to show only open TCP ports while retaining complete JSON reports.
- Show the selected checks and keep unselected checks out of terminal tables.
- Record selected checks and explicit skipped sections in JSON schema 1.2.
- Treat answered DNS queries without records as useful results in DNS-only scans.
- Preserve a failed scan's exit code when its output pipe closes.
- Recognize Windows connection-refused errors as closed TCP ports.
- Defer Ctrl+C cancellation to avoid interrupting a Python 3.11 socket callback.
- Use cmtrl consistently in project credits, licensing, and package metadata.

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
