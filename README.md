# NetScope

A small Python CLI for DNS records, TCP ports, and HTTP headers. Useful for
checking a host or taking a quick look at a local web app.

By **cmtrl cmtrl** · [@cmtrl](https://github.com/cmtrl)

```text
 _   _      _   ____
| \ | | ___| |_/ ___|  ___ ___  _ __   ___
|  \| |/ _ \ __\___ \ / __/ _ \| '_ \ / _ \
| |\  |  __/ |_ ___) | (_| (_) | |_) |  __/
|_| \_|\___|\__|____/ \___\___/| .__/ \___|
                               |_|
```

I'm using this project to learn more about Python networking, async code, and
CLI design. Feedback and bug reports are welcome.

## Install

Python **3.10+**. No administrator privileges needed.

If you use pipx:

```bash
pipx install cmtrl-netscope
```

Or use a virtual environment:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install cmtrl-netscope
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1` instead.
To upgrade an existing installation: `pipx upgrade cmtrl-netscope` or
`python -m pip install --upgrade cmtrl-netscope` in its virtual environment.

## Try it

```bash
# DNS, common TCP ports, and HTTP(S) headers
netscope example.com

# A specific web app: preserve the URL's scheme, port, and path
netscope http://127.0.0.1:8080/health -p 8080

# Custom ports and inclusive ranges, up to 1024 ports
netscope example.com -p 22,80,443,8000-8005

# Save a report
netscope example.com -o json --output-file report.json

# JSON on stdout, suitable for scripts and pipes
netscope example.com --json > report.json

# All captured HTTP headers in the terminal
netscope example.com --verbose
```

The original `netscope -t example.com` syntax still works.
`--timeout 3` changes the per-operation timeout; `--concurrency 12` limits
simultaneous TCP checks. Run `netscope --help` for all options.

## A local demo in two terminals

Start the included HTTP fixture:

```bash
netscope-demo
```

Then open another terminal with NetScope available and run:

```bash
netscope http://127.0.0.1:8080 -p 8080 -o json --output-file demo.json
```

This runs a real scan against your own machine. Expect one open TCP port,
HTTP 200, CSP present, and X-Frame-Options missing. The fixture deliberately
omits that header so you can see the check. HSTS is not applicable to plain
HTTP, and forward DNS is skipped for an IP target. Stop the server with Ctrl+C.
If port 8080 is busy, use `netscope-demo --port 8081` and change the scan URL and
port to match.

There is a [recording walkthrough](https://github.com/cmtrl/netscope/blob/main/docs/DEMO.md)
with exact commands, captions, and an optional voiceover.

## What the checks mean

- DNS queries A, AAAA, MX, TXT, and NS concurrently. Local hosts-file entries
  and localhost work for connections; DNS enumeration shows actual DNS records.
- TCP results distinguish open, refused, timed-out, and failed connections.
  Service names are conventional port hints, not confirmed application names.
- Bare hosts get HTTP/80 and HTTPS/443 checks. A URL checks only that endpoint;
  an explicit URL port is also included in the default TCP selection.
- HTTPS verification stays enabled. Redirects are reported without being followed.
- HSTS, CSP, and X-Frame-Options checks report header presence. They do not
  validate a policy or prove that a site is secure or vulnerable.
- Cookie and authentication response headers are redacted in both terminal
  output and JSON. Use `--show-sensitive-headers` only when you need those values.

Use NetScope on systems you own or have permission to check. It is a focused
reconnaissance tool, not a vulnerability scanner.

See the [reference](https://github.com/cmtrl/netscope/blob/main/docs/REFERENCE.md)
for JSON fields, proxy behavior, timeouts, and exit codes.

## Working on the code

```bash
git clone https://github.com/cmtrl/netscope.git
cd netscope
python -m venv .venv
source .venv/bin/activate
python -m pip install -e .
python -W error -m unittest discover -s tests -v
```

The code is split into `cli.py`, `scanner.py`, `resolver.py`, `utils.py`, and the
local demo fixture in `demo.py`. Tests use local HTTP/TLS and DNS servers; they
do not scan public hosts. [CI](https://github.com/cmtrl/netscope/actions/workflows/ci.yml)
checks Linux, macOS, Windows, and Python 3.10, 3.12, and 3.14.

Optional development checks:

```bash
python -m pip install ruff build twine
ruff check .
ruff format --check .
python -m build
python -m twine check --strict dist/*
```

See [CONTRIBUTING.md](https://github.com/cmtrl/netscope/blob/main/CONTRIBUTING.md)
and the [changelog](https://github.com/cmtrl/netscope/blob/main/CHANGELOG.md).

## License

[MIT](https://github.com/cmtrl/netscope/blob/main/LICENSE) · Copyright (c) 2026 cmtrl cmtrl (cmtrl).
