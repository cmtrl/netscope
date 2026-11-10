# NetScope

A Python CLI for checking DNS records, common TCP ports, and HTTP headers.

By **cmtrl cmtrl** · [@cmtrl](https://github.com/cmtrl)

```text
 _   _      _   ____
| \ | | ___| |_/ ___|  ___ ___  _ __   ___
|  \| |/ _ \ __\___ \ / __/ _ \| '_ \ / _ \
| |\  |  __/ |_ ___) | (_| (_) | |_) |  __/
|_| \_|\___|\__|____/ \___\___/| .__/ \___|
                               |_|
```

I'm using this project to work on Python networking, async code, and CLI design.
It's a starting point I plan to keep improving as I learn more about how these
checks work.

## What it does

- Looks up A, AAAA, MX, TXT, and NS records concurrently.
- Checks TCP ports `21`, `22`, `80`, `443`, `8080`, and `8443`.
- Fetches HTTP and HTTPS response headers.
- Checks for HSTS, CSP, and X-Frame-Options.
- Shows technology hints from headers such as `Server` and `X-Powered-By`.
- Displays results in the terminal and optionally saves them as JSON.

The checks run with `asyncio`, `aiohttp`, and `dnspython`. The terminal output
uses `rich`.

## Setup

Requires Python **3.10 or newer**. No root privileges needed.

Download the source, open its folder, then run:

```bash
python -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

On Windows PowerShell, activate with `.venv\Scripts\Activate.ps1` instead.
Use `python3` in place of `python` if that's how Python is installed on your system.

## Usage

```bash
python main.py -t example.com
```

Save a JSON report:

```bash
python main.py -t example.com -o json --output-file report.json
```

Set a shorter timeout or change the number of concurrent TCP checks:

```bash
python main.py -t example.com --timeout 3 --concurrency 12
```

IP addresses work too. Forward DNS enumeration is skipped for IP targets:

```bash
python main.py -t 127.0.0.1
python main.py -t ::1
```

Use a bare hostname or IP address, without `https://`, a path, or a port number.

```bash
python main.py --help
```

You can also install the command in your virtual environment:

```bash
python -m pip install .
netscope -t example.com
# Or: python -m netscope -t example.com
```

## A few things to know

Use this on systems you own or have permission to check.

An open port means a TCP connection succeeded. It doesn't confirm which service
is running. A missing security header isn't automatically a vulnerability, and
technology headers can be wrong.

HTTP checks use ports 80 and 443. Ports 8080 and 8443 get TCP checks only.
Redirects are shown without being followed, and HTTPS certificate verification
stays enabled. A failed check doesn't discard results from the other checks.

More detail on result states, timeouts, proxies, JSON fields, and exit codes is
in [docs/REFERENCE.md](docs/REFERENCE.md).

## Working on the code

```text
main.py              entry point
netscope/cli.py      arguments and terminal output
netscope/scanner.py  DNS, TCP, and HTTP checks
netscope/utils.py    input validation and JSON export
tests/              tests using local servers and simulated failures
```

Run the tests:

```bash
python -m unittest discover -s tests -v
```

Optional development tools:

```bash
python -m pip install ruff build
ruff check .
python -m build
```

Some things I'd like to work on next:

- Letting the user choose which ports to check.
- Making the output easier to skim when a host has several IP addresses.
- Adding more tests as I change the scanner.

If you find a bug or have a suggestion, an issue or pull request is welcome.

## License

[MIT](LICENSE) · Copyright (c) 2026 cmtrl cmtrl (cmtrl).
