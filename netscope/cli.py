"""NetScope argument parsing and Rich presentation."""

from __future__ import annotations

import argparse
import asyncio
import errno
import io
import json
from datetime import datetime, timezone
from pathlib import Path
import os
import signal
import sys
import threading
from typing import Any

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from .scanner import scan_target
from .utils import CHECKS, VERSION, parse_checks, parse_ports, parse_target, positive_timeout, terminal_text, write_json

BANNER = r""" _   _      _   ____
| \ | | ___| |_/ ___|  ___ ___  _ __   ___
|  \| |/ _ \ __\___ \ / __/ _ \| '_ \ / _ \
| |\  |  __/ |_ ___) | (_| (_) | |_) |  __/
|_| \_|\___|\__|____/ \___\___/| .__/ \___|
                               |_|"""


def validated_target(value: str) -> str:
    try:
        # Keep the explicit URL so the scanner can use its scheme, port, and path.
        selected = parse_target(value)
        return selected.url or selected.host
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def timeout_argument(value: str) -> float:
    try:
        return positive_timeout(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def ports_argument(value: str) -> tuple[int, ...]:
    try:
        return parse_ports(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def checks_argument(value: str) -> tuple[str, ...]:
    try:
        return parse_checks(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError(str(exc)) from exc


def concurrency_argument(value: str) -> int:
    try:
        result = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("concurrency must be an integer") from exc
    if not 1 <= result <= 256:
        raise argparse.ArgumentTypeError("concurrency must be between 1 and 256")
    return result


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="netscope",
        description="NetScope — concurrent DNS, TCP, and HTTP reconnaissance.",
        epilog="Examples: netscope example.com | netscope http://localhost:8080 -p 8080 --json",
    )
    parser.add_argument("-t", "--target", type=validated_target, help="hostname, IPv4/IPv6 address, or HTTP(S) URL")
    parser.add_argument("host", nargs="?", type=validated_target, help="target (alternative to -t)")
    parser.add_argument(
        "-p", "--ports", type=ports_argument, help="TCP ports or ranges, e.g. 22,80,8000-8005 (max 1024)"
    )
    parser.add_argument(
        "--only",
        type=checks_argument,
        default=CHECKS,
        metavar="CHECKS",
        help="run selected checks: dns, ports, http or a comma-separated combination (default: all)",
    )
    parser.add_argument(
        "--open", dest="open_only", action="store_true", help="display only open TCP ports; JSON keeps all results"
    )
    parser.add_argument(
        "--timeout",
        type=timeout_argument,
        default=5.0,
        metavar="SECONDS",
        help="per-operation timeout, 0.1–120 (default: 5)",
    )
    parser.add_argument(
        "--concurrency",
        type=concurrency_argument,
        default=32,
        metavar="N",
        help="maximum concurrent TCP probes, 1–256 (default: 32)",
    )
    parser.add_argument("-o", "--output", choices=("json",), help="export results as JSON")
    parser.add_argument(
        "--output-file", type=Path, help="export destination; requires -o json (existing file is replaced)"
    )
    parser.add_argument("--no-color", action="store_true", help="disable terminal colors")
    parser.add_argument("--json", action="store_true", help="write only JSON to stdout for scripts")
    parser.add_argument("-v", "--verbose", action="store_true", help="also display all captured HTTP headers")
    parser.add_argument(
        "--show-sensitive-headers",
        action="store_true",
        help="include cookie/authentication header values in output and reports",
    )
    parser.add_argument("--version", action="version", version=f"NetScope {VERSION}")
    return parser


def safe(value: object) -> Text:
    return Text(terminal_text(value))


def status_text(value: str) -> Text:
    color = {
        "ok": "green",
        "open": "green",
        "present": "green",
        "completed": "green",
        "closed": "dim",
        "skipped": "dim",
        "not_applicable": "dim",
        "no_answer": "dim",
        "partial": "yellow",
        "missing": "yellow",
        "timeout": "yellow",
    }.get(value, "red")
    return Text(value.replace("_", " "), style=color)


def render_dns(console: Console, dns_result: dict[str, Any]) -> None:
    if dns_result["status"] == "skipped":
        console.print(Panel(safe(dns_result["reason"]), title="DNS enumeration", border_style="dim"))
    else:
        table = Table(title="DNS enumeration", header_style="bold cyan", expand=True)
        for column in ("Type", "State", "Records / details"):
            table.add_column(column, overflow="fold")
        for kind, result in dns_result["records"].items():
            table.add_row(
                kind,
                status_text(result["status"]),
                Text("\n".join(terminal_text(value) for value in result["values"]))
                if result["values"]
                else safe(result.get("error", "No records")),
            )
        console.print(table)
        if dns_result.get("error"):
            console.print(safe(dns_result["error"]), style="red")


def render_ports(console: Console, ports: dict[str, Any], open_only: bool) -> None:
    table = Table(title="TCP port probe", header_style="bold cyan", expand=True)
    for column in ("Address", "Port", "Service hint", "State", "ms / details"):
        table.add_column(column, overflow="fold")
    for result in ports["results"]:
        if open_only and result["status"] != "open":
            continue
        table.add_row(
            safe(result["address"]),
            str(result["port"]),
            result["service"],
            status_text(result["status"]),
            safe(f"{result['elapsed_ms']:.2f}" + (f" · {result['error']}" if "error" in result else "")),
        )
    if table.row_count:
        console.print(table)
    else:
        console.print("No open TCP ports observed." if open_only else "No TCP probe results.", style="dim")
    if open_only:
        hidden = sum(result["status"] != "open" for result in ports["results"])
        console.print(f"Open ports only: {hidden} other probe results hidden. JSON retains all results.", style="dim")
        if any(result["status"] in {"timeout", "error"} for result in ports["results"]):
            console.print("Some probes timed out or failed; those ports may still be open.", style="yellow")
    if ports["resolution"].get("error"):
        console.print(safe(ports["resolution"]["error"]), style="red")
    if ports["resolution"].get("truncated"):
        console.print("Address limit reached: probing only the first 16 resolved addresses.", style="yellow")


def render_http(console: Console, http: dict[str, Any], verbose: bool) -> None:
    for result in http["results"]:
        console.print(Panel(safe(result["url"]), title="HTTP analysis", border_style="cyan"))
        if result["status"] != "ok":
            console.print(Text.assemble(status_text(result["status"]), ": ", safe(result["error"])))
            continue
        console.print(safe(f"HTTP {result['status_code']} {result['reason'] or ''} · {result['elapsed_ms']:.2f} ms"))
        if result["redirect_location"]:
            console.print(Text.assemble("Redirect (not followed): ", safe(result["redirect_location"])))
        if verbose:
            headers = Table(title="Response headers", header_style="bold cyan", expand=True)
            headers.add_column("Header", overflow="fold")
            headers.add_column("Value", overflow="fold")
            for header in result["headers"]:
                headers.add_row(safe(header["name"]), safe(header["value"]))
            console.print(headers)
        security = Table(title="Security header presence", header_style="bold cyan", expand=True)
        security.add_column("Header")
        security.add_column("State")
        for item in result["security_headers"]:
            security.add_row(item["header"], status_text(item["status"]))
        console.print(security)
        hints = "; ".join(f"{item['source']}: {item['value']}" for item in result["technologies"])
        console.print(Text.assemble("Technology hints: ", safe(hints or "none declared")))


def render_report(console: Console, report: dict[str, Any], verbose: bool = False, open_only: bool = False) -> None:
    checks = report.get("settings", {}).get("checks", CHECKS)
    labels = {"dns": "DNS", "ports": "TCP", "http": "HTTP"}
    console.print(
        Panel(
            Text.assemble(
                "Target: ",
                safe(report["target"]),
                "    Status: ",
                status_text(report["status"]),
                f"    Duration: {report['duration_seconds']:.3f}s",
                "\nChecks: " + " / ".join(labels[kind] for kind in checks),
            ),
            title="Scan results",
            border_style="cyan",
        )
    )
    summary = report.get("summary", {})
    if summary:
        parts = []
        if "ports" in checks:
            counts = summary["ports"]
            parts.append(
                f"Ports: {counts['open']} open · {counts['closed']} closed · "
                f"{counts['timeout']} timed out · {counts['error']} errors"
            )
        if "dns" in checks and report["dns"]["status"] != "skipped":
            parts.append(f"DNS records: {summary['dns_records']}")
        if "http" in checks:
            parts.append(
                f"HTTP responses: {summary['http_responses']}    Missing headers: {summary['missing_security_headers']}"
            )
        if parts:
            console.print("    ".join(parts), style="bold")
    if "dns" in checks:
        render_dns(console, report["dns"])
    if "ports" in checks:
        render_ports(console, report["ports"], open_only)
    if "http" in checks:
        render_http(console, report["http"], verbose)
    if any(kind in checks for kind in ("ports", "http")):
        console.print(
            "Service names are port hints; header presence and technology hints are not security verdicts.", style="dim"
        )


def default_output(target: str) -> Path:
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S%fZ")
    label = parse_target(target).host.replace(":", "_")[:80]
    return Path(f"netscope-{label}-{stamp}.json")


def silence_stdout() -> None:
    """Prevent Python's final stdout flush from repeating a closed-pipe error."""
    try:
        with open(os.devnull, "w", encoding="utf-8") as null:
            os.dup2(null.fileno(), sys.stdout.fileno())
    except (OSError, ValueError, io.UnsupportedOperation):
        sys.stdout = io.StringIO()


def emit_report(
    console: Console, report: dict[str, Any], json_output: bool, verbose: bool, open_only: bool = False
) -> bool:
    try:
        if json_output:
            sys.stdout.write(json.dumps(report, ensure_ascii=True, indent=2, allow_nan=False) + "\n")
        else:
            console.print(
                Panel(
                    Text(BANNER, style="bold cyan"),
                    subtitle=f"v{VERSION} · cmtrl · DNS / TCP / HTTP",
                    border_style="cyan",
                )
            )
            render_report(console, report, verbose, open_only)
        sys.stdout.flush()
    except OSError as exc:
        # Windows reports a closed output pipe as EINVAL rather than EPIPE.
        # Limit this handling to terminal writes: EINVAL from export is an error.
        if isinstance(exc, BrokenPipeError) or (os.name == "nt" and exc.errno == errno.EINVAL):
            silence_stdout()
            return False
        raise
    return True


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if bool(args.target) == bool(args.host):
        parser.error("provide one target: netscope HOST or netscope -t HOST")
    target = args.target or args.host
    if args.output_file is not None and args.output is None:
        parser.error("--output-file requires -o json")
    if "ports" not in args.only:
        if args.ports is not None:
            parser.error("--ports requires ports in --only")
        if args.open_only:
            parser.error("--open requires ports in --only")
    console = Console(no_color=args.no_color)
    error_console = Console(stderr=True, no_color=args.no_color)
    try:

        async def run() -> dict[str, Any]:
            loop = asyncio.get_running_loop()
            task = asyncio.current_task()
            previous_handler = signal.getsignal(signal.SIGINT)
            deferred_interrupt = os.name == "posix" and threading.current_thread() is threading.main_thread()
            if deferred_interrupt:
                # Defer cancellation to the event loop. A synchronous SIGINT can
                # cancel a future midway through a Python 3.11 socket callback.
                loop.add_signal_handler(signal.SIGINT, task.cancel)
            try:
                with error_console.status(Text.assemble("Scanning ", safe(target), "…"), spinner="dots"):
                    return await scan_target(
                        target,
                        args.timeout,
                        args.concurrency,
                        args.ports,
                        args.show_sensitive_headers,
                        checks=args.only,
                    )
            finally:
                if deferred_interrupt:
                    loop.remove_signal_handler(signal.SIGINT)
                    signal.signal(signal.SIGINT, previous_handler)

        report = asyncio.run(run())
        destination = None
        if args.output == "json":
            destination = write_json(report, args.output_file or default_output(target))
        exit_code = 1 if report["status"] == "failed" else 0
        if not emit_report(console, report, args.json, args.verbose, args.open_only):
            return exit_code
        if destination:
            (error_console if args.json else console).print(
                Text.assemble("JSON saved: ", safe(destination)), style="green"
            )
        return exit_code
    except (KeyboardInterrupt, asyncio.CancelledError):
        error_console.print("Scan cancelled.", style="yellow")
        return 130
    except BrokenPipeError:
        silence_stdout()
        return 0
    except (OSError, ValueError) as exc:
        error_console.print(Text.assemble("Error: ", safe(exc)), style="red")
        return 1
