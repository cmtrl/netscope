"""A loopback-only HTTP fixture for trying NetScope without a public target."""

from __future__ import annotations

import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from socketserver import TCPServer
import sys


class DemoServer(ThreadingHTTPServer):
    def server_bind(self) -> None:
        # HTTPServer performs a reverse-DNS lookup even for loopback. This
        # fixture already knows its name and should start without a DNS server.
        TCPServer.server_bind(self)
        self.server_name = "localhost"
        self.server_port = self.server_address[1]


class DemoHandler(BaseHTTPRequestHandler):
    def version_string(self) -> str:
        return "NetScope-Demo"

    def do_GET(self) -> None:
        if self.path not in {"/", "/health"}:
            self.send_error(404)
            return
        body = json.dumps({"service": "NetScope local demo", "status": "ok"}).encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Content-Security-Policy", "default-src 'none'")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Cache-Control", "no-store")
        # X-Frame-Options is intentionally omitted to illustrate a presence check.
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, format: str, *args) -> None:
        pass


def listen_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("port must be an integer") from exc
    if not 0 <= port <= 65535:
        raise argparse.ArgumentTypeError("port must be between 0 and 65535 (0 chooses a free port)")
    return port


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="netscope-demo", description="Start a local HTTP fixture for a NetScope demo."
    )
    parser.add_argument(
        "--port", type=listen_port, default=8080, help="local port (default: 8080; 0 chooses a free port)"
    )
    args = parser.parse_args(argv)
    try:
        with DemoServer(("127.0.0.1", args.port), DemoHandler) as server:
            port = server.server_port
            print(f"Local demo server: http://127.0.0.1:{port}/", flush=True)
            print(
                f"In another terminal: netscope http://127.0.0.1:{port} -p {port} -o json --output-file demo.json",
                flush=True,
            )
            print("Bound to loopback only. Press Ctrl+C to stop.", flush=True)
            server.serve_forever(poll_interval=0.1)
    except KeyboardInterrupt:
        return 0
    except OSError as exc:
        print(f"Could not start local demo server: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
