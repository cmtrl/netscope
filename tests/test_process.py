"""Run the real CLI as a subprocess; never depend on a public scan target."""

import json
import os
from pathlib import Path
import signal
import socket
import subprocess
import sys
import tempfile
import unittest

from netscope import __version__


class CommandProcessTests(unittest.TestCase):
    def setUp(self):
        self.environment = dict(os.environ)
        self.environment["PYTHONIOENCODING"] = "utf-8"
        self.environment["NO_PROXY"] = self.environment.get("NO_PROXY", "") + ",127.0.0.1"
        self.environment["no_proxy"] = self.environment["NO_PROXY"]
        self.server = subprocess.Popen(
            [sys.executable, "-m", "netscope.demo", "--port", "0"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=self.environment,
            text=True,
            encoding="utf-8",
        )
        line = self.server.stdout.readline().strip()
        self.assertTrue(line.startswith("Local demo server: "), line)
        self.url = line.removeprefix("Local demo server: ")
        self.port = int(self.url.split(":")[-1].rstrip("/"))

    def tearDown(self):
        self.server.terminate()
        self.server.communicate(timeout=10)

    def command(self, arguments):
        return subprocess.run(
            [sys.executable, "-m", "netscope", *arguments],
            env=self.environment,
            capture_output=True,
            text=True,
            encoding="utf-8",
            timeout=20,
        )

    def test_real_module_export_and_json_stdout(self):
        with tempfile.TemporaryDirectory() as directory:
            report_path = Path(directory) / "report.json"
            result = self.command(
                [self.url, "-p", str(self.port), "--json", "-o", "json", "--output-file", str(report_path)]
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(result.stdout)
            self.assertEqual(report, json.loads(report_path.read_text(encoding="utf-8")))
            self.assertEqual(report["status"], "completed")
            self.assertEqual(report["summary"]["ports"]["open"], 1)
            self.assertEqual(report["summary"]["missing_security_headers"], 1)
            self.assertEqual(report["http"]["results"][0]["status_code"], 200)
            self.assertNotIn("NetScope 1", result.stdout)

    def test_real_terminal_output_verbose_headers_and_legacy_entry_point(self):
        for arguments in (
            ["-t", self.url, "-p", str(self.port), "--no-color"],
            [self.url, "-p", str(self.port), "-v", "--no-color"],
        ):
            result = self.command(arguments)
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertIn("1 open", result.stdout)
            self.assertIn("NetScope-Demo", result.stdout)
            self.assertEqual("Response headers" in result.stdout, "-v" in arguments)
            self.assertNotIn("\x1b", result.stdout)
        result = subprocess.run([sys.executable, "main.py", "--version"], capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0)
        self.assertEqual(result.stdout.strip(), f"NetScope {__version__}")

    def test_http_only_exports_skipped_sections(self):
        result = self.command([self.url, "--only", "http", "--json"])
        self.assertEqual(result.returncode, 0, result.stderr)
        report = json.loads(result.stdout)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["settings"]["checks"], ["http"])
        self.assertEqual(report["settings"]["ports"], [])
        self.assertEqual(report["dns"]["status"], "skipped")
        self.assertEqual(report["ports"]["status"], "skipped")
        self.assertEqual(report["http"]["results"][0]["status_code"], 200)

    def test_open_view_keeps_closed_port_results_in_json(self):
        with socket.socket() as closed, tempfile.TemporaryDirectory() as directory:
            # Reserve a non-listening port so another process cannot claim it.
            closed.bind(("127.0.0.1", 0))
            closed_port = closed.getsockname()[1]
            path = Path(directory) / "report.json"
            result = self.command(
                [
                    self.url,
                    "--only",
                    "ports",
                    "-p",
                    f"{self.port},{closed_port}",
                    "--open",
                    "--no-color",
                    "-o",
                    "json",
                    "--output-file",
                    str(path),
                ]
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            report = json.loads(path.read_text(encoding="utf-8"))
            self.assertEqual(
                {item["port"]: item["status"] for item in report["ports"]["results"]},
                {self.port: "open", closed_port: "closed"},
            )
            self.assertEqual(report["http"]["status"], "skipped")
            self.assertEqual(report["settings"]["http_urls"], [])
            self.assertIn("1 closed", result.stdout)
            self.assertIn("1 other probe results hidden", result.stdout)
            self.assertNotIn(str(closed_port), result.stdout)

            as_json = self.command([self.url, "--only", "ports", "-p", str(closed_port), "--open", "--json"])
            self.assertEqual(as_json.returncode, 0, as_json.stderr)
            self.assertEqual(json.loads(as_json.stdout)["ports"]["results"][0]["status"], "closed")

    def test_invalid_arguments_never_write_json(self):
        result = self.command([self.url, "-p", "1-65535", "--json"])
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, "")
        self.assertIn("1024", result.stderr)

    def test_broken_pipe_preserves_export_and_exits_without_traceback(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            process = subprocess.Popen(
                [
                    sys.executable,
                    "-m",
                    "netscope",
                    self.url,
                    "-p",
                    str(self.port),
                    "--json",
                    "-o",
                    "json",
                    "--output-file",
                    str(path),
                ],
                env=self.environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            )
            process.stdout.close()
            stderr = process.stderr.read().decode("utf-8")
            process.stderr.close()
            self.assertEqual(process.wait(timeout=10), 0, stderr)
            self.assertTrue(path.is_file())
            self.assertNotIn("Traceback", stderr)

    @unittest.skipUnless(os.name == "posix", "POSIX signal delivery")
    def test_ctrl_c_cancels_an_inflight_http_request(self):
        with socket.socket() as listener:
            listener.bind(("127.0.0.1", 0))
            listener.listen(4)
            port = listener.getsockname()[1]
            listener.settimeout(10)
            with subprocess.Popen(
                [sys.executable, "-m", "netscope", f"http://127.0.0.1:{port}/", "-p", str(port), "--timeout", "30"],
                env=self.environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
            ) as process:
                connections = []
                try:
                    for _ in range(2):
                        connection, _ = listener.accept()
                        connections.append(connection)
                    process.send_signal(signal.SIGINT)
                    _, stderr = process.communicate(timeout=10)
                    self.assertEqual(process.returncode, 130, stderr.decode("utf-8"))
                    self.assertIn(b"Scan cancelled", stderr)
                    self.assertNotIn(b"Traceback", stderr)
                finally:
                    for connection in connections:
                        connection.close()
