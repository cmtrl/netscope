"""Check selection must control network work, reports, and terminal output."""

from contextlib import redirect_stderr, redirect_stdout
import io
from itertools import combinations
import json
import unittest
from unittest.mock import AsyncMock, patch

from rich.console import Console

from netscope.cli import main, render_ports, render_report
from netscope.scanner import scan_target
from netscope.utils import CHECKS, parse_checks


class SelectionTests(unittest.IsolatedAsyncioTestCase):
    async def test_all_selections_only_call_requested_checks(self):
        sections = {
            "dns": {"status": "ok", "records": {"A": {"status": "ok", "values": ["127.0.0.1"]}}},
            "ports": {"status": "ok", "resolution": {"status": "ok"}, "results": []},
            "http": {"status": "ok", "results": [{"status": "ok"}]},
        }
        for size in range(1, len(CHECKS) + 1):
            for checks in combinations(CHECKS, size):
                with self.subTest(checks=checks):
                    mocks = {kind: AsyncMock(return_value=section) for kind, section in sections.items()}
                    with (
                        patch("netscope.scanner.enumerate_dns", mocks["dns"]),
                        patch("netscope.scanner.scan_ports", mocks["ports"]),
                        patch("netscope.scanner.scan_http", mocks["http"]),
                    ):
                        report = await scan_target("example.com", checks=checks)
                    for kind in CHECKS:
                        if kind in checks:
                            mocks[kind].assert_awaited_once()
                            self.assertEqual(report[kind], sections[kind])
                        else:
                            mocks[kind].assert_not_called()
                            self.assertEqual(report[kind]["status"], "skipped")
                            self.assertIn("Not selected", report[kind]["reason"])
                    self.assertEqual(report["settings"]["checks"], list(checks))
                    self.assertEqual(report["status"], "completed")

    async def test_failed_http_only_scan_is_not_rescued_by_ip_resolution(self):
        with patch("netscope.scanner.scan_http", AsyncMock(return_value={"status": "error", "results": []})):
            report = await scan_target("http://127.0.0.1:8080", checks=("http",))
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["ports"]["resolution"]["status"], "skipped")

    async def test_dns_only_distinguishes_empty_answers_from_failures(self):
        for state, section_status, expected in (
            ("no_answer", "ok", "completed"),
            ("nxdomain", "error", "failed"),
            ("timeout", "error", "failed"),
        ):
            with (
                self.subTest(state=state),
                patch(
                    "netscope.scanner.enumerate_dns",
                    AsyncMock(
                        return_value={"status": section_status, "records": {"A": {"status": state, "values": []}}}
                    ),
                ),
            ):
                report = await scan_target("example.com", checks=("dns",))
            self.assertEqual(report["status"], expected)
            self.assertEqual(report["summary"]["dns_records"], 0)

    async def test_dns_only_ip_target_has_no_usable_results(self):
        report = await scan_target("127.0.0.1", checks=("dns",))
        self.assertEqual(report["status"], "failed")
        self.assertEqual(report["dns"]["status"], "skipped")
        self.assertIn("IP target", report["dns"]["reason"])

    async def test_api_rejects_empty_and_unknown_checks(self):
        for checks in ((), ("tls",), ("dns", ""), "dns", None):
            with self.subTest(checks=checks), self.assertRaises(ValueError):
                await scan_target("localhost", checks=checks)


class SelectionPresentationTests(unittest.TestCase):
    def test_cli_normalizes_combined_selection_and_keeps_json_clean(self):
        report = {"status": "completed"}
        scanner = AsyncMock(return_value=report)
        with (
            patch("netscope.cli.scan_target", scanner),
            redirect_stdout(io.StringIO()) as output,
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(main(["localhost", "--only", "HTTP, dns,HTTP", "--json"]), 0)
        self.assertEqual(scanner.await_args.kwargs["checks"], ("dns", "http"))
        self.assertEqual(json.loads(output.getvalue()), report)
        self.assertEqual(parse_checks("ports,dns"), ("dns", "ports"))

    def test_open_view_retains_an_inconclusive_probe_warning(self):
        ports = {
            "resolution": {"status": "ok"},
            "results": [
                {"address": "127.0.0.1", "port": port, "service": "unknown", "status": state, "elapsed_ms": 1.0}
                for port, state in [(33333, "open"), (44444, "closed"), (55555, "timeout"), (6666, "error")]
            ],
        }
        output = io.StringIO()
        render_ports(Console(file=output, width=120, color_system=None), ports, open_only=True)
        text = output.getvalue()
        self.assertIn("33333", text)
        for hidden in ["44444", "55555", "6666"]:
            self.assertNotIn(hidden, text)
        self.assertIn("3 other probe results hidden", text)
        self.assertIn("those ports may still be open", text)

    def test_open_view_with_no_results_does_not_claim_ports_are_closed(self):
        output = io.StringIO()
        render_ports(Console(file=output), {"resolution": {}, "results": []}, open_only=True)
        self.assertIn("No open TCP ports observed", output.getvalue())

    def test_http_only_view_omits_unselected_sections_and_counts(self):
        report = {
            "target": "localhost",
            "status": "completed",
            "duration_seconds": 0.1,
            "settings": {"checks": ["http"]},
            "summary": {"http_responses": 1, "missing_security_headers": 0},
            "http": {"results": []},
        }
        output = io.StringIO()
        render_report(Console(file=output, width=120, color_system=None), report)
        text = output.getvalue()
        self.assertIn("Checks: HTTP", text)
        self.assertNotIn("DNS enumeration", text)
        self.assertNotIn("TCP port probe", text)
        self.assertNotIn("Ports: 0", text)
