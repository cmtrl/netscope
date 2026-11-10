from contextlib import redirect_stderr, redirect_stdout
import io
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import AsyncMock, patch

from netscope.cli import main, safe


class CliTests(unittest.TestCase):
    def test_help(self):
        with redirect_stdout(io.StringIO()) as output, self.assertRaises(SystemExit) as caught:
            main(["--help"])
        self.assertEqual(caught.exception.code, 0)
        self.assertIn("--output-file", output.getvalue())

    def test_invalid_arguments(self):
        for arguments in (
            [],
            ["-t", "https://example.com"],
            ["-t", "example.com", "--timeout", "nan"],
            ["-t", "example.com", "--concurrency", "0"],
            ["-t", "example.com", "--output-file", "report.json"],
        ):
            with (
                self.subTest(arguments=arguments),
                redirect_stderr(io.StringIO()),
                self.assertRaises(SystemExit) as caught,
            ):
                main(arguments)
            self.assertEqual(caught.exception.code, 2)

    def test_terminal_markup_stays_literal(self):
        self.assertEqual(safe("[red]spoof[/red]").plain, "[red]spoof[/red]")
        self.assertFalse(safe("[red]spoof[/red]").spans)

    def test_json_export_and_exit_codes(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            for status, expected in (("completed", 0), ("partial", 0), ("failed", 1)):
                report = {"status": status, "target": "localhost"}
                with (
                    patch("netscope.cli.scan_target", AsyncMock(return_value=report)),
                    patch("netscope.cli.render_report"),
                    redirect_stdout(io.StringIO()),
                ):
                    result = main(["-t", "localhost", "-o", "json", "--output-file", str(path), "--no-color"])
                self.assertEqual(result, expected)
                self.assertEqual(json.loads(path.read_text()), report)

    def test_export_failure_exit_code(self):
        with (
            patch("netscope.cli.scan_target", AsyncMock(return_value={"status": "completed"})),
            patch("netscope.cli.render_report"),
            patch("netscope.cli.write_json", side_effect=PermissionError("denied")),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()) as errors,
        ):
            result = main(["-t", "localhost", "-o", "json"])
        self.assertEqual(result, 1)
        self.assertIn("denied", errors.getvalue())

    def test_ctrl_c_exit_code(self):
        def interrupt(coroutine):
            # The real asyncio.run would consume this coroutine.
            coroutine.close()
            raise KeyboardInterrupt

        with (
            patch("netscope.cli.asyncio.run", side_effect=interrupt),
            redirect_stdout(io.StringIO()),
            redirect_stderr(io.StringIO()),
        ):
            self.assertEqual(main(["-t", "localhost"]), 130)
