import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from netscope.utils import normalize_target, positive_timeout, terminal_text, url_host, write_json


class ValidationTests(unittest.TestCase):
    def test_normalizes_targets(self):
        cases = {
            " Example.COM. ": "example.com",
            "bücher.example": "xn--bcher-kva.example",
            "127.0.0.1": "127.0.0.1",
            "[2001:0db8::1]": "2001:db8::1",
            "::1": "::1",
            "localhost": "localhost",
        }
        for raw, expected in cases.items():
            with self.subTest(raw=raw):
                self.assertEqual(normalize_target(raw), expected)

    def test_rejects_invalid_targets(self):
        for value in (
            "",
            " ",
            "https://example.com",
            "example.com:443",
            "example.com/path",
            "*.example.com",
            "a..com",
            "-bad.com",
            "bad-.com",
            "bad_name.com",
            "999.1.1.1",
            "127.1",
            "01.2.3.4",
            "a b.com",
            "a\x1b.com",
            "[127.0.0.1]",
            "[bad]",
            "fe80::1%eth0",
            "[fe80::1%eth0]",
            "a" * 64 + ".com",
            ".",
            "foo\\bar",
            "example.com@evil.com",
            ".".join(["a" * 63] * 4),
        ):
            with self.subTest(value=value), self.assertRaises(ValueError):
                normalize_target(value)

    def test_ipv6_url(self):
        self.assertEqual(url_host("::1"), "[::1]")

    def test_timeout_bounds(self):
        self.assertEqual(positive_timeout("0.1"), 0.1)
        for value in ("nan", "inf", "-1", "0", "121", "oops"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                positive_timeout(value)

    def test_terminal_controls_removed(self):
        self.assertEqual(terminal_text("a\x1b[31mb\u202ec\n"), "a [31mb c ")


class ExportTests(unittest.TestCase):
    def test_atomic_json_utf8_and_private_permissions(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text("old content")
            report = {"target": "example.com", "text": "café", "nested": [1, None]}
            self.assertEqual(write_json(report, path), path)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), report)
            if os.name == "posix":
                self.assertEqual(path.stat().st_mode & 0o777, 0o600)
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_write_failure_preserves_existing_file_and_cleans_temp(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            path.write_text("old content")
            with patch("netscope.utils.os.replace", side_effect=PermissionError("read only")):
                with self.assertRaises(PermissionError):
                    write_json({"new": True}, path)
            self.assertEqual(path.read_text(), "old content")
            self.assertEqual(list(Path(directory).iterdir()), [path])

    def test_missing_parent_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(FileNotFoundError):
                write_json({}, Path(directory) / "missing" / "report.json")
