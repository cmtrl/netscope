import asyncio
import errno
import socket
import ssl
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

import aiohttp
from aiohttp import web
import dns.exception
import dns.resolver
from multidict import CIMultiDict

from netscope.scanner import (
    analyze_headers,
    enumerate_dns,
    fetch_http,
    probe_port,
    resolve_addresses,
    scan_ports,
    scan_target,
)


class DnsTests(unittest.IsolatedAsyncioTestCase):
    async def test_queries_all_types_concurrently_and_keeps_partial_results(self):
        active = 0
        peak = 0

        async def resolve(target, kind, **kwargs):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1
            self.assertEqual(kwargs, {"lifetime": 0.2, "search": False})
            if kind == "AAAA":
                raise dns.resolver.NoAnswer
            if kind == "TXT":
                raise dns.exception.Timeout
            return [MagicMock(to_text=lambda: "record value")]

        resolver = MagicMock(resolve=resolve)
        with patch("netscope.resolver.dns.asyncresolver.Resolver", return_value=resolver):
            result = await enumerate_dns("example.com", 0.2)
        self.assertEqual(peak, 5)
        self.assertEqual(result["status"], "partial")
        self.assertEqual(result["records"]["TXT"]["status"], "timeout")
        self.assertEqual(result["records"]["AAAA"]["status"], "no_answer")
        self.assertEqual(result["records"]["MX"]["values"], ["record value"])

    async def test_ip_skips_forward_dns(self):
        with patch("netscope.resolver.dns.asyncresolver.Resolver") as resolver:
            self.assertEqual((await enumerate_dns("::1", 1))["status"], "skipped")
            resolver.assert_not_called()

    async def test_nxdomain_and_resolver_failure(self):
        for error in (dns.resolver.NXDOMAIN(), dns.resolver.NoNameservers()):
            with self.subTest(error=error):
                resolver = MagicMock(resolve=AsyncMock(side_effect=error))
                with patch("netscope.resolver.dns.asyncresolver.Resolver", return_value=resolver):
                    result = await enumerate_dns("absent.invalid", 0.1)
                self.assertEqual(result["status"], "error")
                self.assertEqual(len(result["records"]), 5)


class PortTests(unittest.IsolatedAsyncioTestCase):
    async def test_real_nonblocking_open_port(self):
        def connected(reader, writer):
            writer.close()

        server = await asyncio.start_server(connected, "127.0.0.1", 0)
        async with server:
            port = server.sockets[0].getsockname()[1]
            result = await probe_port("127.0.0.1", port, 1, asyncio.Semaphore(1))
        self.assertEqual(result["status"], "open")

    async def test_refusal_timeout_and_unreachable_are_distinct(self):
        loop = asyncio.get_running_loop()
        for error, expected in (
            (ConnectionRefusedError(errno.ECONNREFUSED, "refused"), "closed"),
            (OSError(10061, "Winsock connection refused"), "closed"),
            (asyncio.TimeoutError(), "timeout"),
            (OSError(errno.ENETUNREACH, "unreachable"), "error"),
        ):
            with self.subTest(expected=expected), patch.object(loop, "sock_connect", AsyncMock(side_effect=error)):
                result = await probe_port("127.0.0.1", 443, 0.1, asyncio.Semaphore(1))
                self.assertEqual(result["status"], expected)

    async def test_concurrency_bound_and_both_address_families(self):
        active = 0
        peak = 0
        loop = asyncio.get_running_loop()

        async def connect(connection, endpoint):
            nonlocal active, peak
            active += 1
            peak = max(peak, active)
            await asyncio.sleep(0.01)
            active -= 1

        with (
            patch(
                "netscope.scanner.resolve_addresses",
                AsyncMock(
                    return_value={
                        "status": "ok",
                        "addresses": ["127.0.0.1", "::1"],
                        "truncated": False,
                    }
                ),
            ),
            patch.object(loop, "sock_connect", connect),
        ):
            result = await scan_ports("localhost", 1, 2)
        self.assertEqual(peak, 2)
        self.assertEqual(len(result["results"]), 12)

    async def test_resolution_error_preserves_structured_failure(self):
        with patch("netscope.resolver.AsyncResolver.resolve", AsyncMock(side_effect=socket.gaierror("unknown"))):
            result = await scan_ports("absent.invalid", 0.1, 2)
        self.assertEqual(result["status"], "error")
        self.assertEqual(result["results"], [])

    async def test_address_deduplication_and_cap(self):
        entries = [{"host": f"192.0.2.{i}"} for i in range(1, 20)]
        with patch("netscope.resolver.AsyncResolver.resolve", AsyncMock(return_value=entries + entries)):
            result = await resolve_addresses("example.com", 1)
        self.assertEqual(len(result["addresses"]), 16)
        self.assertTrue(result["truncated"])


class HttpTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.redirect_hits = 0
        app = web.Application()

        async def root(request):
            return web.Response(
                headers=CIMultiDict(
                    [
                        ("sTrIcT-TrAnSpOrT-sEcUrItY", "max-age=31536000"),
                        ("Content-Security-Policy", "default-src 'self'"),
                        ("X-Powered-By", "test-engine"),
                        ("X-Test", "one"),
                        ("X-Test", "two"),
                    ]
                )
            )

        async def redirect(request):
            return web.Response(status=302, headers={"Location": "/destination"})

        async def destination(request):
            self.redirect_hits += 1
            return web.Response()

        async def slow(request):
            await asyncio.sleep(0.15)
            return web.Response()

        async def stream(request):
            response = web.StreamResponse()
            await response.prepare(request)
            await asyncio.sleep(0.15)
            return response

        for path, handler in (
            ("/", root),
            ("/redirect", redirect),
            ("/destination", destination),
            ("/slow", slow),
            ("/stream", stream),
        ):
            app.router.add_get(path, handler)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.base = f"http://127.0.0.1:{site._server.sockets[0].getsockname()[1]}"
        self.session = aiohttp.ClientSession(timeout=aiohttp.ClientTimeout(total=0.08))

    async def asyncTearDown(self):
        await self.session.close()
        await self.runner.cleanup()

    async def test_http_headers_duplicates_technology_and_security(self):
        result = await fetch_http(self.session, self.base)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(
            [header["value"] for header in result["headers"] if header["name"] == "X-Test"], ["one", "two"]
        )
        states = {entry["header"]: entry["status"] for entry in result["security_headers"]}
        self.assertEqual(states["Strict-Transport-Security"], "not_applicable")
        self.assertEqual(states["Content-Security-Policy"], "present")
        self.assertEqual(states["X-Frame-Options"], "missing")
        self.assertIn({"source": "X-Powered-By", "value": "test-engine"}, result["technologies"])

    async def test_redirect_not_followed(self):
        result = await fetch_http(self.session, self.base + "/redirect")
        self.assertEqual(result["status_code"], 302)
        self.assertEqual(result["redirect_location"], "/destination")
        self.assertEqual(self.redirect_hits, 0)

    async def test_timeout(self):
        result = await fetch_http(self.session, self.base + "/slow")
        self.assertEqual(result["status"], "timeout")

    async def test_body_not_required(self):
        result = await fetch_http(self.session, self.base + "/stream")
        self.assertEqual(result["status"], "ok")

    async def test_http_error_response_still_analyzed(self):
        result = await fetch_http(self.session, self.base + "/absent")
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["status_code"], 404)

    async def test_connection_drop(self):
        async def drop(reader, writer):
            writer.close()
            await writer.wait_closed()

        server = await asyncio.start_server(drop, "127.0.0.1", 0)
        async with server:
            url = f"http://127.0.0.1:{server.sockets[0].getsockname()[1]}"
            result = await fetch_http(self.session, url)
        self.assertEqual(result["status"], "error")

    async def test_certificate_failure_is_not_retried_insecurely(self):
        session = MagicMock()
        error = aiohttp.ClientConnectorCertificateError(MagicMock(), ssl.CertificateError("untrusted"))
        session.get.side_effect = error
        result = await fetch_http(session, "https://example.com/")
        self.assertEqual(result["status"], "tls_error")
        session.get.assert_called_once_with("https://example.com/", allow_redirects=False)

    def test_https_header_presence_is_case_insensitive_and_not_policy_validation(self):
        headers = CIMultiDict({"strict-transport-security": "max-age=0", "X-Frame-Options": " "})
        security, _ = analyze_headers(headers, "https")
        self.assertEqual(security[0]["status"], "present")
        self.assertEqual(security[2]["status"], "missing")


class ReportTests(unittest.IsolatedAsyncioTestCase):
    async def test_partial_failed_and_completed_states(self):
        for usable, http_status, expected in (
            (True, "partial", "partial"),
            (True, "ok", "completed"),
            (False, "error", "failed"),
        ):
            with self.subTest(expected=expected):
                ports = {
                    "status": "ok" if usable else "error",
                    "resolution": {"status": "ok" if usable else "error"},
                    "results": [],
                }
                http = {"status": http_status, "results": []}
                with (
                    patch(
                        "netscope.scanner.enumerate_dns", AsyncMock(return_value={"status": "skipped", "records": {}})
                    ),
                    patch("netscope.scanner.scan_ports", AsyncMock(return_value=ports)),
                    patch("netscope.scanner.scan_http", AsyncMock(return_value=http)),
                ):
                    report = await scan_target("127.0.0.1")
                self.assertEqual(report["status"], expected)
                self.assertEqual(report["schema_version"], "1.2")

    async def test_api_rejects_bad_settings(self):
        for kwargs in ({"timeout": float("nan")}, {"timeout": -1}, {"concurrency": 0}, {"concurrency": 257}):
            with self.subTest(kwargs=kwargs), self.assertRaises(ValueError):
                await scan_target("localhost", **kwargs)

    async def test_cancellation_propagates(self):
        with (
            patch("netscope.scanner.enumerate_dns", AsyncMock(side_effect=asyncio.CancelledError)),
            patch("netscope.scanner.scan_ports", AsyncMock(return_value={})),
            patch("netscope.scanner.scan_http", AsyncMock(return_value={})),
        ):
            with self.assertRaises(asyncio.CancelledError):
                await scan_target("localhost")
