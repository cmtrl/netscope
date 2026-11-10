"""Network and CLI regressions for URL targets, scripts, and reliable cleanup."""

import asyncio
from contextlib import redirect_stderr, redirect_stdout
import io
import json
import os
from pathlib import Path
import socket
import ssl
import tempfile
import time
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from aiohttp import web
import aiohttp
import dns.asyncresolver
import dns.message
import dns.rcode
import dns.rdatatype
import dns.rrset

from netscope.cli import default_output, main, render_report
from netscope.resolver import AsyncResolver, read_hosts
from netscope.scanner import enumerate_dns, fetch_http, resolve_addresses, scan_http, scan_target
from netscope.utils import parse_ports, parse_target, validate_ports, write_json
from rich.console import Console


class InputTests(unittest.TestCase):
    def test_url_normalization_preserves_endpoint(self):
        for raw, host, url in (
            ("HTTPS://EXAMPLE.COM:8443/health", "example.com", "https://example.com:8443/health"),
            ("http://[::1]:8080/", "::1", "http://[::1]:8080/"),
            ("https://bücher.example", "xn--bcher-kva.example", "https://xn--bcher-kva.example/"),
        ):
            with self.subTest(raw=raw):
                target = parse_target(raw)
                self.assertEqual(target.host, host)
                self.assertEqual(target.url, url)

    def test_url_rejects_credentials_and_ambiguous_targets(self):
        for raw in (
            "ftp://example.com",
            "http://user:secret@example.com/",
            "http://example.com/?token=secret",
            "http://example.com/#fragment",
            "http://example.com:0",
            "http://example.com:65536",
            "http://example.com:",
            "http://example.com:abc",
            "http://",
            "http://[invalid]/",
            "http://example.com/a b",
            "http://example.com/a\x00b",
            "http://[fe80::1%eth0]/",
        ):
            with self.subTest(raw=raw), self.assertRaises(ValueError):
                parse_target(raw)

    def test_port_lists_ranges_and_deduplication(self):
        self.assertEqual(parse_ports("443,80,80,8000-8002"), (80, 443, 8000, 8001, 8002))
        self.assertEqual(parse_ports("1,65535"), (1, 65535))
        self.assertEqual(len(parse_ports("1-1024")), 1024)

    def test_invalid_or_unbounded_port_selections(self):
        for value in ("", "80,", "0", "65536", "1-65535", "2-1", "-1", "80/http", "1-1025", "1-1024,1025"):
            with self.subTest(value=value), self.assertRaises(ValueError):
                parse_ports(value)
        for values in ((), (True,), (80.0,), (0,), (65536,)):
            with self.subTest(values=values), self.assertRaises(ValueError):
                validate_ports(values)

    def test_generated_filename_stays_short_for_maximum_hostname(self):
        host = ".".join(["a" * 63] * 3 + ["b" * 61])
        self.assertLess(len(default_output(host).name), 180)
        self.assertNotIn(":", default_output("http://[::1]:8080/").name)

    @unittest.skipUnless(os.name == "posix", "POSIX filename-length regression")
    def test_long_valid_output_filename_uses_short_temporary_name(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / ("a" * 245 + ".json")
            write_json({"ok": True}, path)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), {"ok": True})

    def test_hosts_parsing_and_localhost_fallback(self):
        with patch(
            "netscope.resolver.Path.read_text",
            return_value="127.0.0.2 Demo.TEST alias # comment\n::1 local6\ninvalid ignored\n",
        ):
            hosts = read_hosts()
        self.assertEqual(hosts["demo.test"], ["127.0.0.2"])
        self.assertEqual(hosts["alias"], ["127.0.0.2"])
        self.assertIn("127.0.0.1", hosts["localhost"])
        self.assertNotIn("ignored", hosts)
        with patch("netscope.resolver.Path.read_text", side_effect=PermissionError):
            self.assertIn("localhost", read_hosts())


class ResolverTests(unittest.IsolatedAsyncioTestCase):
    async def test_unexpected_check_failure_cancels_sibling_checks(self):
        stopped = []

        async def blocked(name):
            try:
                await asyncio.Event().wait()
            finally:
                stopped.append(name)

        async def fail(*args):
            await asyncio.sleep(0)
            raise RuntimeError("test failure")

        async def port_check(*args):
            await blocked("ports")

        async def http_check(*args):
            await blocked("http")

        with (
            patch("netscope.scanner.enumerate_dns", side_effect=fail),
            patch("netscope.scanner.scan_ports", side_effect=port_check),
            patch("netscope.scanner.scan_http", side_effect=http_check),
        ):
            with self.assertRaisesRegex(RuntimeError, "test failure"):
                await scan_target("127.0.0.1")
        self.assertEqual(sorted(stopped), ["http", "ports"])

    async def test_queries_are_shared_and_consumer_cancellation_is_isolated(self):
        ready = asyncio.Event()

        async def slow_answer(*args, **kwargs):
            await ready.wait()
            return ["answer"]

        resolver = AsyncResolver(1)
        resolver._resolver = MagicMock(resolve=AsyncMock(side_effect=slow_answer))
        first = asyncio.create_task(resolver.query("demo.test", "A"))
        second = asyncio.create_task(resolver.query("demo.test", "A"))
        await asyncio.sleep(0)
        first.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await first
        ready.set()
        self.assertEqual(await second, ["answer"])
        self.assertEqual(resolver._resolver.resolve.await_count, 1)
        await resolver.close()

    async def test_close_cancels_owned_dns_tasks(self):
        resolver = AsyncResolver(10)
        resolver._resolver = MagicMock(resolve=AsyncMock(side_effect=lambda *a, **k: None))

        async def blocked(*args, **kwargs):
            await asyncio.Event().wait()

        resolver._resolver.resolve.side_effect = blocked
        consumer = asyncio.create_task(resolver.query("demo.test", "A"))
        await asyncio.sleep(0)
        await resolver.close()
        with self.assertRaises(asyncio.CancelledError):
            await consumer
        self.assertTrue(all(task.done() for task in resolver._queries.values()))

    async def test_query_deadline_is_enforced(self):
        async def blocked(*args, **kwargs):
            await asyncio.Event().wait()

        resolver = AsyncResolver(0.1)
        resolver._resolver = MagicMock(resolve=AsyncMock(side_effect=blocked))
        started = time.monotonic()
        with self.assertRaises(asyncio.TimeoutError):
            await resolver.query("demo.test", "A")
        self.assertLess(time.monotonic() - started, 1)
        await resolver.close()

    async def test_hosts_and_ip_addresses_do_not_call_dns(self):
        resolver = AsyncResolver(0.1)
        for target in ("localhost", "demo.localhost", "127.0.0.1", "::1"):
            result = await resolver.resolve(target, 8080, socket.AF_UNSPEC)
            self.assertTrue(result)
        self.assertFalse(resolver._queries)
        with self.assertRaises(socket.gaierror):
            await resolver.resolve("::1", family=socket.AF_INET)
        await resolver.close()

    async def test_resolver_configuration_failure_preserves_report(self):
        with patch("netscope.resolver.dns.asyncresolver.Resolver", side_effect=dns.resolver.NoResolverConfiguration):
            dns_result = await enumerate_dns("demo.test", 0.1)
            addresses = await resolve_addresses("demo.test", 0.1)
        self.assertEqual(dns_result["status"], "error")
        self.assertEqual(addresses["status"], "error")


class DNSFixture(asyncio.DatagramProtocol):
    def __init__(self):
        self.counts = {}
        self.drop = False

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, packet, address):
        request = dns.message.from_wire(packet)
        kind = dns.rdatatype.to_text(request.question[0].rdtype)
        self.counts[kind] = self.counts.get(kind, 0) + 1
        if self.drop:
            return
        reply = dns.message.make_response(request)
        records = {"A": "127.0.0.1", "MX": "10 mail.demo.test.", "TXT": '"local DNS fixture"', "NS": "ns.demo.test."}
        if kind in records:
            reply.answer.append(dns.rrset.from_text("demo.test.", 60, "IN", kind, records[kind]))
        self.transport.sendto(reply.to_wire(), address)


class NetworkTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.loop_errors = []
        loop = asyncio.get_running_loop()
        self.original_exception_handler = loop.get_exception_handler()

        def handle_loop_error(loop, context):
            # A bare TCP probe and a rejected self-signed certificate intentionally
            # terminate the TLS fixture's handshake. Do not hide other errors.
            if context.get("message") == "Error on transport creation for incoming connection" and isinstance(
                context.get("exception"), (ConnectionResetError, ssl.SSLError)
            ):
                return
            self.loop_errors.append(context)
            loop.default_exception_handler(context)

        loop.set_exception_handler(handle_loop_error)
        app = web.Application()
        self.paths = []

        async def page(request):
            self.paths.append(request.path)
            return web.Response(
                text="local fixture",
                headers={"Server": "NetScope-Test", "Set-Cookie": "session=private", "X-Powered-By": "fixture"},
            )

        app.router.add_get("/health", page)
        self.runner = web.AppRunner(app)
        await self.runner.setup()
        site = web.TCPSite(self.runner, "127.0.0.1", 0)
        await site.start()
        self.port = site._server.sockets[0].getsockname()[1]
        self.url = f"http://127.0.0.1:{self.port}/health"
        self.proxy_environment = patch.dict(
            os.environ,
            {
                "NO_PROXY": os.environ.get("NO_PROXY", "") + ",127.0.0.1,localhost,demo.test",
                "no_proxy": os.environ.get("no_proxy", "") + ",127.0.0.1,localhost,demo.test",
            },
        )
        self.proxy_environment.start()

    async def asyncTearDown(self):
        self.proxy_environment.stop()
        await self.runner.cleanup()
        asyncio.get_running_loop().set_exception_handler(self.original_exception_handler)
        self.assertFalse(self.loop_errors, self.loop_errors)

    async def test_url_scan_reaches_custom_port_and_path(self):
        report = await scan_target(self.url, ports=(self.port,), timeout=1)
        self.assertEqual(report["status"], "completed")
        self.assertEqual(report["summary"]["ports"]["open"], 1)
        self.assertEqual(report["summary"]["http_responses"], 1)
        self.assertEqual(len(report["http"]["results"]), 1)
        self.assertEqual(self.paths, ["/health"])
        self.assertEqual(report["settings"]["ports"], [self.port])
        self.assertEqual(report["summary"]["missing_security_headers"], 2)

    async def test_url_port_is_added_to_default_tcp_selection(self):
        report = await scan_target(self.url, timeout=0.2)
        self.assertIn(self.port, report["settings"]["ports"])
        self.assertTrue(
            any(item["port"] == self.port and item["status"] == "open" for item in report["ports"]["results"])
        )

    async def test_cookie_redaction_default_and_explicit_opt_in(self):
        for enabled in (False, True):
            report = await scan_target(self.url, ports=(self.port,), timeout=1, show_sensitive_headers=enabled)
            header = next(
                item for item in report["http"]["results"][0]["headers"] if item["name"].lower() == "set-cookie"
            )
            self.assertEqual(header["value"], "session=private" if enabled else "[redacted]")
            self.assertEqual("session=private" in json.dumps(report), enabled)
            output = io.StringIO()
            render_report(Console(file=output, width=120, color_system=None), report, verbose=True)
            self.assertEqual("session=private" in output.getvalue(), enabled)

    async def test_live_dns_packets_shared_with_http_and_port_resolution(self):
        transport, server = await asyncio.get_running_loop().create_datagram_endpoint(
            DNSFixture, local_addr=("127.0.0.1", 0)
        )
        dns_client = dns.asyncresolver.Resolver(configure=False)
        dns_client.nameservers = ["127.0.0.1"]
        dns_client.port = transport.get_extra_info("sockname")[1]
        resolver = AsyncResolver(1)
        resolver._resolver = dns_client
        try:
            harvested, addresses, http = await asyncio.gather(
                enumerate_dns("demo.test", 1, resolver),
                resolve_addresses("demo.test", 1, resolver),
                scan_http("demo.test", 1, (f"http://demo.test:{self.port}/health",), resolver),
            )
            self.assertEqual(harvested["status"], "ok")
            self.assertEqual(harvested["records"]["A"]["ttl_seconds"], 60)
            self.assertEqual(addresses["addresses"], ["127.0.0.1"])
            self.assertEqual(http["status"], "ok")
            self.assertEqual(server.counts, dict.fromkeys(("A", "AAAA", "MX", "TXT", "NS"), 1))
        finally:
            await resolver.close()
            transport.close()

    async def test_actual_dns_timeout_closes_without_system_resolver_thread(self):
        transport, server = await asyncio.get_running_loop().create_datagram_endpoint(
            DNSFixture, local_addr=("127.0.0.1", 0)
        )
        server.drop = True
        dns_client = dns.asyncresolver.Resolver(configure=False)
        dns_client.nameservers = ["127.0.0.1"]
        dns_client.port = transport.get_extra_info("sockname")[1]
        resolver = AsyncResolver(0.1)
        resolver._resolver = dns_client
        try:
            result = await resolve_addresses("demo.test", 0.1, resolver)
            self.assertEqual(result["status"], "timeout")
        finally:
            await resolver.close()
            transport.close()

    async def test_real_tls_default_rejection_and_explicit_test_trust(self):
        fixtures = Path(__file__).parent / "fixtures"
        server_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server_context.load_cert_chain(fixtures / "localhost-cert.pem", fixtures / "localhost-key.pem")
        site = web.TCPSite(self.runner, "127.0.0.1", 0, ssl_context=server_context)
        await site.start()
        port = site._server.sockets[0].getsockname()[1]
        url = f"https://127.0.0.1:{port}/health"
        report = await scan_target(url, ports=(port,), timeout=2)
        self.assertEqual(report["http"]["results"][0]["status"], "tls_error")
        self.assertEqual(report["ports"]["results"][0]["status"], "open")
        trust = ssl.create_default_context(cafile=str(fixtures / "localhost-cert.pem"))
        async with aiohttp.ClientSession(connector=aiohttp.TCPConnector(ssl=trust)) as session:
            result = await fetch_http(session, url)
        self.assertEqual(result["status"], "ok")
        self.assertEqual(result["security_headers"][0]["status"], "missing")

    async def test_non_utf8_response_header_can_be_exported(self):
        async def respond(reader, writer):
            try:
                await reader.readuntil(b"\r\n\r\n")
                writer.write(b"HTTP/1.1 200 OK\r\nX-Bytes: \xff\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                await writer.drain()
            except asyncio.IncompleteReadError:
                pass  # The TCP probe closes without sending an HTTP request.
            finally:
                writer.close()
                await writer.wait_closed()

        server = await asyncio.start_server(respond, "127.0.0.1", 0)
        async with server:
            port = server.sockets[0].getsockname()[1]
            report = await scan_target(f"http://127.0.0.1:{port}/", ports=(port,), timeout=1)
        self.assertEqual(report["http"]["results"][0]["status"], "ok")
        with tempfile.TemporaryDirectory() as directory:
            path = write_json(report, Path(directory) / "report.json")
            self.assertEqual(json.loads(path.read_text(encoding="utf-8"))["target"], "127.0.0.1")


class CLIScriptingTests(unittest.TestCase):
    def test_json_stdout_is_clean_even_on_a_narrow_colored_terminal(self):
        report = {"status": "partial", "target": "a" * 200, "text": "café"}
        with (
            patch("netscope.cli.scan_target", AsyncMock(return_value=report)),
            patch.dict(os.environ, {"COLUMNS": "20", "FORCE_COLOR": "1"}),
        ):
            with redirect_stdout(io.StringIO()) as output, redirect_stderr(io.StringIO()):
                result = main(["localhost", "--json"])
        self.assertEqual(result, 0)
        self.assertEqual(json.loads(output.getvalue()), report)
        self.assertNotIn("\x1b", output.getvalue())

    def test_positional_and_legacy_targets_pass_custom_ports(self):
        for arguments in (["localhost"], ["-t", "localhost"]):
            scanner = AsyncMock(return_value={"status": "completed"})
            with (
                patch("netscope.cli.scan_target", scanner),
                patch("netscope.cli.render_report"),
                redirect_stdout(io.StringIO()),
            ):
                self.assertEqual(main(arguments + ["-p", "80,443", "--no-color"]), 0)
            self.assertEqual(scanner.await_args.args[3], (80, 443))

    def test_ambiguous_target_arguments_rejected(self):
        with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit) as error:
            main(["localhost", "-t", "example.com"])
        self.assertEqual(error.exception.code, 2)

    def test_file_is_saved_before_terminal_render_failure(self):
        report = {"status": "completed"}
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "report.json"
            with (
                patch("netscope.cli.scan_target", AsyncMock(return_value=report)),
                patch("netscope.cli.render_report", side_effect=OSError("terminal unavailable")),
                redirect_stdout(io.StringIO()),
                redirect_stderr(io.StringIO()),
            ):
                result = main(["localhost", "-o", "json", "--output-file", str(path)])
            self.assertEqual(result, 1)
            self.assertEqual(json.loads(path.read_text(encoding="utf-8")), report)
