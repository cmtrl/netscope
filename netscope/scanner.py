"""Bounded, asynchronous DNS, TCP, and HTTP reconnaissance."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import errno
import ipaddress
import math
import socket
import time
from typing import Any

import aiohttp
import dns.exception
import dns.resolver
from multidict import CIMultiDict

from .resolver import AsyncResolver, resolver_context
from .utils import COMMON_PORTS, SCHEMA_VERSION, SERVICES, VERSION, is_ip, parse_target, url_host, validate_ports

DNS_TYPES = ("A", "AAAA", "MX", "TXT", "NS")
MAX_ADDRESSES = 16
SENSITIVE_HEADERS = {
    "set-cookie",
    "authorization",
    "proxy-authorization",
    "authentication-info",
    "proxy-authentication-info",
}


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


async def gather_checks(*coroutines):
    """If a check aborts unexpectedly, cancel and await its sibling checks."""
    tasks = [asyncio.create_task(coroutine) for coroutine in coroutines]
    try:
        return await asyncio.gather(*tasks)
    except BaseException:
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)
        raise


async def enumerate_dns(target: str, timeout: float, resolver: AsyncResolver | None = None) -> dict[str, Any]:
    if is_ip(target):
        return {"status": "skipped", "reason": "IP target; forward DNS enumeration requires a hostname", "records": {}}
    if target == "localhost" or target.endswith(".localhost"):
        return {"status": "skipped", "reason": "localhost is resolved locally; no external DNS queries", "records": {}}
    async with resolver_context(timeout, resolver) as resolver:

        async def query(record_type: str) -> tuple[str, dict[str, Any]]:
            try:
                answer = await resolver.query(target, record_type)
                result = {"status": "ok", "values": sorted(record.to_text() for record in answer)}
                if getattr(answer, "rrset", None) is not None:
                    result["ttl_seconds"] = answer.rrset.ttl
            except dns.resolver.NXDOMAIN:
                result = {"status": "nxdomain", "values": [], "error": "DNS name does not exist"}
            except dns.resolver.NoAnswer:
                result = {"status": "no_answer", "values": []}
            except (dns.exception.Timeout, asyncio.TimeoutError):
                result = {"status": "timeout", "values": [], "error": "DNS query timed out"}
            except (dns.exception.DNSException, OSError) as exc:
                result = {"status": "error", "values": [], "error": str(exc)}
            return record_type, result

        records = dict(await asyncio.gather(*(query(kind) for kind in DNS_TYPES)))
    statuses = {result["status"] for result in records.values()}
    status = "ok" if statuses <= {"ok", "no_answer"} else "partial" if "ok" in statuses else "error"
    return {"status": status, "records": records}


async def resolve_addresses(target: str, timeout: float, resolver: AsyncResolver | None = None) -> dict[str, Any]:
    if is_ip(target):
        return {"status": "ok", "addresses": [target], "truncated": False}
    async with resolver_context(timeout, resolver) as resolver:
        try:
            entries = await resolver.resolve(target, family=socket.AF_UNSPEC)
        except asyncio.TimeoutError:
            return {"status": "timeout", "addresses": [], "error": "Address resolution timed out"}
        except (OSError, dns.exception.DNSException) as exc:
            return {"status": "error", "addresses": [], "error": str(exc)}
    unique = sorted({entry["host"] for entry in entries}, key=lambda addr: (ipaddress.ip_address(addr).version, addr))
    if not unique:
        return {"status": "error", "addresses": [], "error": "No IPv4 or IPv6 addresses returned"}
    return {"status": "ok", "addresses": unique[:MAX_ADDRESSES], "truncated": len(unique) > MAX_ADDRESSES}


async def probe_port(address: str, port: int, timeout: float, semaphore: asyncio.Semaphore) -> dict[str, Any]:
    result: dict[str, Any] = {"address": address, "port": port, "service": SERVICES.get(port, "unknown")}
    async with semaphore:
        started = time.monotonic()
        try:
            family = socket.AF_INET6 if ":" in address else socket.AF_INET
            with socket.socket(family, socket.SOCK_STREAM) as connection:
                connection.setblocking(False)
                endpoint = (address, port, 0, 0) if family == socket.AF_INET6 else (address, port)
                await asyncio.wait_for(asyncio.get_running_loop().sock_connect(connection, endpoint), timeout=timeout)
            result["status"] = "open"
        except asyncio.TimeoutError:
            result.update(status="timeout", error="TCP connection timed out")
        except OSError as exc:
            if exc.errno == errno.ECONNREFUSED:
                result["status"] = "closed"
            else:
                result.update(status="error", error=str(exc))
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


async def scan_ports(
    target: str,
    timeout: float,
    concurrency: int,
    ports: tuple[int, ...] = COMMON_PORTS,
    resolver: AsyncResolver | None = None,
) -> dict[str, Any]:
    resolution = await resolve_addresses(target, timeout, resolver)
    if resolution["status"] != "ok":
        return {"status": "error", "resolution": resolution, "results": []}
    semaphore = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(
        *(probe_port(address, port, timeout, semaphore) for address in resolution["addresses"] for port in ports)
    )
    return {
        "status": "partial"
        if resolution.get("truncated") or any(result["status"] in {"error", "timeout"} for result in results)
        else "ok",
        "resolution": resolution,
        "results": results,
    }


def analyze_headers(headers: Any, scheme: str) -> tuple[list[dict[str, Any]], list[dict[str, str]]]:
    """Presence checks and declared technology hints, not vulnerability claims."""
    security = []
    for name in ("Strict-Transport-Security", "Content-Security-Policy", "X-Frame-Options"):
        values = headers.getall(name, [])
        status = "present" if any(value.strip() for value in values) else "missing"
        if name == "Strict-Transport-Security" and scheme != "https":
            status = "not_applicable"
        security.append({"header": name, "status": status, "values": values})
    technologies = [
        {"source": name, "value": value}
        for name in ("Server", "X-Powered-By", "X-Generator", "Via")
        for value in headers.getall(name, [])
        if value.strip()
    ]
    return security, technologies


def header_text(value: str) -> str:
    # aiohttp uses surrogateescape for non-UTF-8 bytes; exported JSON must remain UTF-8 encodable.
    return value.encode("utf-8", errors="replace").decode("utf-8")


async def fetch_http(session: aiohttp.ClientSession, url: str, show_sensitive_headers: bool = False) -> dict[str, Any]:
    result: dict[str, Any] = {"url": url}
    started = time.monotonic()
    try:
        async with session.get(url, allow_redirects=False) as response:
            headers = CIMultiDict((header_text(name), header_text(value)) for name, value in response.headers.items())
            security, technologies = analyze_headers(headers, response.url.scheme)
            captured = [
                {
                    "name": name,
                    "value": "[redacted]"
                    if name.lower() in SENSITIVE_HEADERS and not show_sensitive_headers
                    else value,
                }
                for name, value in headers.items()
            ]
            result.update(
                status="ok",
                status_code=response.status,
                reason=header_text(response.reason or ""),
                headers=captured,
                security_headers=security,
                technologies=technologies,
                redirect_location=headers.get("Location") if 300 <= response.status < 400 else None,
            )
            response.close()
    except asyncio.TimeoutError:
        result.update(status="timeout", error="HTTP request timed out")
    except aiohttp.ClientSSLError as exc:
        result.update(status="tls_error", error=str(exc))
    except (aiohttp.ClientError, OSError, dns.exception.DNSException) as exc:
        result.update(status="error", error=str(exc))
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


async def scan_http(
    target: str,
    timeout: float,
    urls: tuple[str, ...] | None = None,
    resolver: AsyncResolver | None = None,
    show_sensitive_headers: bool = False,
) -> dict[str, Any]:
    urls = urls if urls is not None else tuple(f"{scheme}://{url_host(target)}/" for scheme in ("https", "http"))
    async with resolver_context(timeout, resolver) as resolver:
        connector = aiohttp.TCPConnector(limit=4, limit_per_host=2, resolver=resolver, family=socket.AF_UNSPEC)
        async with aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=timeout, ceil_threshold=120),
            headers={"User-Agent": f"NetScope/{VERSION}"},
            cookie_jar=aiohttp.DummyCookieJar(),
            trust_env=True,
            auto_decompress=False,
        ) as session:
            results = await asyncio.gather(*(fetch_http(session, url, show_sensitive_headers) for url in urls))
    successes = sum(result["status"] == "ok" for result in results)
    return {"status": "ok" if successes == len(results) else "partial" if successes else "error", "results": results}


async def scan_target(
    target: str,
    timeout: float = 5.0,
    concurrency: int = 32,
    ports: tuple[int, ...] | None = None,
    show_sensitive_headers: bool = False,
) -> dict[str, Any]:
    """Scan one host or URL; retain independent failures and close all DNS tasks."""
    selected = parse_target(target)
    if (
        not isinstance(timeout, (int, float))
        or isinstance(timeout, bool)
        or not math.isfinite(timeout)
        or not 0.1 <= timeout <= 120
    ):
        raise ValueError("timeout must be between 0.1 and 120 seconds")
    if type(concurrency) is not int or not 1 <= concurrency <= 256:
        raise ValueError("concurrency must be an integer between 1 and 256")
    ports = validate_ports(
        ports if ports is not None else tuple(sorted(set(COMMON_PORTS) | ({selected.port} if selected.port else set())))
    )
    urls = (selected.url,) if selected.url else None
    started = time.monotonic()
    started_at = utc_now()
    async with resolver_context(timeout, None) as resolver:
        dns_result, port_result, http = await gather_checks(
            enumerate_dns(selected.host, timeout, resolver),
            scan_ports(selected.host, timeout, concurrency, ports, resolver),
            scan_http(selected.host, timeout, urls, resolver, show_sensitive_headers),
        )
    usable = (
        port_result["resolution"]["status"] == "ok"
        or any(record["status"] == "ok" for record in dns_result["records"].values())
        or any(result["status"] == "ok" for result in http["results"])
    )
    status = (
        "failed"
        if not usable
        else "partial"
        if any(section["status"] not in {"ok", "skipped"} for section in (dns_result, port_result, http))
        else "completed"
    )
    port_counts = {
        state: sum(item["status"] == state for item in port_result["results"])
        for state in ("open", "closed", "timeout", "error")
    }
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "NetScope", "version": VERSION},
        "target": selected.host,
        "target_type": "ip" if is_ip(selected.host) else "hostname",
        "started_at": started_at,
        "finished_at": utc_now(),
        "duration_seconds": round(time.monotonic() - started, 3),
        "status": status,
        "settings": {
            "timeout_seconds": timeout,
            "tcp_concurrency": concurrency,
            "ports": list(ports),
            "http_urls": list(urls)
            if urls
            else [f"{scheme}://{url_host(selected.host)}/" for scheme in ("https", "http")],
            "show_sensitive_headers": show_sensitive_headers,
        },
        "summary": {
            "ports": port_counts,
            "dns_records": sum(len(record["values"]) for record in dns_result["records"].values()),
            "http_responses": sum(item["status"] == "ok" for item in http["results"]),
            "missing_security_headers": sum(
                check["status"] == "missing" for item in http["results"] for check in item.get("security_headers", [])
            ),
        },
        "dns": dns_result,
        "ports": port_result,
        "http": http,
    }
