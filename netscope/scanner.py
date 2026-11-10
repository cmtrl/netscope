"""Bounded, asynchronous DNS, TCP, and HTTP reconnaissance."""

from __future__ import annotations

import asyncio
from datetime import datetime, timezone
import errno
import ipaddress
import socket
import time
from typing import Any

import aiohttp
import dns.asyncresolver
import dns.exception
import dns.resolver

from .utils import COMMON_PORTS, SCHEMA_VERSION, SERVICES, VERSION, is_ip, normalize_target, url_host

DNS_TYPES = ("A", "AAAA", "MX", "TXT", "NS")
MAX_ADDRESSES = 16


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds")


async def enumerate_dns(target: str, timeout: float) -> dict[str, Any]:
    if is_ip(target):
        return {"status": "skipped", "reason": "IP target; forward DNS enumeration requires a hostname", "records": {}}
    try:
        resolver = dns.asyncresolver.Resolver()
    except dns.exception.DNSException as exc:
        return {"status": "error", "error": str(exc), "records": {}}

    async def query(record_type: str) -> tuple[str, dict[str, Any]]:
        try:
            answer = await resolver.resolve(target, record_type, lifetime=timeout, search=False)
            result = {"status": "ok", "values": sorted(record.to_text() for record in answer)}
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


async def resolve_addresses(target: str, timeout: float) -> dict[str, Any]:
    if is_ip(target):
        return {"status": "ok", "addresses": [target], "truncated": False}
    try:
        addresses = await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(target, None, type=socket.SOCK_STREAM),
            timeout=timeout,
        )
    except asyncio.TimeoutError:
        return {"status": "timeout", "addresses": [], "error": "Address resolution timed out"}
    except OSError as exc:
        return {"status": "error", "addresses": [], "error": str(exc)}
    unique = sorted({entry[4][0] for entry in addresses}, key=lambda addr: (ipaddress.ip_address(addr).version, addr))
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
                await asyncio.wait_for(
                    asyncio.get_running_loop().sock_connect(connection, endpoint),
                    timeout=timeout,
                )
            result["status"] = "open"
        except asyncio.TimeoutError:
            result.update(status="timeout", error="TCP connect timed out; filtered or unreachable")
        except OSError as exc:
            if exc.errno == errno.ECONNREFUSED:
                result["status"] = "closed"
            else:
                result.update(status="error", error=str(exc))
        result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


async def scan_ports(target: str, timeout: float, concurrency: int) -> dict[str, Any]:
    resolution = await resolve_addresses(target, timeout)
    if resolution["status"] != "ok":
        return {"status": "error", "resolution": resolution, "results": []}
    semaphore = asyncio.Semaphore(concurrency)
    results = await asyncio.gather(
        *(probe_port(address, port, timeout, semaphore) for address in resolution["addresses"] for port in COMMON_PORTS)
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


async def fetch_http(session: aiohttp.ClientSession, url: str) -> dict[str, Any]:
    result: dict[str, Any] = {"url": url}
    started = time.monotonic()
    try:
        # GET supports servers that reject HEAD. Stop after headers; do not read a body.
        async with session.get(url, allow_redirects=False) as response:
            security, technologies = analyze_headers(response.headers, response.url.scheme)
            result.update(
                status="ok",
                status_code=response.status,
                reason=response.reason,
                headers=[{"name": name, "value": value} for name, value in response.headers.items()],
                security_headers=security,
                technologies=technologies,
                redirect_location=response.headers.get("Location") if 300 <= response.status < 400 else None,
            )
            response.close()
    except asyncio.TimeoutError:
        result.update(status="timeout", error="HTTP request timed out")
    except aiohttp.ClientSSLError as exc:
        result.update(status="tls_error", error=str(exc))
    except (aiohttp.ClientError, OSError) as exc:
        result.update(status="error", error=str(exc))
    result["elapsed_ms"] = round((time.monotonic() - started) * 1000, 2)
    return result


async def scan_http(target: str, timeout: float) -> dict[str, Any]:
    connector = aiohttp.TCPConnector(limit=2, limit_per_host=2)
    async with aiohttp.ClientSession(
        connector=connector,
        timeout=aiohttp.ClientTimeout(total=timeout),
        headers={"User-Agent": f"NetScope/{VERSION}"},
        cookie_jar=aiohttp.DummyCookieJar(),
        trust_env=True,
        auto_decompress=False,
    ) as session:
        results = await asyncio.gather(
            *(fetch_http(session, f"{scheme}://{url_host(target)}/") for scheme in ("https", "http"))
        )
    successes = sum(result["status"] == "ok" for result in results)
    return {"status": "ok" if successes == 2 else "partial" if successes else "error", "results": results}


async def scan_target(target: str, timeout: float = 5.0, concurrency: int = 32) -> dict[str, Any]:
    """Scan a single validated target; retain independent failures in the report."""
    target = normalize_target(target)
    if not 0.1 <= timeout <= 120:
        raise ValueError("timeout must be between 0.1 and 120 seconds")
    if not 1 <= concurrency <= 256:
        raise ValueError("concurrency must be between 1 and 256")
    started = time.monotonic()
    started_at = utc_now()
    dns_result, ports, http = await asyncio.gather(
        enumerate_dns(target, timeout),
        scan_ports(target, timeout, concurrency),
        scan_http(target, timeout),
    )
    usable = (
        ports["resolution"]["status"] == "ok"
        or any(record["status"] == "ok" for record in dns_result["records"].values())
        or any(result["status"] == "ok" for result in http["results"])
    )
    status = (
        "failed"
        if not usable
        else "partial"
        if any(section["status"] not in {"ok", "skipped"} for section in (dns_result, ports, http))
        else "completed"
    )
    return {
        "schema_version": SCHEMA_VERSION,
        "tool": {"name": "NetScope", "version": VERSION},
        "target": target,
        "target_type": "ip" if is_ip(target) else "hostname",
        "started_at": started_at,
        "finished_at": utc_now(),
        "duration_seconds": round(time.monotonic() - started, 3),
        "status": status,
        "settings": {"timeout_seconds": timeout, "tcp_concurrency": concurrency, "ports": list(COMMON_PORTS)},
        "dns": dns_result,
        "ports": ports,
        "http": http,
    }
