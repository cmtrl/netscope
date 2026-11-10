"""Shared async DNS and HTTP resolution, including local hosts-file entries."""

from __future__ import annotations

import asyncio
from contextlib import asynccontextmanager
import ipaddress
import os
from pathlib import Path
import socket
from typing import Any

import aiohttp.abc
import dns.asyncresolver
import dns.exception


def read_hosts() -> dict[str, list[str]]:
    path = (
        Path(os.environ.get("SystemRoot", r"C:\Windows")) / "System32/drivers/etc/hosts"
        if os.name == "nt"
        else Path("/etc/hosts")
    )
    hosts: dict[str, list[str]] = {}
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        lines = []
    for line in lines:
        fields = line.split("#", 1)[0].split()
        if len(fields) < 2:
            continue
        try:
            parsed = ipaddress.ip_address(fields[0])
            if getattr(parsed, "scope_id", None):
                continue
            address = parsed.compressed
        except ValueError:
            continue
        for name in fields[1:]:
            hosts.setdefault(name.lower().rstrip("."), []).append(address)
    # localhost must never depend on an external DNS server.
    hosts.setdefault("localhost", ["127.0.0.1", "::1"])
    return hosts


class AsyncResolver(aiohttp.abc.AbstractResolver):
    """One bounded task per DNS question, shared by enumeration and connections."""

    def __init__(self, timeout: float):
        self.timeout = timeout
        self.hosts = read_hosts()
        self._resolver: dns.asyncresolver.Resolver | None = None
        self._queries: dict[tuple[str, str], asyncio.Task[Any]] = {}

    async def query(self, host: str, record_type: str) -> Any:
        key = (host.lower().rstrip("."), record_type)
        if key not in self._queries:
            if self._resolver is None:
                self._resolver = dns.asyncresolver.Resolver()

            async def perform_query():
                # Construct the inner coroutine only after the owning task starts.
                # Immediate cancellation must not leave an unawaited coroutine.
                return await asyncio.wait_for(
                    self._resolver.resolve(host, record_type, lifetime=self.timeout, search=False), self.timeout
                )

            self._queries[key] = asyncio.create_task(perform_query())
        # One consumer timing out must not cancel another consumer's DNS query.
        return await asyncio.shield(self._queries[key])

    async def resolve(self, host: str, port: int = 0, family: int = socket.AF_INET) -> list[dict[str, Any]]:
        try:
            addresses = [ipaddress.ip_address(host).compressed]
        except ValueError:
            name = host.lower().rstrip(".")
            addresses = self.hosts.get(name, self.hosts["localhost"] if name.endswith(".localhost") else [])
        if not addresses:
            kinds = ("A",) if family == socket.AF_INET else ("AAAA",) if family == socket.AF_INET6 else ("A", "AAAA")
            answers = await asyncio.gather(*(self.query(host, kind) for kind in kinds), return_exceptions=True)
            addresses = [
                record.address for answer in answers if not isinstance(answer, BaseException) for record in answer
            ]
            if not addresses:
                timeouts = any(isinstance(answer, (dns.exception.Timeout, asyncio.TimeoutError)) for answer in answers)
                if timeouts:
                    raise asyncio.TimeoutError("DNS resolution timed out")
                raise socket.gaierror(socket.EAI_NONAME, f"No usable addresses for {host}")
        results = []
        for address in dict.fromkeys(addresses):
            address_family = socket.AF_INET6 if ":" in address else socket.AF_INET
            if family not in (socket.AF_UNSPEC, address_family):
                continue
            results.append(
                {
                    "hostname": host,
                    "host": address,
                    "port": port,
                    "family": address_family,
                    "proto": socket.IPPROTO_TCP,
                    "flags": socket.AI_NUMERICHOST,
                }
            )
        if not results:
            raise socket.gaierror(socket.EAI_NONAME, f"No addresses in the requested family for {host}")
        return results

    async def close(self) -> None:
        for task in self._queries.values():
            if not task.done():
                task.cancel()
        if self._queries:
            await asyncio.gather(*self._queries.values(), return_exceptions=True)


@asynccontextmanager
async def resolver_context(timeout: float, resolver: AsyncResolver | None):
    owned = resolver is None
    resolver = resolver if resolver is not None else AsyncResolver(timeout)
    try:
        yield resolver
    finally:
        if owned:
            await resolver.close()
