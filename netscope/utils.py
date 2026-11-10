"""Input validation, safe terminal text, and durable JSON output."""

from __future__ import annotations

import ipaddress
import json
import math
import os
from pathlib import Path
import re
import tempfile
import unicodedata
from typing import Any

VERSION = "1.0.0"
SCHEMA_VERSION = "1.0"
COMMON_PORTS = (21, 22, 80, 443, 8080, 8443)
SERVICES = {21: "FTP", 22: "SSH", 80: "HTTP", 443: "HTTPS", 8080: "HTTP-alt", 8443: "HTTPS-alt"}


def normalize_target(value: str) -> str:
    """Accept one IP literal or DNS hostname; reject URLs, ports, and wildcards."""
    target = value.strip()
    if not target or any(char.isspace() for char in target):
        raise ValueError("target must be one domain or IP address")
    if target.startswith("[") and target.endswith("]"):
        target = target[1:-1]
        try:
            address = ipaddress.IPv6Address(target)
        except ValueError as exc:
            raise ValueError("brackets must contain an IPv6 address") from exc
        if address.scope_id:
            raise ValueError("scoped IPv6 addresses are not supported")
        return address.compressed
    if "%" in target:
        raise ValueError("scoped IPv6 addresses are not supported")
    try:
        return ipaddress.ip_address(target).compressed
    except ValueError:
        pass
    if any(char in target for char in "/:@?#\\[]*"):
        raise ValueError("use a bare domain or IP address, without a URL, port, or path")
    try:
        hostname = target.encode("idna").decode("ascii").lower().removesuffix(".")
    except UnicodeError as exc:
        raise ValueError("target is not a valid internationalized hostname") from exc
    if re.fullmatch(r"[\d.]+", hostname):
        raise ValueError("invalid IPv4 address")
    labels = hostname.split(".")
    if len(hostname) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", label) for label in labels):
        raise ValueError("invalid hostname: use DNS labels of 1–63 letters, digits, or hyphens")
    return hostname


def is_ip(target: str) -> bool:
    try:
        ipaddress.ip_address(target)
        return True
    except ValueError:
        return False


def url_host(target: str) -> str:
    return f"[{target}]" if ":" in target else target


def positive_timeout(value: str) -> float:
    try:
        timeout = float(value)
    except ValueError as exc:
        raise ValueError("timeout must be a number") from exc
    if not math.isfinite(timeout) or not 0.1 <= timeout <= 120:
        raise ValueError("timeout must be between 0.1 and 120 seconds")
    return timeout


def terminal_text(value: object) -> str:
    """Remove terminal controls, including bidi controls, from untrusted values."""
    return "".join(char if not unicodedata.category(char).startswith("C") else " " for char in str(value))


def write_json(report: dict[str, Any], destination: Path) -> Path:
    """Atomically replace a report using a private, same-directory temp file."""
    destination = destination.expanduser().absolute()
    # Parents must exist; a typo should not silently create a directory tree.
    payload = json.dumps(report, indent=2, ensure_ascii=False, allow_nan=False) + "\n"
    temporary: str | None = None
    try:
        with tempfile.NamedTemporaryFile(
            mode="w",
            encoding="utf-8",
            dir=destination.parent,
            prefix=f".{destination.name}.",
            suffix=".tmp",
            delete=False,
        ) as stream:
            temporary = stream.name
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, destination)
    finally:
        if temporary is not None:
            Path(temporary).unlink(missing_ok=True)
    return destination
