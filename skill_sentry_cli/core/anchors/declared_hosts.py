"""Declared network destinations from a skill's explicit permissions.

Only ``permissions.network`` and ``network.hosts`` are read.  Free-text metadata
such as ``homepage``, ``api`` or ``endpoints`` is written by the skill author, so
a malicious skill could list its own exfiltration host there.  Those fields are
therefore never treated as a declaration.

A declared host lowers the severity of a credential flow to MEDIUM.  It never
clears the finding: declared destinations are still reported for review.
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any
from urllib.parse import urlparse


def _extract_host(item: str) -> str | None:
    """Return the lower-case hostname from a URL, host, or host:port string."""

    item = item.strip()
    if not item:
        return None
    if "://" in item:
        parsed = urlparse(item)
        host = parsed.hostname or parsed.netloc
    elif "/" in item:
        parsed = urlparse(f"http://{item}")
        host = parsed.hostname or parsed.netloc
    else:
        host = item.split(":")[0]
    host = (host or "").lower().strip()
    return host or None


def _collect(values: Any, into: set[str]) -> None:
    if isinstance(values, str):
        host = _extract_host(values)
        if host:
            into.add(host)
    elif isinstance(values, list):
        for item in values:
            if isinstance(item, str):
                host = _extract_host(item)
                if host:
                    into.add(host)


def extract_declared_hosts(frontmatter: dict[str, Any] | None) -> set[str]:
    """Return the hosts the skill declares through explicit network permissions."""

    if not isinstance(frontmatter, dict):
        return set()
    declared: set[str] = set()
    permissions = frontmatter.get("permissions")
    if isinstance(permissions, dict):
        _collect(permissions.get("network"), declared)
    network = frontmatter.get("network")
    if isinstance(network, dict):
        _collect(network.get("hosts"), declared)
    return declared


def is_host_declared(candidate: str, declared_hosts: Iterable[str]) -> bool:
    """True when ``candidate`` is a declared host or a subdomain of one."""

    host = _extract_host(candidate)
    if not host:
        return False
    for declared in declared_hosts:
        declared = declared.lower().strip()
        if host == declared or host.endswith("." + declared):
            return True
    return False


__all__ = ["extract_declared_hosts", "is_host_declared"]
