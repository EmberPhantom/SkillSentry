"""Extraction and matching of declared network destinations from skill frontmatter."""

from __future__ import annotations

import re
from typing import Any, Iterable, Set
from urllib.parse import urlparse


def _extract_host(item: str) -> str | None:
    """Extracts hostname from a URL, host string, or host:port."""
    item = item.strip()
    if not item:
        return None
    if "://" in item:
        parsed = urlparse(item)
        host = parsed.hostname or parsed.netloc
    else:
        # Might be "api.github.com:443" or "api.github.com" or "http://..."
        if "/" in item:
            parsed = urlparse(f"http://{item}")
            host = parsed.hostname or parsed.netloc
        else:
            host = item.split(":")[0]
    if host:
        return host.lower().strip()
    return None


def extract_declared_hosts(frontmatter: dict[str, Any] | None) -> set[str]:
    """Extracts all declared hosts strictly from frontmatter metadata.
    
    Reads only structured fields (e.g. permissions.network, allowed-hosts, network.hosts,
    homepage, api, endpoints). Never reads body text.
    """
    if not isinstance(frontmatter, dict):
        return set()

    declared: Set[str] = set()

    # 1. permissions.network
    perms = frontmatter.get("permissions")
    if isinstance(perms, dict):
        net = perms.get("network")
        if isinstance(net, list):
            for item in net:
                if isinstance(item, str):
                    h = _extract_host(item)
                    if h:
                        declared.add(h)
        elif isinstance(net, str):
            h = _extract_host(net)
            if h:
                declared.add(h)

    # 2. allowed-hosts / allowed_hosts
    for key in ("allowed-hosts", "allowed_hosts", "hosts"):
        val = frontmatter.get(key)
        if isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    h = _extract_host(item)
                    if h:
                        declared.add(h)
        elif isinstance(val, str):
            h = _extract_host(val)
            if h:
                declared.add(h)

    # 3. network: {hosts: [...]}
    net_val = frontmatter.get("network")
    if isinstance(net_val, dict):
        hosts_list = net_val.get("hosts")
        if isinstance(hosts_list, list):
            for item in hosts_list:
                if isinstance(item, str):
                    h = _extract_host(item)
                    if h:
                        declared.add(h)

    # 4. URLs in metadata fields: homepage, api, endpoints
    for key in ("homepage", "api", "endpoints"):
        val = frontmatter.get(key)
        if isinstance(val, str):
            h = _extract_host(val)
            if h:
                declared.add(h)
        elif isinstance(val, list):
            for item in val:
                if isinstance(item, str):
                    h = _extract_host(item)
                    if h:
                        declared.add(h)

    return declared


def is_host_declared(candidate: str, declared_hosts: Iterable[str]) -> bool:
    """Checks whether candidate host matches any declared host (exact or subdomain suffix)."""
    cand = _extract_host(candidate)
    if not cand:
        return False
    for dec in declared_hosts:
        dec = dec.lower().strip()
        if cand == dec:
            return True
        if cand.endswith("." + dec):
            return True
    return False

