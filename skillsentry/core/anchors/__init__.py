"""Deterministic anchors and taint-lite credential analysis."""

from __future__ import annotations

from skillsentry.core.anchors.credential_flow import (
    CREDENTIAL_RULES_VERSION,
    Floor,
    analyze_credential_flows,
)
from skillsentry.core.anchors.declared_hosts import (
    extract_declared_hosts,
    is_host_declared,
)

__all__ = [
    "CREDENTIAL_RULES_VERSION",
    "Floor",
    "analyze_credential_flows",
    "extract_declared_hosts",
    "is_host_declared",
]

