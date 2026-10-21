"""Ephemeral Docker sandbox, masquerade, canary filesystem, and sinkholes.

Public objects are resolved lazily so importing a narrow helper (for example
``skillsentry.core.sandbox.monitor``) never pulls in the Docker SDK or creates
an import cycle with the Poisoned Well package.
"""

from __future__ import annotations

import importlib
from typing import Any

__all__ = [
    "CanarySet",
    "DnsQuery",
    "DnsSinkhole",
    "FakeHttpResponder",
    "HttpObservation",
    "MasqueradeCheck",
    "MasqueradeConfig",
    "MasqueradeError",
    "MasqueradeUnavailable",
    "MonitorEvent",
    "SandboxConfig",
    "SandboxError",
    "SandboxRequest",
    "SandboxResult",
    "SandboxRunner",
    "SandboxUnavailable",
    "build_canary_tar",
    "build_honeypot",
    "runtime_environment",
]

_LAZY: dict[str, tuple[str, str]] = {
    "CanarySet": ("skillsentry.core.poisoned_well.canary_gen", "CanarySet"),
    "DnsSinkhole": ("skillsentry.core.sandbox.dns_sinkhole", "DnsSinkhole"),
    "DnsQuery": ("skillsentry.core.sandbox.dns_sinkhole", "DnsQuery"),
    "FakeHttpResponder": ("skillsentry.core.sandbox.fake_http", "FakeHttpResponder"),
    "HttpObservation": ("skillsentry.core.sandbox.fake_http", "HttpObservation"),
    "MasqueradeCheck": ("skillsentry.core.sandbox.masquerade", "MasqueradeCheck"),
    "MasqueradeConfig": ("skillsentry.core.sandbox.masquerade", "MasqueradeConfig"),
    "MasqueradeError": ("skillsentry.core.sandbox.masquerade", "MasqueradeError"),
    "MasqueradeUnavailable": ("skillsentry.core.sandbox.masquerade", "MasqueradeUnavailable"),
    "MonitorEvent": ("skillsentry.core.sandbox.monitor", "MonitorEvent"),
    "SandboxConfig": ("skillsentry.core.sandbox.runner", "SandboxConfig"),
    "SandboxError": ("skillsentry.core.sandbox.runner", "SandboxError"),
    "SandboxRequest": ("skillsentry.core.sandbox.runner", "SandboxRequest"),
    "SandboxResult": ("skillsentry.core.sandbox.runner", "SandboxResult"),
    "SandboxRunner": ("skillsentry.core.sandbox.runner", "SandboxRunner"),
    "SandboxUnavailable": ("skillsentry.core.sandbox.runner", "SandboxUnavailable"),
    "build_canary_tar": ("skillsentry.core.sandbox.canary_fs", "build_canary_tar"),
    "build_honeypot": ("skillsentry.core.sandbox.context_honeypot", "build_honeypot"),
    "runtime_environment": (
        "skillsentry.core.sandbox.context_honeypot",
        "runtime_environment",
    ),
}


def __getattr__(name: str) -> Any:
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
    module_name, attribute = target
    value = getattr(importlib.import_module(module_name), attribute)
    globals()[name] = value
    return value
