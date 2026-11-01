"""Ephemeral Docker sandbox, masquerade, canary filesystem, and sinkholes.

Public objects are resolved lazily so importing a narrow helper (for example
``skill_sentry_cli.core.sandbox.monitor``) never pulls in the Docker SDK or creates
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
    "SinkholeConfig",
    "SinkholeObservation",
    "SinkholeSidecar",
    "build_canary_tar",
    "build_honeypot",
    "runtime_environment",
]

_LAZY: dict[str, tuple[str, str]] = {
    "CanarySet": ("skill_sentry_cli.core.poisoned_well.canary_gen", "CanarySet"),
    "DnsSinkhole": ("skill_sentry_cli.core.sandbox.dns_sinkhole", "DnsSinkhole"),
    "DnsQuery": ("skill_sentry_cli.core.sandbox.dns_sinkhole", "DnsQuery"),
    "FakeHttpResponder": ("skill_sentry_cli.core.sandbox.fake_http", "FakeHttpResponder"),
    "HttpObservation": ("skill_sentry_cli.core.sandbox.fake_http", "HttpObservation"),
    "MasqueradeCheck": ("skill_sentry_cli.core.sandbox.masquerade", "MasqueradeCheck"),
    "MasqueradeConfig": ("skill_sentry_cli.core.sandbox.masquerade", "MasqueradeConfig"),
    "MasqueradeError": ("skill_sentry_cli.core.sandbox.masquerade", "MasqueradeError"),
    "MasqueradeUnavailable": ("skill_sentry_cli.core.sandbox.masquerade", "MasqueradeUnavailable"),
    "MonitorEvent": ("skill_sentry_cli.core.sandbox.monitor", "MonitorEvent"),
    "SandboxConfig": ("skill_sentry_cli.core.sandbox.runner", "SandboxConfig"),
    "SandboxError": ("skill_sentry_cli.core.sandbox.runner", "SandboxError"),
    "SandboxRequest": ("skill_sentry_cli.core.sandbox.runner", "SandboxRequest"),
    "SandboxResult": ("skill_sentry_cli.core.sandbox.runner", "SandboxResult"),
    "SandboxRunner": ("skill_sentry_cli.core.sandbox.runner", "SandboxRunner"),
    "SandboxUnavailable": ("skill_sentry_cli.core.sandbox.runner", "SandboxUnavailable"),
    "SinkholeConfig": ("skill_sentry_cli.core.sandbox.sidecar", "SinkholeConfig"),
    "SinkholeObservation": ("skill_sentry_cli.core.sandbox.sidecar", "SinkholeObservation"),
    "SinkholeSidecar": ("skill_sentry_cli.core.sandbox.sidecar", "SinkholeSidecar"),
    "build_canary_tar": ("skill_sentry_cli.core.sandbox.canary_fs", "build_canary_tar"),
    "build_honeypot": ("skill_sentry_cli.core.sandbox.context_honeypot", "build_honeypot"),
    "runtime_environment": (
        "skill_sentry_cli.core.sandbox.context_honeypot",
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
