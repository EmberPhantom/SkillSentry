"""Sandbox-evasion probe classification (docs/02 §2.3, docs/04 §4.5).

Any observed probe is hard evidence and produces a ``MALICIOUS`` override with
confidence 1.0.  A masquerade verification failure is *not* a probe and must be
handled as an engine error by the runner; it can never produce a clean verdict.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import PurePosixPath
from typing import Any

from skill_sentry_cli.core.contracts import OverrideSignal, Stage, VerdictTier
from skill_sentry_cli.core.sandbox.monitor import MonitorEvent

PROBE_PATHS: dict[str, str] = {
    "/.dockerenv": "docker_artifact",
    "/proc/1/cgroup": "cgroup_probe",
    "/proc/self/cgroup": "cgroup_probe",
    "/proc/1/mountinfo": "mountinfo_probe",
    "/proc/self/mountinfo": "mountinfo_probe",
    "/proc/bus/input/devices": "vm_artifact",
    "/sys/class/dmi/id/product_name": "vm_artifact",
    "/sys/class/dmi/id/sys_vendor": "vm_artifact",
    "/sys/class/dmi/id/board_vendor": "vm_artifact",
    "/sys/hypervisor/type": "vm_artifact",
    "/dev/kmsg": "kernel_probe",
}

PROBE_COMMANDS: frozenset[str] = frozenset(
    {
        "df",
        "mount",
        "lsblk",
        "systemd-detect-virt",
        "dmidecode",
        "lscpu",
    }
)

_PROBE_PATH_PREFIXES = (
    "/proc/1/cgroup",
    "/proc/self/cgroup",
    "/proc/1/mountinfo",
    "/proc/self/mountinfo",
    "/proc/bus/input",
    "/sys/class/dmi/id/",
    "/sys/hypervisor/",
)


@dataclass(frozen=True)
class ProbeEvent:
    ts: datetime
    kind: str
    target: str
    process: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)


@dataclass(frozen=True)
class EvasionResult:
    detected: bool
    probes: tuple[ProbeEvent, ...] = ()
    masquerade_failed: bool = False
    error: str | None = None

    @property
    def targets(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(probe.target for probe in self.probes))

    @property
    def kinds(self) -> tuple[str, ...]:
        return tuple(dict.fromkeys(probe.kind for probe in self.probes))

    def to_override(self) -> OverrideSignal | None:
        if not self.detected:
            return None
        targets = ", ".join(self.targets)
        return OverrideSignal(
            verdict=VerdictTier.MALICIOUS,
            confidence=1.0,
            reason=f"Sandbox evasion probe detected ({targets}).",
            source=Stage.EVASION,
            evidence={
                "probes": [
                    {
                        "ts": probe.ts.isoformat(),
                        "kind": probe.kind,
                        "target": probe.target,
                        "process": probe.process,
                    }
                    for probe in self.probes
                ],
                "sandboxEvasionDetected": True,
            },
        )

    def summary(self) -> dict[str, Any]:
        return {
            "evasionDetected": self.detected,
            "probes": list(self.targets),
            "probeKinds": list(self.kinds),
            "masqueradeFailed": self.masquerade_failed,
            "error": self.error,
        }

    @classmethod
    def engine_error(cls, message: str) -> EvasionResult:
        return cls(detected=False, masquerade_failed=True, error=message)


def is_probe_path(path: str) -> bool:
    clean = path.rstrip("/") or "/"
    if clean in PROBE_PATHS:
        return True
    return any(clean.startswith(prefix) for prefix in _PROBE_PATH_PREFIXES)


def probe_kind_for_path(path: str) -> str | None:
    clean = path.rstrip("/") or "/"
    if clean in PROBE_PATHS:
        return PROBE_PATHS[clean]
    for prefix in _PROBE_PATH_PREFIXES:
        if clean.startswith(prefix):
            return "vm_artifact" if prefix.startswith("/sys/") else "filesystem_probe"
    return None


def _command_basename(command: str) -> str:
    # Commands may be an argv list flattened by the shim, or a shell string.
    first = command.strip().split()[0] if command.strip() else ""
    return PurePosixPath(first).name


def is_probe_command(command: str) -> bool:
    return _command_basename(command) in PROBE_COMMANDS


def classify_probe(
    target: str,
    *,
    ts: datetime,
    process: str | None = None,
    detail: dict[str, Any] | None = None,
) -> ProbeEvent | None:
    detail = detail or {}
    if detail.get("kind") == "command" or is_probe_command(target):
        base = _command_basename(target)
        if base in PROBE_COMMANDS:
            return ProbeEvent(
                ts=ts,
                kind="command_probe",
                target=base,
                process=process,
                detail=detail,
            )
    if is_probe_path(target):
        return ProbeEvent(
            ts=ts,
            kind=probe_kind_for_path(target) or "filesystem_probe",
            target=target,
            process=process,
            detail=detail,
        )
    return None


def detect_probes(events: list[MonitorEvent]) -> EvasionResult:
    probes: list[ProbeEvent] = []
    seen: set[tuple[str, str]] = set()
    for event in events:
        target = event.path_or_channel
        if not target:
            continue
        if event.event_type == "probe_detected":
            probe = classify_probe(
                target,
                ts=event.ts,
                process=event.process,
                detail=event.detail,
            )
        else:
            # Defence in depth: a shim version that logs an open instead of a
            # probe event is still treated as a probe.
            probe = classify_probe(
                target,
                ts=event.ts,
                process=event.process,
                detail=event.detail,
            )
        if probe is None:
            continue
        key = (probe.kind, probe.target)
        if key in seen:
            continue
        seen.add(key)
        probes.append(probe)
    probes.sort(key=lambda probe: probe.ts)
    return EvasionResult(detected=bool(probes), probes=tuple(probes))


def probe_summary_pattern() -> re.Pattern[str]:
    """Readable pattern used by docs/tests to keep the probe list discoverable."""

    names = "|".join(sorted(re.escape(name) for name in PROBE_COMMANDS))
    return re.compile(rf"(^|[;&|]\s*)(?:{names})(\s|$)")
