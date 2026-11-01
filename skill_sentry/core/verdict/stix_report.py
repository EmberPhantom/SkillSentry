"""STIX 2.1 IOC bundle writer (docs/05-api-reference.md §5.7)."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any
from uuid import uuid4

from skill_sentry.core.contracts import Verdict, format_utc, utc_now
from skill_sentry.core.version import ENGINE_VERSION

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


class NoIOCsError(RuntimeError):
    """Raised when a STIX export is requested for a scan without IOCs."""


def _pattern_for(value: str) -> tuple[str, str]:
    if value.startswith(("http://", "https://")):
        return "url", f"[url:value = '{value}']"
    if _IPV4_RE.match(value):
        return "ipv4-addr", f"[ipv4-addr:value = '{value}']"
    return "domain-name", f"[domain-name:value = '{value}']"


def _sdo(object_type: str, **fields: Any) -> dict[str, Any]:
    return {"type": object_type, "spec_version": "2.1", "id": f"{object_type}--{uuid4()}", **fields}


def build_stix(verdict: Verdict, *, generated_at: datetime | None = None) -> dict[str, Any]:
    """Build a STIX 2.1 bundle, or raise when active defense did not trigger."""
    active = verdict.active_defense
    if active is None or not active.triggered:
        raise NoIOCsError("no_iocs")
    indicators = [value for value in active.c2_indicators if value]
    if not indicators:
        raise NoIOCsError("no_iocs")

    created = generated_at or utc_now()
    stamp = format_utc(created)
    identity_id = f"identity--{uuid4()}"
    malware_id = f"malware--{uuid4()}"

    objects: list[dict[str, Any]] = [
        _sdo(
            "identity",
            created=stamp,
            modified=stamp,
            name="SkillSentry 2.0",
            description="Local-first Agent Skill supply-chain auditor.",
            identity_class="system",
            x_skillsentry_engine_version=ENGINE_VERSION,
        ),
        _sdo(
            "malware",
            created=stamp,
            modified=stamp,
            created_by_ref=identity_id,
            name=verdict.skill,
            description=(
                f"Agent Skill flagged {verdict.verdict.value} with risk "
                f"{verdict.risk_score}/100. {active.actual_behavior or ''}".strip()
            ),
            is_family=False,
            labels=["malicious-activity"],
            confidence=max(0, min(100, round(verdict.confidence * 100))),
            x_skillsentry_scan_id=str(verdict.scan_id),
            x_skillsentry_skill_id=str(verdict.skill_id),
            x_skillsentry_canary_marker=active.canary_marker,
            x_skillsentry_exfil_channel=(
                active.exfil_channel.value if active.exfil_channel else None
            ),
            x_skillsentry_encoding=active.encoding,
        ),
    ]

    for value in indicators:
        ioc_type, pattern = _pattern_for(value)
        indicator_id = f"indicator--{uuid4()}"
        objects.append(
            _sdo(
                "indicator",
                created=stamp,
                modified=stamp,
                created_by_ref=identity_id,
                name=f"C2 {ioc_type} {value}",
                description=(
                    f"Observed in sandboxed {active.exfil_channel.value if active.exfil_channel else 'egress'} "
                    f"traffic while serving canary {active.canary_marker or 'material'}."
                ),
                indicator_types=["malicious-activity"],
                pattern=pattern,
                pattern_type="stix",
                valid_from=stamp,
                labels=["malicious-activity"],
                confidence=100 if active.triggered else 50,
                x_skillsentry_channel=(
                    active.exfil_channel.value if active.exfil_channel else None
                ),
            )
        )
        objects.append(
            _sdo(
                "relationship",
                created=stamp,
                modified=stamp,
                created_by_ref=identity_id,
                relationship_type="indicates",
                source_ref=malware_id,
                target_ref=indicator_id,
                description=f"{verdict.skill} exfiltrates to {value}",
            )
        )

    return {
        "type": "bundle",
        "id": f"bundle--{uuid4()}",
        "spec_version": "2.1",
        "objects": objects,
        "x_skillsentry_verdict": verdict.verdict.value,
        "x_skillsentry_risk_score": verdict.risk_score,
    }


def build_stix_text(verdict: Verdict, *, generated_at: datetime | None = None) -> str:
    return json.dumps(build_stix(verdict, generated_at=generated_at), indent=2) + "\n"


__all__ = ["NoIOCsError", "build_stix", "build_stix_text"]
