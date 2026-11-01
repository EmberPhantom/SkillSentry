"""Build the Attacker Profile / ``activeDefense`` block from confirmed evidence."""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import datetime
from typing import Any
from urllib.parse import urlsplit

from skill_sentry.core.contracts import (
    ActiveDefense,
    ContextCanary,
    ExfilChannel,
    Finding,
    FindingEvidence,
    Severity,
    Stage,
)
from skill_sentry.core.evasion.detector import EvasionResult
from skill_sentry.core.poisoned_well.canary_gen import CanarySet
from skill_sentry.core.poisoned_well.exfil_tracker import Correlation

_IPV4_RE = re.compile(r"^(?:\d{1,3}\.){3}\d{1,3}$")


@dataclass(frozen=True)
class IOC:
    ioc_type: str
    value: str
    channel: str
    first_seen: datetime
    confirmed: bool = True


@dataclass(frozen=True)
class AttackerProfile:
    triggered: bool
    declared_intent: str
    actual_behavior: str
    context_aware_canary: ContextCanary
    targeted_assets: tuple[str, ...] = ()
    exfil_channel: ExfilChannel | None = None
    canary_marker: str | None = None
    secondary_canary: str | None = None
    encoding: str | None = None
    c2_indicators: tuple[str, ...] = ()
    evasion_detected: bool = False
    iocs: tuple[IOC, ...] = ()
    ioc_export: str | None = None
    probe_targets: tuple[str, ...] = ()

    def to_active_defense(self) -> ActiveDefense:
        return ActiveDefense(
            triggered=self.triggered,
            targeted_assets=list(self.targeted_assets),
            exfil_channel=self.exfil_channel,
            canary_marker=self.canary_marker,
            secondary_canary=self.secondary_canary,
            c2_indicators=list(self.c2_indicators),
            encoding=self.encoding,
            sandbox_evasion_detected=self.evasion_detected,
            declared_intent=self.declared_intent or None,
            context_aware_canary=self.context_aware_canary,
            actual_behavior=self.actual_behavior or None,
            ioc_export=self.ioc_export,
        )

    def to_finding(self) -> Finding | None:
        if not self.triggered:
            return None
        if self.exfil_channel is not None:
            message = (
                f"Poisoned Well confirmed exfiltration of {', '.join(self.targeted_assets)} "
                f"via {self.exfil_channel.value}."
            )
            finding_type = "canary-exfiltration"
        else:
            message = f"Sandbox evasion probes detected: {', '.join(self.probe_targets)}."
            finding_type = "sandbox-evasion"
        return Finding(
            stage=Stage.POISONED_WELL if self.exfil_channel else Stage.EVASION,
            severity=Severity.CRITICAL,
            message=message,
            finding_type=finding_type,
            evidence=FindingEvidence(
                marker=self.canary_marker,
                channel=self.exfil_channel.value if self.exfil_channel else None,
                c2=self.c2_indicators[0] if self.c2_indicators else None,
                path=self.targeted_assets[0] if self.targeted_assets else None,
                **{
                    "targetedAssets": list(self.targeted_assets),
                    "encoding": self.encoding,
                    "probes": list(self.probe_targets),
                },
            ),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "triggered": self.triggered,
            "declaredIntent": self.declared_intent,
            "actualBehavior": self.actual_behavior,
            "contextAwareCanary": self.context_aware_canary.value,
            "targetedAssets": list(self.targeted_assets),
            "exfilChannel": self.exfil_channel.value if self.exfil_channel else None,
            "canaryMarker": self.canary_marker,
            "secondaryCanary": self.secondary_canary,
            "encoding": self.encoding,
            "c2Indicators": list(self.c2_indicators),
            "sandboxEvasionDetected": self.evasion_detected,
            "iocExport": self.ioc_export,
            "iocs": [
                {
                    "type": ioc.ioc_type,
                    "value": ioc.value,
                    "channel": ioc.channel,
                    "firstSeen": ioc.first_seen.isoformat(),
                    "confirmed": ioc.confirmed,
                }
                for ioc in self.iocs
            ],
        }


def _ioc_type(value: str) -> str:
    if _IPV4_RE.match(value):
        return "ipv4-addr"
    if value.startswith(("http://", "https://")):
        return "url"
    return "domain-name"


def _iocs_for(correlation: Correlation) -> tuple[IOC, ...]:
    channel = correlation.observation.protocol
    seen: set[tuple[str, str]] = set()
    iocs: list[IOC] = []
    for value in correlation.c2_indicators:
        key = (_ioc_type(value), value)
        if key in seen:
            continue
        seen.add(key)
        iocs.append(
            IOC(
                ioc_type=key[0],
                value=value,
                channel=channel,
                first_seen=correlation.observation.ts,
                confirmed=True,
            )
        )
    # Capture the full URL for an HTTP exfil as well as its hostname, when it
    # carries a path that may be useful to a responder.
    if observation_url := correlation.observation.query_or_url:
        try:
            parsed = urlsplit(observation_url)
        except ValueError:
            parsed = None
        if parsed is not None and parsed.netloc and parsed.path not in {"", "/"}:
            key = ("url", observation_url)
            if key not in seen:
                seen.add(key)
                iocs.append(
                    IOC(
                        ioc_type="url",
                        value=observation_url,
                        channel=channel,
                        first_seen=correlation.observation.ts,
                        confirmed=True,
                    )
                )
    return tuple(iocs)


def build_attacker_profile(
    canaries: CanarySet,
    *,
    correlation: Correlation | None = None,
    evasion: EvasionResult | None = None,
    secondary_served: bool = False,
    ioc_export: str | None = None,
) -> AttackerProfile:
    """Assemble the profile from whichever hard evidence was confirmed."""

    evasion_detected = bool(evasion and evasion.detected)
    triggered = bool(correlation and correlation.matched) or evasion_detected
    targeted_assets: tuple[str, ...] = ()
    exfil_channel: ExfilChannel | None = None
    marker: str | None = None
    encoding: str | None = None
    c2: tuple[str, ...] = ()
    iocs: tuple[IOC, ...] = ()
    probe_targets = evasion.targets if evasion else ()

    if correlation and correlation.matched:
        targeted_assets = correlation.targeted_assets
        exfil_channel = correlation.channel
        marker = correlation.marker
        encoding = correlation.encoding
        c2 = correlation.c2_indicators
        iocs = _iocs_for(correlation)
        c2_text = ", ".join(c2) or "the sinkhole"
        actual_behavior = (
            f"Read {', '.join(targeted_assets) or 'a seeded canary'} and sent the "
            f"{marker} marker to {c2_text} via {exfil_channel.value} "
            f"({encoding or 'raw'} encoding)."
        )
    elif evasion_detected:
        actual_behavior = (
            f"Probed the environment for sandbox/VM artifacts: {', '.join(probe_targets)}."
        )
    else:
        actual_behavior = "No canary read, exfiltration, or sandbox probe observed."

    return AttackerProfile(
        triggered=triggered,
        declared_intent=canaries.declared_intent,
        actual_behavior=actual_behavior,
        context_aware_canary=canaries.intent,
        targeted_assets=targeted_assets,
        exfil_channel=exfil_channel,
        canary_marker=marker,
        secondary_canary=canaries.secondary_marker if secondary_served else None,
        encoding=encoding,
        c2_indicators=c2,
        evasion_detected=evasion_detected,
        iocs=iocs,
        ioc_export=ioc_export,
        probe_targets=probe_targets,
    )
