"""Intent-aware context honeypot.

The honeypot answers one question: *what would this skill plausibly be able to
steal?*  A Slack skill gets a Slack token and generic AWS/SSH material; an
unknown skill gets the full set.  Seeding is delegated to
:mod:`skill_sentry_cli.core.poisoned_well.canary_gen` so the marker lifecycle has a
single owner.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from uuid import UUID

from skill_sentry_cli.core.contracts import ContextCanary
from skill_sentry_cli.core.poisoned_well.canary_gen import (
    CANARY_ROOT,
    CanarySet,
    generate_canary_set,
    normalize_intent,
)

INTENT_KEYWORDS: Mapping[ContextCanary, tuple[str, ...]] = {
    ContextCanary.AWS: ("aws", "amazon", "s3", "ec2", "iam", "cloud", "credential"),
    ContextCanary.GITHUB: ("github", "git", "repository", "repo", "pull request"),
    ContextCanary.SLACK: ("slack", "webhook", "notification", "chat", "workspace"),
    ContextCanary.SSH: ("ssh", "devops", "deploy", "server", "remote", "ansible"),
    ContextCanary.GENERIC: (),
}


@dataclass(frozen=True)
class HoneypotPlan:
    """Small, serialisable summary of what the honeypot will seed."""

    intent: ContextCanary
    declared_intent: str
    paths: tuple[str, ...]
    env_keys: tuple[str, ...]
    marker: str

    @classmethod
    def from_canaries(cls, canaries: CanarySet) -> HoneypotPlan:
        return cls(
            intent=canaries.intent,
            declared_intent=canaries.declared_intent,
            paths=tuple(item.display_path for item in canaries.files),
            env_keys=tuple(sorted(canaries.env)),
            marker=canaries.marker,
        )


def classify(declared_intent: str | None) -> ContextCanary:
    return normalize_intent(declared_intent)


def build_honeypot(
    scan_id: UUID,
    declared_intent: str | None,
    *,
    marker: str | None = None,
    secondary_marker: str | None = None,
) -> CanarySet:
    return generate_canary_set(
        scan_id,
        declared_intent,
        marker=marker,
        secondary_marker=secondary_marker,
    )


def runtime_environment(canaries: CanarySet) -> dict[str, str]:
    """Environment for the skill process (canaries + realistic HOME)."""

    env = {
        "HOME": CANARY_ROOT,
        "USER": "nobody",
        "LOGNAME": "nobody",
        "SHELL": "/bin/sh",
        "PATH": "/usr/local/bin:/usr/bin:/bin",
    }
    env.update(canaries.env)
    return env


def plan(declared_intent: str | None) -> HoneypotPlan:
    """Preview the honeypot for a declared intent without consuming a marker."""

    # A preview marker is deterministic and not used for correlation.
    preview = generate_canary_set(
        UUID(int=0),
        declared_intent,
        marker="SKS-00000000",
        secondary_marker="SKS-ffffffff",
    )
    return HoneypotPlan.from_canaries(preview)
