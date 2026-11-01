"""Decision-backend selection.

This is separate from the legacy generation/vision selector.  ``auto`` prefers
Laya when the package and router configuration are available, falls back to the
legacy semantic path only when the caller says it exists, and otherwise returns
an explicit degraded selection.  A missing required decision backend never
silently becomes a clean scan.
"""

from __future__ import annotations

from dataclasses import dataclass

from skill_sentry.core.config import DecisionSettings, SkillsEntryConfig
from skill_sentry.core.decisions.base import DecisionClient, DecisionUnavailable
from skill_sentry.core.decisions.laya import LayaDecisionClient


@dataclass(frozen=True)
class DecisionSelection:
    """Result of decision-backend selection.

    ``client`` is set only for a typed decision backend.  ``backend`` may be
    ``laya``, ``legacy``, or ``none`` so callers can route the legacy semantic
    analyzer separately and record the degraded reason.
    """

    client: DecisionClient | None
    backend: str
    degraded: bool = False
    reason: str | None = None
    required: bool = False

    @property
    def available(self) -> bool:
        return self.client is not None


def select_decision_model(
    config: SkillsEntryConfig | DecisionSettings | None = None,
    *,
    backend: str | None = None,
    probe: bool = True,
    laya_client: DecisionClient | None = None,
    legacy_available: bool = False,
) -> DecisionSelection:
    """Return the typed decision backend or an explicit fallback/degradation.

    ``auto`` prefers Laya if it imports and its router can be constructed.  It
    does not load checkpoint weights; the first :meth:`decide` call does that
    and any load failure becomes a degraded stage.  Explicit ``laya`` fails
    closed with :class:`DecisionUnavailable` when the health probe fails.
    """

    settings = _decision_settings(config)
    choice = _backend_value(backend if backend is not None else settings.backend)
    required = settings.required

    if choice == "none":
        return DecisionSelection(
            client=None,
            backend="none",
            degraded=True,
            reason="decision backend disabled; semantic analysis is deterministic-only",
            required=required,
        )
    if choice == "legacy":
        return DecisionSelection(
            client=None,
            backend="legacy",
            degraded=not legacy_available,
            reason=None if legacy_available else "legacy semantic model is not available",
            required=required,
        )
    if choice not in {"auto", "laya"}:
        raise ValueError(f"unsupported decision backend: {choice!r}")

    client = laya_client or LayaDecisionClient(settings)
    healthy = True if not probe else _healthy(client)
    if healthy:
        return DecisionSelection(
            client=client,
            backend="laya",
            degraded=False,
            required=required,
        )

    error = _failure_detail(client)
    if choice == "laya":
        raise DecisionUnavailable(f"laya decision backend is not available: {error}")

    if required:
        return DecisionSelection(
            client=None,
            backend="none",
            degraded=True,
            reason=f"laya is required but unavailable: {error}",
            required=True,
        )
    if legacy_available:
        return DecisionSelection(
            client=None,
            backend="legacy",
            degraded=False,
            reason=f"laya unavailable; using legacy semantic path: {error}",
            required=required,
        )
    return DecisionSelection(
        client=None,
        backend="none",
        degraded=True,
        reason=f"no decision backend available: {error}",
        required=required,
    )


def _decision_settings(
    config: SkillsEntryConfig | DecisionSettings | None,
) -> DecisionSettings:
    if config is None:
        return DecisionSettings()
    if isinstance(config, DecisionSettings):
        return config
    return config.decision


def _backend_value(value: str) -> str:
    normalised = str(value).strip().lower()
    return {
        "laya-local": "laya",
        "local": "laya",
        "off": "none",
        "disabled": "none",
    }.get(normalised, normalised)


def _healthy(client: DecisionClient) -> bool:
    try:
        return bool(client.health())
    except Exception:
        return False


def _failure_detail(client: DecisionClient) -> str:
    detail = getattr(client, "last_error", None)
    if isinstance(detail, str) and detail.strip():
        return detail
    return "health probe failed"


__all__ = ["DecisionSelection", "select_decision_model"]
