"""Decision selector semantics and fail-closed fallbacks."""

from __future__ import annotations

from typing import Any

import pytest
from skill_sentry.core.config import DecisionSettings, default_config
from skill_sentry.core.decisions import (
    DecisionAnswer,
    DecisionQuestion,
    DecisionResult,
    DecisionUnavailable,
    select_decision_model,
)


class _FakeClient:
    backend = "fake"
    model_version = "fake-1"

    def __init__(self, healthy: bool = True, error: str | None = None) -> None:
        self.healthy = healthy
        self.last_error = error

    def decide(
        self,
        state: str | dict[str, Any],
        questions: dict[str, DecisionQuestion],
        *,
        timeout_s: float | None = None,
    ) -> DecisionResult:
        del state, questions, timeout_s
        return DecisionResult(
            answers={"intent": DecisionAnswer(choice="other")},
            backend=self.backend,
            checkpoint="fake",
        )

    def health(self) -> bool:
        return self.healthy


def test_auto_selects_healthy_laya():
    client = _FakeClient()
    selection = select_decision_model(DecisionSettings(backend="auto"), laya_client=client)

    assert selection.available is True
    assert selection.client is client
    assert selection.backend == "laya"
    assert selection.degraded is False


def test_explicit_laya_fails_closed_when_unhealthy():
    client = _FakeClient(healthy=False, error="checkpoint load failed")

    with pytest.raises(DecisionUnavailable, match="checkpoint load failed"):
        select_decision_model(DecisionSettings(backend="laya"), laya_client=client)


def test_auto_falls_back_to_legacy_when_available():
    client = _FakeClient(healthy=False, error="laya missing")
    selection = select_decision_model(
        DecisionSettings(backend="auto"),
        laya_client=client,
        legacy_available=True,
    )

    assert selection.client is None
    assert selection.backend == "legacy"
    assert selection.degraded is False
    assert "laya missing" in (selection.reason or "")


def test_auto_without_any_backend_is_degraded():
    selection = select_decision_model(
        DecisionSettings(backend="auto"),
        laya_client=_FakeClient(healthy=False),
        legacy_available=False,
    )

    assert selection.client is None
    assert selection.backend == "none"
    assert selection.degraded is True


def test_required_laya_does_not_fall_back_to_legacy():
    selection = select_decision_model(
        DecisionSettings(backend="auto", required=True),
        laya_client=_FakeClient(healthy=False, error="model download failed"),
        legacy_available=True,
    )

    assert selection.client is None
    assert selection.backend == "none"
    assert selection.degraded is True
    assert selection.required is True
    assert "required" in (selection.reason or "")


def test_none_and_legacy_are_explicit_selections():
    none = select_decision_model(DecisionSettings(backend="none"))
    assert none.backend == "none"
    assert none.degraded is True

    legacy = select_decision_model(DecisionSettings(backend="legacy"), legacy_available=True)
    assert legacy.backend == "legacy"
    assert legacy.degraded is False

    unavailable = select_decision_model(DecisionSettings(backend="legacy"), legacy_available=False)
    assert unavailable.backend == "legacy"
    assert unavailable.degraded is True


def test_probe_false_does_not_call_health(monkeypatch: pytest.MonkeyPatch):
    client = _FakeClient(healthy=False)

    def _must_not_run(self: _FakeClient) -> bool:
        raise AssertionError("health should not be called")

    monkeypatch.setattr(_FakeClient, "health", _must_not_run)
    selection = select_decision_model(
        DecisionSettings(backend="auto"),
        laya_client=client,
        probe=False,
    )

    assert selection.client is client
    assert selection.backend == "laya"


def test_config_object_backend_override_and_aliases():
    config = default_config()
    selection = select_decision_model(
        config,
        backend="none",
    )
    assert selection.backend == "none"

    selection = select_decision_model(
        backend="laya-local",
        laya_client=_FakeClient(),
    )
    assert selection.backend == "laya"
