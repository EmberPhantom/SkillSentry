"""Laya adapter: lazy loading, response mapping, timeout, and fail-closed paths."""

from __future__ import annotations

import time
from types import SimpleNamespace
from typing import Any

import pytest
from skill_sentry_cli.core.config import DecisionSettings
from skill_sentry_cli.core.decisions import (
    DecisionQuestion,
    DecisionUnavailable,
    LayaDecisionClient,
)


class _FakeRouter:
    def __init__(
        self,
        response: Any = None,
        *,
        delay_s: float = 0.0,
        error: Exception | None = None,
    ) -> None:
        self.response = response
        self.delay_s = delay_s
        self.error = error
        self.calls: list[tuple[Any, dict[str, Any], dict[str, Any]]] = []
        self.unloaded = False

    def predict(self, state: Any, questions: dict[str, Any], **kwargs: Any) -> Any:
        self.calls.append((state, questions, kwargs))
        if self.delay_s:
            time.sleep(self.delay_s)
        if self.error is not None:
            raise self.error
        return self.response

    def unload(self) -> None:
        self.unloaded = True


def _questions() -> dict[str, DecisionQuestion]:
    return {
        "intent": DecisionQuestion(
            type="choice",
            instructions="Which category?",
            criteria={"billing": "payments", "technical": "bugs"},
        ),
        "urgency": DecisionQuestion(
            type="score",
            instructions="How urgent?",
            criteria=["low", "high"],
        ),
        "cap_network": DecisionQuestion(
            type="noul",
            instructions="Does it use the network?",
            min_confidence=0.75,
        ),
    }


def _response() -> dict[str, Any]:
    return {
        "answers": {
            "intent": {
                "type": "choice",
                "choice": "billing",
                "probabilities": {"billing": 0.8, "technical": 0.2},
                "confidence": 0.4,
                "answer_confidence": 0.8,
            },
            "urgency": {
                "type": "score",
                "score": 1.0,
                "probabilities": [0.1, 0.9],
                "confidence": 0.7,
            },
            "cap_network": {
                "type": "noul",
                "noul": 0.9,
                "confidence": 0.9,
                "abstention": "passed",
            },
        },
        "routing": {"model": "multilingual", "reason": "non-English text"},
        "usage": {"input_tokens": 10, "output_tokens": 3},
    }


def _client(
    router: _FakeRouter,
    *,
    settings: DecisionSettings | None = None,
    checkpoint: str | None = None,
) -> LayaDecisionClient:
    return LayaDecisionClient(
        settings or DecisionSettings(),
        checkpoint=checkpoint,
        router=router,
        laya_module=SimpleNamespace(__version__="0.4.17"),
    )


def test_maps_typed_response_and_pins_checkpoint():
    router = _FakeRouter(_response())
    client = _client(router, checkpoint="multilingual")

    result = client.decide("Please refund this invoice", _questions())

    assert result.backend == "laya"
    assert result.checkpoint == "multilingual"
    assert result.model_version == "laya-0.4.17"
    assert result.answers["intent"].choice == "billing"
    assert result.answers["intent"].confidence == 0.8
    assert result.answers["urgency"].score == 1.0
    assert result.answers["cap_network"].noul == 0.9
    assert result.answers["cap_network"].abstention is False
    assert result.usage == {"input_tokens": 10, "output_tokens": 3}

    _, sent_questions, kwargs = router.calls[0]
    assert sent_questions["cap_network"] == {
        "type": "noul",
        "instructions": "Does it use the network?",
    }
    assert kwargs["model"] == "multilingual"
    assert kwargs["max_len"] == 1024
    assert kwargs["head_max_len"] == 256
    assert kwargs["min_confidence"] == 0.75


def test_abstention_string_is_preserved_with_the_raw_primitive():
    response = _response()
    response["answers"]["intent"]["abstention"] = "abstained"
    router = _FakeRouter(response)

    result = _client(router).decide("x", _questions())

    answer = result.answers["intent"]
    assert answer.abstention is True
    assert answer.choice == "billing"


def test_unexpected_answer_ids_fail_closed():
    response = _response()
    del response["answers"]["urgency"]
    router = _FakeRouter(response)

    with pytest.raises(DecisionUnavailable, match="question mismatch"):
        _client(router).decide("x", _questions())


def test_unknown_choice_label_fails_closed():
    response = _response()
    response["answers"]["intent"]["choice"] = "invented"
    router = _FakeRouter(response)

    with pytest.raises(DecisionUnavailable, match="unknown label"):
        _client(router).decide("x", _questions())


def test_malformed_probabilities_and_confidence_fail_closed():
    response = _response()
    response["answers"]["intent"]["probabilities"] = {"billing": 1.4, "technical": 0.2}
    response["answers"]["intent"]["answer_confidence"] = 1.2
    router = _FakeRouter(response)

    with pytest.raises(DecisionUnavailable, match="malformed"):
        _client(router).decide("x", _questions())


def test_non_object_response_fails_closed():
    router = _FakeRouter(["not", "an", "object"])

    with pytest.raises(DecisionUnavailable, match="non-object"):
        _client(router).decide("x", _questions())


def test_timeout_fails_closed_and_poisons_the_client():
    router = _FakeRouter(_response(), delay_s=0.2)
    client = _client(router)

    with pytest.raises(DecisionUnavailable, match="timed out"):
        client.decide("x", _questions(), timeout_s=0.01)

    assert client.health() is False
    assert "timed out" in (client.last_error or "")


def test_missing_package_is_a_typed_unavailable_error(monkeypatch: pytest.MonkeyPatch):
    def _missing(name: str):
        raise ImportError("No module named 'laya'")

    monkeypatch.setattr("skill_sentry_cli.core.decisions.laya.importlib.import_module", _missing)
    client = LayaDecisionClient(DecisionSettings())

    assert client.health() is False
    with pytest.raises(DecisionUnavailable, match="laya is unavailable"):
        client.decide("x", _questions())


def test_router_factory_is_lazy_and_not_called_twice():
    calls: list[dict[str, Any]] = []
    router = _FakeRouter(_response())

    def factory(**kwargs: Any) -> _FakeRouter:
        calls.append(kwargs)
        return router

    client = LayaDecisionClient(
        DecisionSettings(),
        router_factory=factory,
        laya_module=SimpleNamespace(__version__="0.4.17"),
    )
    assert calls == []
    assert client.loaded is False

    assert client.health() is True
    assert len(calls) == 1
    assert client.loaded is True

    client.decide("x", _questions())
    assert len(calls) == 1


def test_local_model_path_and_calibration_are_passed_to_router():
    calls: list[dict[str, Any]] = []
    router = _FakeRouter(_response())

    def factory(**kwargs: Any) -> _FakeRouter:
        calls.append(kwargs)
        return router

    client = LayaDecisionClient(
        DecisionSettings(model_path="./models/laya", calibration_path="calibration.json"),
        device="cpu",
        router_factory=factory,
        laya_module=SimpleNamespace(__version__="0.4.17"),
    )

    assert client.health() is True
    assert calls == [
        {
            "device": "cpu",
            "models": {"english": "./models/laya"},
            "default": "english",
            "agent_kwargs": {"calibration": "calibration.json"},
        }
    ]

    client.decide("x", _questions())
    assert router.calls[0][2]["model"] == "english"


def test_close_unloads_the_router():
    router = _FakeRouter(_response())
    client = _client(router)

    client.close()

    assert router.unloaded is True
    assert client.loaded is False
