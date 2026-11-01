"""Lazy Laya adapter for the typed decision contract.

The adapter imports :mod:`laya` only when a decision is requested.  Constructing a
client is cheap and safe for CLI startup, health checks, and deterministic-only
scans.  Loading a checkpoint is always explicit at first use.

Laya is advisory.  A timeout, import failure, checkpoint failure, or malformed
response is mapped to :class:`DecisionUnavailable` so the caller can mark the
semantic stage degraded instead of treating it as clean.
"""

from __future__ import annotations

import contextlib
import importlib
import math
import threading
from collections.abc import Callable, Mapping
from typing import Any

from skill_sentry.core.config import DecisionSettings
from skill_sentry.core.decisions.base import (
    DecisionAnswer,
    DecisionError,
    DecisionQuestion,
    DecisionResult,
    DecisionUnavailable,
)

_LOCAL_DEFAULT_CHECKPOINT = "english"


class LayaDecisionClient:
    """In-process Laya client implementing :class:`DecisionClient`.

    ``router`` and ``router_factory`` are injection points for tests and for
    callers that own a long-lived router.  The default factory imports
    ``laya.Router`` on first use.
    """

    backend = "laya"

    def __init__(
        self,
        settings: DecisionSettings | None = None,
        *,
        checkpoint: str | None = None,
        device: str | None = None,
        model_path: str | None = None,
        timeout_s: float | None = None,
        max_len: int | None = None,
        head_max_len: int | None = None,
        calibration_path: str | None = None,
        router: Any | None = None,
        router_factory: Callable[..., Any] | None = None,
        laya_module: Any | None = None,
    ) -> None:
        data = (settings or DecisionSettings()).model_dump()
        overrides = {
            "checkpoint": checkpoint,
            "device": device,
            "model_path": model_path,
            "timeout_s": timeout_s,
            "max_len": max_len,
            "head_max_len": head_max_len,
            "calibration_path": calibration_path,
        }
        for key, value in overrides.items():
            if value is not None:
                data[key] = value
        self.settings = DecisionSettings.model_validate(data)

        pin = None if self.settings.checkpoint == "auto" else self.settings.checkpoint
        if self.settings.model_path and pin is None:
            # A single offline directory cannot serve both routed checkpoints.  Pin the
            # English checkpoint by default so a local path never causes an accidental
            # multilingual download or a route to a directory that does not exist.
            pin = _LOCAL_DEFAULT_CHECKPOINT
        self._pin = pin
        self._router = router
        self._router_factory = router_factory
        self._laya_module = laya_module
        self._version = str(getattr(laya_module, "__version__", "") or "") if laya_module else ""
        self._lock = threading.RLock()
        self._failed: str | None = None
        self._last_error: str | None = None

    # -- identity ----------------------------------------------------------
    @property
    def model_version(self) -> str:
        return f"laya-{self._version}" if self._version else "laya-unknown"

    @property
    def checkpoint(self) -> str:
        return self._pin or "auto"

    @property
    def loaded(self) -> bool:
        return self._router is not None

    @property
    def last_error(self) -> str | None:
        return self._last_error

    @property
    def timeout_s(self) -> float:
        return self.settings.timeout_s

    # -- protocol ----------------------------------------------------------
    def health(self) -> bool:
        """Return package/router readiness without loading checkpoint weights.

        This is deliberately cheap: selection may call it before a scan.  A
        broken checkpoint is discovered on the first :meth:`decide` call and is
        then reported as degraded, never as clean.
        """

        if self._failed is not None:
            return False
        try:
            self._ensure_router()
        except DecisionError:
            return False
        return True

    def decide(
        self,
        state: str | dict[str, Any],
        questions: dict[str, DecisionQuestion],
        *,
        timeout_s: float | None = None,
    ) -> DecisionResult:
        checked_questions = _validate_questions(questions)
        _validate_state(state)
        router = self._ensure_router()

        payload = {qid: _question_payload(question) for qid, question in checked_questions.items()}
        kwargs = self._predict_kwargs(checked_questions)
        timeout = self.settings.timeout_s if timeout_s is None else float(timeout_s)
        if timeout <= 0:
            raise ValueError("timeout_s must be positive")

        try:
            raw = _call_with_timeout(router, state, payload, kwargs, timeout)
            return self._parse_result(raw, checked_questions)
        except DecisionUnavailable as exc:
            self._failed = str(exc)
            self._last_error = str(exc)
            raise

    def close(self) -> None:
        """Release resident checkpoints when the caller owns the router."""

        router = self._router
        self._router = None
        unload = getattr(router, "unload", None)
        if callable(unload):
            with contextlib.suppress(Exception):
                unload()

    def __enter__(self) -> LayaDecisionClient:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()

    # -- loading -----------------------------------------------------------
    def _ensure_router(self) -> Any:
        with self._lock:
            if self._failed is not None:
                raise DecisionUnavailable(self._failed)
            if self._router is not None:
                return self._router
            try:
                module = self._laya_module
                if module is None:
                    module = importlib.import_module("laya")
                self._version = str(getattr(module, "__version__", "") or self._version)
                factory = self._router_factory or getattr(module, "Router", None)
                if not callable(factory):
                    raise DecisionUnavailable("laya package does not expose Router")
                self._router = factory(**self._router_kwargs())
                return self._router
            except DecisionUnavailable as exc:
                self._failed = str(exc)
                self._last_error = str(exc)
                raise
            except Exception as exc:
                message = f"laya is unavailable: {type(exc).__name__}: {str(exc)[:240]}"
                self._failed = message
                self._last_error = message
                raise DecisionUnavailable(message) from exc

    def _router_kwargs(self) -> dict[str, Any]:
        kwargs: dict[str, Any] = {}
        if self.settings.device != "auto":
            kwargs["device"] = self.settings.device
        if self.settings.model_path:
            target = self._pin or _LOCAL_DEFAULT_CHECKPOINT
            kwargs["models"] = {target: self.settings.model_path}
            kwargs["default"] = target
        if self.settings.calibration_path:
            kwargs["agent_kwargs"] = {"calibration": self.settings.calibration_path}
        return kwargs

    # -- request / response ------------------------------------------------
    def _predict_kwargs(self, questions: Mapping[str, DecisionQuestion]) -> dict[str, Any]:
        kwargs: dict[str, Any] = {
            "max_len": self.settings.max_len,
            "head_max_len": self.settings.head_max_len,
        }
        if self._pin:
            kwargs["model"] = self._pin
        thresholds = [
            question.min_confidence
            for question in questions.values()
            if question.min_confidence is not None
        ]
        if thresholds:
            kwargs["min_confidence"] = min(thresholds)
        return kwargs

    def _parse_result(
        self,
        raw: Any,
        questions: Mapping[str, DecisionQuestion],
    ) -> DecisionResult:
        if not isinstance(raw, dict):
            raise DecisionUnavailable("laya returned a non-object response")
        answers_raw = raw.get("answers")
        if not isinstance(answers_raw, dict):
            raise DecisionUnavailable("laya response is missing an answers object")

        expected = set(questions)
        actual = set(answers_raw)
        if expected != actual:
            missing = sorted(expected - actual)
            extra = sorted(actual - expected)
            detail = []
            if missing:
                detail.append(f"missing={missing[:5]}")
            if extra:
                detail.append(f"unexpected={extra[:5]}")
            raise DecisionUnavailable(f"laya response question mismatch ({'; '.join(detail)})")

        answers: dict[str, DecisionAnswer] = {}
        for qid, question in questions.items():
            try:
                answers[qid] = _parse_answer(qid, question, answers_raw[qid])
            except DecisionUnavailable:
                raise
            except Exception as exc:
                raise DecisionUnavailable(
                    f"laya answer {qid!r} is malformed: {type(exc).__name__}: {str(exc)[:240]}"
                ) from exc

        routing_raw = raw.get("routing", {})
        if not isinstance(routing_raw, dict):
            raise DecisionUnavailable("laya response routing metadata is not an object")
        routing = dict(routing_raw)
        usage_raw = raw.get("usage", {})
        if not isinstance(usage_raw, dict):
            raise DecisionUnavailable("laya response usage metadata is not an object")

        checkpoint = routing.get("model")
        if not isinstance(checkpoint, str) or not checkpoint.strip():
            checkpoint = self._pin or "unknown"

        return DecisionResult(
            answers=answers,
            backend=self.backend,
            checkpoint=checkpoint,
            model_version=self.model_version,
            routing=routing,
            usage=dict(usage_raw),
        )


def _validate_state(state: Any) -> None:
    if state is None:
        raise ValueError("state must not be None")
    if not isinstance(state, str | dict):
        raise TypeError("state must be a string or dict")


def _validate_questions(
    questions: Mapping[str, DecisionQuestion],
) -> dict[str, DecisionQuestion]:
    if not isinstance(questions, dict) or not questions:
        raise ValueError("questions must be a non-empty mapping")
    checked: dict[str, DecisionQuestion] = {}
    for qid, question in questions.items():
        if not isinstance(qid, str) or not qid.strip():
            raise ValueError("question IDs must be non-empty strings")
        if not isinstance(question, DecisionQuestion):
            raise TypeError(f"question {qid!r} must be a DecisionQuestion")
        checked[qid] = question
    return checked


def _question_payload(question: DecisionQuestion) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "type": question.type,
        "instructions": question.instructions,
    }
    if question.criteria is not None:
        payload["criteria"] = question.criteria
    return payload


def _call_with_timeout(
    router: Any,
    state: str | dict[str, Any],
    questions: dict[str, Any],
    kwargs: dict[str, Any],
    timeout_s: float,
) -> Any:
    """Run Laya in a daemon thread and fail closed when it exceeds the budget.

    The SDK's timeout hooks bound hook execution, not the forward pass, so the
    adapter owns the wall-clock budget.  A timed-out worker is abandoned and the
    client is marked unhealthy; it must not be reused for a verdict.
    """

    outcome: dict[str, Any] = {}

    def run() -> None:
        try:
            outcome["result"] = router.predict(state, questions, **kwargs)
        except Exception as exc:  # propagate type/message through the box
            outcome["error"] = exc

    thread = threading.Thread(target=run, name="skillsentry-laya", daemon=True)
    thread.start()
    thread.join(timeout_s)
    if thread.is_alive():
        raise DecisionUnavailable(f"laya decision timed out after {timeout_s:g}s")
    error = outcome.get("error")
    if error is not None:
        raise DecisionUnavailable(
            f"laya prediction failed: {type(error).__name__}: {str(error)[:240]}"
        ) from error
    if "result" not in outcome:
        raise DecisionUnavailable("laya prediction returned no result")
    return outcome["result"]


def _parse_answer(
    qid: str,
    question: DecisionQuestion,
    raw: Any,
) -> DecisionAnswer:
    if not isinstance(raw, dict):
        raise DecisionUnavailable(f"laya answer {qid!r} is not an object")

    declared_type = raw.get("type")
    if declared_type is not None and declared_type != question.type:
        raise DecisionUnavailable(
            f"laya answer {qid!r} type {declared_type!r} does not match {question.type!r}"
        )

    abstention_raw = raw.get("abstention")
    if isinstance(abstention_raw, bool):
        abstention = abstention_raw
    elif isinstance(abstention_raw, str):
        abstention = abstention_raw.strip().lower() in {"abstained", "unevaluated", "true", "1"}
    else:
        abstention = False

    confidence = raw.get("answer_confidence", raw.get("confidence"))
    probabilities = raw.get("probabilities")
    common = {
        "abstention": abstention,
        "confidence": _optional_float(confidence, qid),
        "probabilities": probabilities,
    }

    if question.type == "choice":
        choice = raw.get("choice")
        if choice is None and abstention:
            return DecisionAnswer(**common)
        if not isinstance(choice, str) or not choice.strip():
            raise DecisionUnavailable(f"laya choice answer {qid!r} is missing a label")
        criteria = question.criteria if isinstance(question.criteria, dict) else {}
        if criteria and choice not in criteria:
            raise DecisionUnavailable(
                f"laya choice answer {qid!r} returned an unknown label {choice!r}"
            )
        if isinstance(probabilities, dict):
            unknown = sorted(set(probabilities) - set(criteria))
            if unknown:
                raise DecisionUnavailable(
                    f"laya choice probabilities {qid!r} contain unknown labels {unknown[:5]}"
                )
        elif isinstance(probabilities, list) and len(probabilities) != len(criteria):
            raise DecisionUnavailable(
                f"laya choice probabilities {qid!r} have the wrong option count"
            )
        return DecisionAnswer(choice=choice, **common)

    if question.type == "score":
        score = raw.get("score")
        if score is None and abstention:
            return DecisionAnswer(**common)
        number = _required_number(score, qid, "score")
        criteria = question.criteria if isinstance(question.criteria, list) else []
        if isinstance(probabilities, list) and len(probabilities) != len(criteria):
            raise DecisionUnavailable(
                f"laya score probabilities {qid!r} have the wrong level count"
            )
        return DecisionAnswer(score=number, **common)

    noul = raw.get("noul")
    if noul is None and abstention:
        return DecisionAnswer(**common)
    return DecisionAnswer(noul=_required_number(noul, qid, "noul"), **common)


def _optional_float(value: Any, qid: str) -> float | None:
    if value is None:
        return None
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise DecisionUnavailable(f"laya answer {qid!r} has a non-numeric confidence")
    number = float(value)
    if not math.isfinite(number):
        raise DecisionUnavailable(f"laya answer {qid!r} has a non-finite confidence")
    return number


def _required_number(value: Any, qid: str, field: str) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise DecisionUnavailable(f"laya answer {qid!r} is missing a numeric {field}")
    number = float(value)
    if not math.isfinite(number):
        raise DecisionUnavailable(f"laya answer {qid!r} has a non-finite {field}")
    return number


__all__ = ["LayaDecisionClient"]
