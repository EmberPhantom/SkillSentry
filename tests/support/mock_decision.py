"""Deterministic decision client for unit tests and local wiring checks.

Never imported or executed by production runtime code under skillsentry/.
"""

from __future__ import annotations

from typing import Any

from skillsentry.core.decisions.base import (
    DecisionAnswer,
    DecisionQuestion,
    DecisionResult,
)

_MALICIOUS_MARKERS = (
    "aws/credentials",
    "base64",
    "curl ",
    "dockerenv",
    "evil",
    "exfil",
    "nslookup",
    "private key",
    "token",
)


class MockDecisionClient:
    """Deterministic typed decisions with ``auto``/``benign``/``malicious`` profiles for tests."""

    backend = "mock"
    model_version = "mock-laya-v1"

    def __init__(
        self,
        profile: str = "auto",
        *,
        answers: dict[str, DecisionAnswer] | None = None,
    ) -> None:
        if profile not in {"auto", "benign", "malicious"}:
            raise ValueError(f"unknown MockDecisionClient profile: {profile}")
        self.profile = profile
        self._answers = dict(answers or {})

    def decide(
        self,
        state: str | dict[str, Any],
        questions: dict[str, DecisionQuestion],
        *,
        timeout_s: float | None = None,
    ) -> DecisionResult:
        del timeout_s
        malicious = self._is_malicious(state)
        answers: dict[str, DecisionAnswer] = {}
        for qid, question in questions.items():
            if qid in self._answers:
                answers[qid] = self._answers[qid]
            else:
                answers[qid] = _mock_answer(qid, question, malicious)
        return DecisionResult(
            answers=answers,
            backend=self.backend,
            checkpoint="mock",
            model_version=self.model_version,
            routing={"model": "mock", "reason": "deterministic test double"},
            usage={"input_tokens": 0, "output_tokens": 0},
        )

    def health(self) -> bool:
        return True

    def close(self) -> None:
        return None

    def _is_malicious(self, state: str | dict[str, Any]) -> bool:
        if self.profile == "malicious":
            return True
        if self.profile == "benign":
            return False
        text = state if isinstance(state, str) else str(state)
        lowered = text.lower()
        return any(marker in lowered for marker in _MALICIOUS_MARKERS)


def _mock_answer(qid: str, question: DecisionQuestion, malicious: bool) -> DecisionAnswer:
    if question.type == "choice":
        criteria = question.criteria if isinstance(question.criteria, dict) else {}
        keys = list(criteria)
        if qid == "deception" and "deceptive" in criteria:
            choice = "deceptive" if malicious else "consistent"
        elif malicious and "data_export" in criteria:
            choice = "data_export"
        elif not malicious and "other" in criteria:
            choice = "other"
        else:
            choice = keys[0] if keys else "other"
        if len(keys) == 1:
            probabilities: dict[str, float] = {keys[0]: 1.0}
        else:
            rest = (1.0 - 0.9) / max(1, len(keys) - 1)
            probabilities = {key: (0.9 if key == choice else rest) for key in keys}
        return DecisionAnswer(choice=choice, probabilities=probabilities, confidence=0.9)

    if question.type == "score":
        criteria = question.criteria if isinstance(question.criteria, list) else []
        selected = 1.0 if malicious else 0.0
        index = 1 if malicious and len(criteria) > 1 else 0
        rest = (1.0 - 0.9) / max(1, len(criteria) - 1)
        probabilities = [0.9 if position == index else rest for position in range(len(criteria))]
        return DecisionAnswer(score=selected, probabilities=probabilities, confidence=0.9)

    return DecisionAnswer(noul=0.9 if malicious else 0.05, confidence=0.9)


__all__ = ["MockDecisionClient"]

