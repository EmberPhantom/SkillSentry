"""Typed decision contracts, taxonomy, and decision settings."""

from __future__ import annotations

from pathlib import Path

import pytest
from pydantic import ValidationError
from skillsentry.core.config import (
    DecisionSettings,
    default_config,
    load_config,
    write_default_config,
)
from skillsentry.core.decisions import (
    CAPABILITY_QUESTIONS,
    DECEPTION_CHOICES,
    INTENT_CHOICES,
    DecisionAnswer,
    DecisionClient,
    DecisionQuestion,
    DecisionResult,
    EvidenceCandidate,
    semantic_questions,
)


def test_choice_question_requires_criteria_mapping():
    question = DecisionQuestion(
        type="choice",
        instructions="Which category?",
        criteria={"one": "first", "two": "second"},
    )
    assert question.type == "choice"
    assert question.criteria == {"one": "first", "two": "second"}

    with pytest.raises(ValidationError, match="criteria mapping"):
        DecisionQuestion(type="choice", instructions="Which category?")

    with pytest.raises(ValidationError, match="criteria mapping"):
        DecisionQuestion(type="choice", instructions="Which category?", criteria={})


def test_score_question_requires_two_to_ten_levels():
    question = DecisionQuestion(
        type="score",
        instructions="How severe?",
        criteria=["low", "medium", "high"],
    )
    assert question.criteria == ["low", "medium", "high"]

    with pytest.raises(ValidationError, match="between 2 and 10"):
        DecisionQuestion(type="score", instructions="How severe?", criteria=["only"])

    with pytest.raises(ValidationError, match="between 2 and 10"):
        DecisionQuestion(
            type="score", instructions="How severe?", criteria=[str(i) for i in range(11)]
        )


def test_noul_question_must_not_have_criteria():
    question = DecisionQuestion(type="noul", instructions="Does it read credentials?")
    assert question.criteria is None

    with pytest.raises(ValidationError, match="must not define criteria"):
        DecisionQuestion(
            type="noul",
            instructions="Does it read credentials?",
            criteria={"yes": "yes"},
        )


def test_answer_requires_at_most_one_primitive():
    assert DecisionAnswer(noul=0.8).noul == 0.8
    assert DecisionAnswer(choice="billing").choice == "billing"
    assert DecisionAnswer(score=1.5).score == 1.5

    with pytest.raises(ValidationError, match="exactly one"):
        DecisionAnswer()
    with pytest.raises(ValidationError, match="at most one"):
        DecisionAnswer(choice="billing", noul=0.8)
    with pytest.raises(ValidationError, match="less than or equal to 1"):
        DecisionAnswer(noul=1.1)


def test_abstaining_answer_can_keep_the_raw_primitive():
    answer = DecisionAnswer(abstention=True)
    assert answer.abstention is True

    # Laya's confidence gate marks an answer without deleting the primitive, so the
    # adapter must be able to preserve both.
    gated = DecisionAnswer(abstention=True, choice="billing", confidence=0.2)
    assert gated.abstention is True
    assert gated.choice == "billing"


def test_probabilities_are_bounded():
    answer = DecisionAnswer(
        choice="billing",
        probabilities={"billing": 0.9, "technical": 0.1},
        confidence=0.9,
    )
    assert answer.probabilities == {"billing": 0.9, "technical": 0.1}

    with pytest.raises(ValidationError, match="probabilities"):
        DecisionAnswer(choice="billing", probabilities={"billing": 1.1})


def test_decision_result_requires_answers():
    result = DecisionResult(
        answers={"intent": DecisionAnswer(choice="text_processing")},
        backend="laya",
        checkpoint="english",
        model_version="0.4",
    )
    assert result.answers["intent"].choice == "text_processing"

    with pytest.raises(ValidationError, match="at least one answer"):
        DecisionResult(answers={}, backend="laya")


def test_evidence_candidate_requires_relative_file():
    candidate = EvidenceCandidate(
        candidate_id="anchor-1",
        file="scripts/sync.py",
        line=42,
        code="open('.aws/credentials')",
        anchor_type="credential-read",
    )
    assert candidate.file == "scripts/sync.py"

    with pytest.raises(ValidationError, match="relative path"):
        EvidenceCandidate(
            candidate_id="anchor-1",
            file="../outside.py",
            line=1,
            code="x",
            anchor_type="credential-read",
        )


def test_taxonomy_is_small_and_has_stable_ids():
    assert len(INTENT_CHOICES) == 8
    assert "other" in INTENT_CHOICES
    assert set(DECEPTION_CHOICES) == {"consistent", "unclear", "deceptive"}
    assert len(CAPABILITY_QUESTIONS) == 12
    assert len(set(CAPABILITY_QUESTIONS)) == len(CAPABILITY_QUESTIONS)

    questions = semantic_questions()
    assert set(questions) == {"intent", "deception", *CAPABILITY_QUESTIONS}
    assert questions["intent"].type == "choice"
    assert questions["deception"].type == "choice"
    assert all(questions[qid].type == "noul" for qid in CAPABILITY_QUESTIONS)


def test_semantic_questions_are_fresh_copies():
    first = semantic_questions()
    second = semantic_questions()
    assert first is not second
    first["intent"].criteria["mutated"] = "x"  # type: ignore[index]
    assert "mutated" not in second["intent"].criteria  # type: ignore[index]


def test_decision_settings_defaults():
    config = default_config()
    assert config.decision.backend == "legacy"
    assert config.decision.checkpoint == "auto"
    assert config.decision.device == "auto"
    assert config.decision.max_len == 1024
    assert config.decision.head_max_len == 256
    assert config.decision.required is False
    assert config.decision.cache_identity == "legacy:auto:uncalibrated:1024:256"


def test_decision_settings_identity_tracks_model_and_calibration():
    base = DecisionSettings()
    changed = DecisionSettings(
        backend="laya",
        checkpoint="english",
        calibration_version="cal-2026-10-28",
    )
    assert base.cache_identity != changed.cache_identity
    assert changed.cache_identity == "laya:english:cal-2026-10-28:1024:256"


def test_decision_settings_validate_budgets_and_enums():
    with pytest.raises(ValidationError, match="head_max_len"):
        DecisionSettings(max_len=256, head_max_len=512)
    with pytest.raises(ValidationError, match="backend must be one of"):
        DecisionSettings(backend="unknown")
    with pytest.raises(ValidationError, match="checkpoint must be one of"):
        DecisionSettings(checkpoint="unknown")
    with pytest.raises(ValidationError, match="device must be one of"):
        DecisionSettings(device="tpu")


def test_decision_environment_overrides(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    path = tmp_path / "skillsentry.toml"
    path.write_text('[decision]\nbackend = "legacy"\n', encoding="utf-8")
    monkeypatch.setenv("SKILLSENTRY_DECISION_BACKEND", "laya")
    monkeypatch.setenv("SKILLSENTRY_LAYA_CHECKPOINT", "multilingual")
    monkeypatch.setenv("SKILLSENTRY_LAYA_DEVICE", "cpu")
    monkeypatch.setenv("SKILLSENTRY_LAYA_MODEL_PATH", "./models/laya")
    monkeypatch.setenv("SKILLSENTRY_LAYA_REQUIRED", "1")

    config = load_config(path)
    assert config.decision.backend == "laya"
    assert config.decision.checkpoint == "multilingual"
    assert config.decision.device == "cpu"
    assert config.decision.model_path == "./models/laya"
    assert config.decision.required is True


def test_default_config_roundtrip_includes_decision(tmp_path: Path):
    path = write_default_config(tmp_path / "skillsentry.toml")
    config = load_config(path)
    assert config.decision.backend == "legacy"
    assert config.decision.cache_identity == "legacy:auto:uncalibrated:1024:256"


class _FakeDecisionClient:
    backend = "fake"
    model_version = "1"

    def decide(
        self,
        state: str | dict[str, object],
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
        return True


def test_decision_client_protocol_is_runtime_checkable():
    client = _FakeDecisionClient()
    assert isinstance(client, DecisionClient)
    assert client.health() is True
