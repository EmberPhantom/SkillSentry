"""Typed decision contracts for System One semantic backends.

The models in this module are intentionally provider-neutral.  A backend such
as Laya or TypeSafe Jev receives a state and a set of typed questions; it
returns answers and probabilities, never free-form text.

The final verdict is still produced by deterministic fusion.  These models only
describe advisory semantic decisions.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Literal, Protocol, runtime_checkable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator


class DecisionError(RuntimeError):
    """Base class for decision-backend failures."""


class DecisionUnavailable(DecisionError):
    """No decision backend is installed, reachable, or healthy."""


class DecisionModel(BaseModel):
    """Base model for decision contracts."""

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class DecisionQuestion(DecisionModel):
    """One typed question sent to a decision backend.

    ``choice`` requires a mapping of option key to description.  ``score``
    requires an ordered list of levels.  ``noul`` is a yes/no question and must
    not carry criteria.
    """

    type: Literal["choice", "score", "noul"]
    instructions: str = Field(min_length=1, max_length=4096)
    criteria: dict[str, str] | list[str] | None = None
    min_confidence: float | None = Field(default=None, ge=0.0, le=1.0)

    @model_validator(mode="after")
    def _validate_criteria(self) -> DecisionQuestion:
        if self.type == "choice":
            if not isinstance(self.criteria, dict) or not self.criteria:
                raise ValueError("choice questions require a non-empty criteria mapping")
            if len(self.criteria) > 255:
                raise ValueError("choice questions support at most 255 options")
            if any(not key.strip() for key in self.criteria):
                raise ValueError("choice option keys must not be empty")
            if any(not value.strip() for value in self.criteria.values()):
                raise ValueError("choice option descriptions must not be empty")
        elif self.type == "score":
            if not isinstance(self.criteria, list) or not 2 <= len(self.criteria) <= 10:
                raise ValueError("score questions require between 2 and 10 ordered levels")
            if any(not level.strip() for level in self.criteria):
                raise ValueError("score levels must not be empty")
        elif self.criteria is not None:
            raise ValueError("noul questions must not define criteria")
        return self


class DecisionAnswer(DecisionModel):
    """One answer returned for a :class:`DecisionQuestion`."""

    choice: str | None = None
    score: float | None = None
    noul: float | None = Field(default=None, ge=0.0, le=1.0)
    probabilities: dict[str, float] | list[float] | None = None
    confidence: float | None = Field(default=None, ge=0.0, le=1.0)
    abstention: bool = False

    @model_validator(mode="after")
    def _validate_answer(self) -> DecisionAnswer:
        present = [self.choice is not None, self.score is not None, self.noul is not None]
        if sum(present) > 1:
            raise ValueError("an answer must contain at most one of choice, score, or noul")
        if not self.abstention and sum(present) != 1:
            raise ValueError(
                "a non-abstaining answer must contain exactly one of choice, score, or noul"
            )
        if self.choice is not None and not self.choice.strip():
            raise ValueError("choice answer must not be empty")
        if self.probabilities is not None:
            values = (
                self.probabilities.values()
                if isinstance(self.probabilities, dict)
                else self.probabilities
            )
            if any(not 0.0 <= float(value) <= 1.0 for value in values):
                raise ValueError("probabilities must be between 0 and 1")
        return self


class DecisionResult(DecisionModel):
    """Complete response from a decision backend."""

    answers: dict[str, DecisionAnswer]
    backend: str = Field(min_length=1)
    checkpoint: str = ""
    model_version: str = ""
    routing: dict[str, Any] = Field(default_factory=dict)
    usage: dict[str, Any] = Field(default_factory=dict)

    @field_validator("answers")
    @classmethod
    def _validate_answer_ids(cls, value: dict[str, DecisionAnswer]) -> dict[str, DecisionAnswer]:
        if not value:
            raise ValueError("a decision result must contain at least one answer")
        if any(not key.strip() for key in value):
            raise ValueError("answer IDs must not be empty")
        return value


class EvidenceCandidate(DecisionModel):
    """Code-owned evidence that a decision backend may classify.

    The backend never supplies or invents the file, line, or code fields; those
    remain deterministic evidence used in findings and reports.
    """

    candidate_id: str = Field(min_length=1, max_length=120)
    file: str = Field(min_length=1, max_length=1024)
    line: int = Field(ge=1)
    code: str = Field(min_length=1, max_length=4000)
    anchor_type: str = Field(min_length=1, max_length=120)

    @field_validator("file")
    @classmethod
    def _validate_relative_file(cls, value: str) -> str:
        normalised = value.replace("\\", "/")
        while normalised.startswith("./"):
            normalised = normalised[2:]
        path = Path(normalised)
        if path.is_absolute() or ".." in path.parts:
            raise ValueError("evidence file must be a relative path inside the skill package")
        return normalised


@runtime_checkable
class DecisionClient(Protocol):
    """Provider-neutral interface for typed semantic decisions."""

    backend: str
    model_version: str

    def decide(
        self,
        state: str | dict[str, Any],
        questions: dict[str, DecisionQuestion],
        *,
        timeout_s: float | None = None,
    ) -> DecisionResult:
        """Answer ``questions`` about ``state`` or raise :class:`DecisionError`."""
        ...

    def health(self) -> bool:
        """Cheap liveness probe; must not raise."""
        ...


__all__ = [
    "DecisionAnswer",
    "DecisionClient",
    "DecisionError",
    "DecisionQuestion",
    "DecisionResult",
    "DecisionUnavailable",
    "EvidenceCandidate",
]
