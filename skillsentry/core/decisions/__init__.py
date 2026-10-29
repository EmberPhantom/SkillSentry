"""Typed decision contracts for local semantic backends.

Laya and similar System One models answer typed questions instead of
generating free-form text.  Keep this interface separate from
:class:`skillsentry.core.models.base.ModelClient`, which remains the
generation/vision interface.
"""

from skillsentry.core.decisions.base import (
    DecisionAnswer,
    DecisionClient,
    DecisionError,
    DecisionQuestion,
    DecisionResult,
    DecisionUnavailable,
    EvidenceCandidate,
)
from skillsentry.core.decisions.laya import LayaDecisionClient
from skillsentry.core.decisions.questions import (
    CAPABILITY_QUESTIONS,
    DECEPTION_CHOICES,
    INTENT_CHOICES,
    semantic_questions,
)
from skillsentry.core.decisions.selector import DecisionSelection, select_decision_model

__all__ = [
    "CAPABILITY_QUESTIONS",
    "DECEPTION_CHOICES",
    "INTENT_CHOICES",
    "DecisionAnswer",
    "DecisionClient",
    "DecisionError",
    "DecisionQuestion",
    "DecisionResult",
    "DecisionSelection",
    "DecisionUnavailable",
    "EvidenceCandidate",
    "LayaDecisionClient",
    "select_decision_model",
    "semantic_questions",
]
