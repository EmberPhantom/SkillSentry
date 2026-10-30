"""Semantic analyzer error types."""

from __future__ import annotations

from skillsentry.core.models.base import ModelError, ModelUnavailable


class ModelTimeout(ModelError):
    """Inference request timed out."""


class ModelBadResponse(ModelError):
    """Model returned unparsable, schema-invalid, or cut-off output."""


class PromptTruncated(ModelError):
    """Prompt exceeded context window or was truncated by server."""


__all__ = [
    "ModelBadResponse",
    "ModelError",
    "ModelTimeout",
    "ModelUnavailable",
    "PromptTruncated",
]
