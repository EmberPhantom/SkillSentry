"""Model error types."""

from __future__ import annotations

from skillsentry.core.models.base import (
    ModelBadResponse,
    ModelError,
    ModelTimeout,
    ModelUnavailable,
    PromptTruncated,
)

__all__ = [
    "ModelBadResponse",
    "ModelError",
    "ModelTimeout",
    "ModelUnavailable",
    "PromptTruncated",
]

