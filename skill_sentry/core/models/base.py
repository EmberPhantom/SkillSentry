"""Model-client interface **I2** (producer: Dev 1; consumer: Dev 2).

``generate_json`` must return a dict matching the supplied JSON Schema.
``analyze_image`` returns OCR text, normalised bounding boxes and findings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from skill_sentry.core.contracts import ImageAnalysis


class ModelError(RuntimeError):
    """Base class for model failures."""


class ModelUnavailable(ModelError):
    """No backend is reachable (callers must emit a ``*-unavailable`` finding)."""


@runtime_checkable
class ModelClient(Protocol):
    """Typed interface between Dev 2's analyzers and Dev 1's model plumbing."""

    backend: str
    model_version: str

    def generate_json(
        self,
        system: str,
        user: str,
        schema: dict[str, Any],
        retries: int = 1,
    ) -> dict[str, Any]:
        """Run a text completion constrained to ``schema``.

        Implementations must retry once on malformed JSON, then raise
        :class:`ModelUnavailable`.
        """
        ...

    def analyze_image(self, path: str | Path, prompt: str) -> ImageAnalysis:
        """OCR and classify one image (path on disk, no network fetch)."""
        ...

    def health(self) -> bool:
        """Cheap liveness probe; must not raise."""
        ...
