"""Model-client interface **I2** (producer: Dev 1; consumer: Dev 2).

``generate_json`` must return a dict matching the supplied JSON Schema.
``analyze_image`` returns OCR text, normalised bounding boxes and findings.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from skill_sentry_cli.core.contracts import ImageAnalysis


class ModelError(RuntimeError):
    """Base class for model failures."""


class ModelUnavailable(ModelError):
    """No backend is reachable (callers must emit a ``*-unavailable`` finding)."""


class ModelTimeout(ModelUnavailable):
    """A request ran past its time limit. Asking again would take as long, so it is not retried."""


class ModelTruncated(ModelUnavailable):
    """The reply was cut at the output limit. At temperature 0 a retry cuts at the same place,
    so it is not retried."""


class ModelAuthError(ModelUnavailable):
    """The provider refused the credentials (HTTP 401 or 403). Asking again cannot help."""


class ModelNotFound(ModelUnavailable):
    """The provider has no such model or endpoint (HTTP 404). Asking again cannot help."""


class ModelQuotaExhausted(ModelUnavailable):
    """The provider's daily (or longer) quota is used up. Waiting inside a scan cannot help, so
    the run stops asking and says so once. ``retry_after`` is when the provider says it resets."""

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ModelThrottled(ModelUnavailable):
    """Pacing the requests to the provider's limits would take longer than the scan may.

    Nothing was sent. The scan's time limit is kept, and the stage says it was throttled."""


class ModelRateLimited(ModelUnavailable):
    """The provider answered 429. ``retry_after`` is how long it asked callers to wait, if known."""

    def __init__(self, message: str, *, retry_after: float | None = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


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
