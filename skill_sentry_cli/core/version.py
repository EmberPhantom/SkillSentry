"""Package metadata and engine version helpers.

The engine version participates in the Stage-0 cache key.  Any change to the
fusion weights is folded into the version string so cached verdicts produced
under different scoring rules are never reused (docs/developer/database.md §3.5).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

__version__ = "2.1.1"
ENGINE_VERSION = __version__
CONTRACT_VERSION = "1"
# Privacy badge text per analysis backend.  ``GEMMA_BADGE`` is kept for
# compatibility; callers that know the backend should use ``badge_for_backend``.
GEMMA_BADGE = "Fully local analysis · open weights"
CLOUD_BADGE = "Cloud analysis · code excerpts sent to the Gemini API"
UNKNOWN_BADGE = "Analysis backend unknown"

_LOCAL_BACKENDS = frozenset({"local", "ollama", "mock", "demo"})
_CLOUD_BACKENDS = frozenset({"cloud", "gemini-api"})

DEFAULT_WEIGHTS: dict[str, float] = {
    "anchors": 0.15,
    "semantic": 0.20,
    "vision": 0.20,
    "sandbox": 0.25,
}


def badge_for_backend(backend: str | None) -> str:
    """Return the privacy badge that matches the analysis backend in use.

    Local (``local``/``ollama``) and mock/demo backends keep ``GEMMA_BADGE``.
    Cloud (``cloud``/``gemini-api``) sends code excerpts off the machine, so it
    gets ``CLOUD_BADGE``.  Anything else (``auto``, ``unavailable``, unknown,
    or ``None``) is reported as unknown rather than claiming local analysis.
    """
    normalized = (backend or "").strip().lower()
    if normalized in _CLOUD_BACKENDS:
        return CLOUD_BADGE
    if normalized in _LOCAL_BACKENDS:
        return GEMMA_BADGE
    return UNKNOWN_BADGE


def weights_fingerprint(weights: Mapping[str, float] | None = None) -> str:
    """Return a stable short fingerprint for a fusion-weight configuration."""
    payload = json.dumps(dict(weights or DEFAULT_WEIGHTS), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:8]


def engine_version(weights: Mapping[str, float] | None = None) -> str:
    """Engine version including the scoring-weight fingerprint.

    Example: ``2.0.0+a1b2c3d4``.
    """
    return f"{ENGINE_VERSION}+{weights_fingerprint(weights)}"
