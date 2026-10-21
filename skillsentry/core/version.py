"""Package metadata and engine version helpers.

The engine version participates in the Stage-0 cache key.  Any change to the
fusion weights is folded into the version string so cached verdicts produced
under different scoring rules are never reused (docs/03-database.md §3.5).
"""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping

__version__ = "2.0.0"
ENGINE_VERSION = __version__
CONTRACT_VERSION = "1"
GEMMA_BADGE = "Powered by Gemma 4 · open weights"

DEFAULT_WEIGHTS: dict[str, float] = {
    "anchors": 0.15,
    "semantic": 0.20,
    "vision": 0.20,
    "sandbox": 0.25,
}


def weights_fingerprint(weights: Mapping[str, float] | None = None) -> str:
    """Return a stable short fingerprint for a fusion-weight configuration."""
    payload = json.dumps(dict(weights or DEFAULT_WEIGHTS), sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:8]


def engine_version(weights: Mapping[str, float] | None = None) -> str:
    """Engine version including the scoring-weight fingerprint.

    Example: ``2.0.0+a1b2c3d4``.
    """
    return f"{ENGINE_VERSION}+{weights_fingerprint(weights)}"
