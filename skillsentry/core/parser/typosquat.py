"""Typosquat / homograph detection for skill names.

Loads a packaged dictionary of known legitimate skill names and detects
deceptive variants via homoglyph folding, NFKC normalization, and
Damerau-Levenshtein distance <= 2.
"""

from __future__ import annotations

import importlib.resources
import json
import unicodedata
from dataclasses import dataclass
from functools import lru_cache

# Fallback known skill names if package resource is unavailable
_FALLBACK_KNOWN_NAMES: tuple[str, ...] = (
    "git-helper",
    "git-translate",
    "github-helper",
    "pdf-summarizer",
    "image-resizer",
    "weather-fetch",
    "slack-notifier",
    "cloud-sync",
    "file-organizer",
    "code-reviewer",
    "web-search",
    "calendar-assistant",
    "email-assistant",
    "database-helper",
    "docker-helper",
    "pdf-reader",
    "markdown-editor",
    "notion-sync",
)


@lru_cache(maxsize=1)
def load_known_skills() -> tuple[str, ...]:
    """Load curated known skill names from packaged data resource."""
    try:
        data_ref = importlib.resources.files("skillsentry.data").joinpath("known_skills_v1.json")
        if data_ref.is_file():
            payload = json.loads(data_ref.read_text(encoding="utf-8"))
            entries = payload.get("entries", [])
            names = [entry["name"] for entry in entries if "name" in entry]
            if names:
                # Merge with fallback to ensure full coverage
                combined = list(dict.fromkeys(names + list(_FALLBACK_KNOWN_NAMES)))
                return tuple(combined)
    except Exception:
        pass
    return _FALLBACK_KNOWN_NAMES


KNOWN_SKILL_NAMES: tuple[str, ...] = load_known_skills()

# Homoglyph / Leet-speak / Unicode lookalike folding map
HOMOGLYPH_MAP: dict[str, str] = {
    # Leet-speak / ASCII lookalikes
    "1": "l",
    "!": "i",
    "|": "l",
    "0": "o",
    "3": "e",
    "5": "s",
    "@": "a",
    "$": "s",
    "4": "a",
    "7": "t",
    "8": "b",
    "9": "g",
    "6": "g",
    # Cyrillic lookalikes
    "\u0430": "a",  # Cyrillic small letter a
    "\u0441": "c",  # Cyrillic small letter es
    "\u0435": "e",  # Cyrillic small letter ie
    "\u043e": "o",  # Cyrillic small letter o
    "\u0440": "p",  # Cyrillic small letter er
    "\u0455": "s",  # Cyrillic small letter dze
    "\u0445": "x",  # Cyrillic small letter ha
    "\u0443": "y",  # Cyrillic small letter u
    "\u0456": "i",  # Cyrillic small letter byelorussian-ukrainian i
    "\u0458": "j",  # Cyrillic small letter je
    "\u0501": "d",  # Cyrillic small letter komi de
    "\u051b": "q",  # Cyrillic small letter qa
    "\u051d": "w",  # Cyrillic small letter we
    # Greek lookalikes
    "\u03b1": "a",  # Greek small letter alpha
    "\u03b2": "b",  # Greek small letter beta
    "\u03b3": "y",  # Greek small letter gamma
    "\u03b5": "e",  # Greek small letter epsilon
    "\u03b9": "i",  # Greek small letter iota
    "\u03ba": "k",  # Greek small letter kappa
    "\u03bd": "v",  # Greek small letter nu
    "\u03bf": "o",  # Greek small letter omicron
    "\u03c1": "p",  # Greek small letter rho
    "\u03c4": "t",  # Greek small letter tau
    "\u03c5": "u",  # Greek small letter upsilon
    "\u03c7": "x",  # Greek small letter chi
}

MULTI_HOMOGLYPHS: list[tuple[str, str]] = [
    ("vv", "w"),
    ("rn", "m"),
    ("cl", "d"),
    ("nn", "m"),
    ("_", "-"),
]


@dataclass(frozen=True)
class TyposquatMatch:
    name: str
    candidate: str
    distance: int
    normalised: str

    @property
    def message(self) -> str:
        return (
            f"Skill name {self.name!r} resembles known skill {self.candidate!r} "
            f"(edit distance {self.distance})"
        )


def _fold(value: str) -> str:
    """Normalize Unicode (NFKC) and fold homoglyphs/leet-speak."""
    normalized = unicodedata.normalize("NFKC", value).lower()
    folded = "".join(HOMOGLYPH_MAP.get(c, c) for c in normalized)
    for pattern, replacement in MULTI_HOMOGLYPHS:
        folded = folded.replace(pattern, replacement)
    return folded


def _damerau_levenshtein(s1: str, s2: str, max_distance: int = 3) -> int:
    """Bounded Damerau-Levenshtein distance supporting transpositions."""
    if s1 == s2:
        return 0
    len1, len2 = len(s1), len(s2)
    if abs(len1 - len2) > max_distance:
        return max_distance + 1

    d: dict[tuple[int, int], int] = {}
    for i in range(-1, len1 + 1):
        d[(i, -1)] = i + 1
    for j in range(-1, len2 + 1):
        d[(-1, j)] = j + 1

    for i in range(len1):
        for j in range(len2):
            cost = 0 if s1[i] == s2[j] else 1
            d[(i, j)] = min(
                d[(i - 1, j)] + 1,       # deletion
                d[(i, j - 1)] + 1,       # insertion
                d[(i - 1, j - 1)] + cost  # substitution
            )
            # Transposition check
            if i > 0 and j > 0 and s1[i] == s2[j - 1] and s1[i - 1] == s2[j]:
                d[(i, j)] = min(d[(i, j)], d[(i - 2, j - 2)] + 1)

    result = d[(len1 - 1, len2 - 1)]
    return result if result <= max_distance else max_distance + 1


def levenshtein(left: str, right: str, *, max_distance: int = 3) -> int:
    """Backwards-compatible alias for Damerau-Levenshtein."""
    return _damerau_levenshtein(left, right, max_distance=max_distance)


def check_typosquat(
    name: str, *, known: tuple[str, ...] | None = None
) -> TyposquatMatch | None:
    """Return the nearest known name when ``name`` is a likely imitation."""
    candidates = known if known is not None else load_known_skills()
    lowered = name.strip().lower()
    if len(lowered) < 4:
        return None

    folded = _fold(lowered)

    # Exact name check (case-insensitive and normalized): not a typosquat
    known_lowered = {item.lower() for item in candidates}
    known_folded = {_fold(item) for item in candidates}
    if lowered in known_lowered or folded in known_folded:
        return None

    best: TyposquatMatch | None = None
    for candidate in candidates:
        candidate_lower = candidate.lower()
        candidate_folded = _fold(candidate_lower)

        distance = min(
            _damerau_levenshtein(lowered, candidate_lower, max_distance=2),
            _damerau_levenshtein(folded, candidate_folded, max_distance=2),
        )
        if distance > 2:
            continue
        # Very short candidates produce too many false positives
        if min(len(lowered), len(candidate_lower)) < 5:
            continue
        if best is None or distance < best.distance:
            best = TyposquatMatch(
                name=name,
                candidate=candidate,
                distance=distance,
                normalised=folded,
            )
    return best


__all__ = [
    "HOMOGLYPH_MAP",
    "KNOWN_SKILL_NAMES",
    "MULTI_HOMOGLYPHS",
    "TyposquatMatch",
    "check_typosquat",
    "levenshtein",
    "load_known_skills",
]
