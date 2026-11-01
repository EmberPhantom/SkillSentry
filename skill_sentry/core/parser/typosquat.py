"""Typosquat / homograph detection for skill names.

The known-name list is intentionally small and local: this is a supply-chain
warning signal, not a verdict by itself.  The matching rules are conservative
(normalised Levenshtein distance <= 2 for names of at least four characters)
and exact names are never flagged.
"""

from __future__ import annotations

import json
import unicodedata
from dataclasses import dataclass
from importlib import resources


def _load_known_names() -> tuple[str, ...]:
    """Load the curated list from the packaged data file (works from a wheel install)."""

    raw = (
        resources.files("skill_sentry.data")
        .joinpath("known_skills_v1.json")
        .read_text(encoding="utf-8")
    )
    entries = json.loads(raw)["entries"]
    return tuple(sorted({str(entry["name"]) for entry in entries}))


KNOWN_SKILL_NAMES: tuple[str, ...] = _load_known_names()

_TRANSLATION = str.maketrans(
    {
        "0": "o",
        "1": "l",
        "3": "e",
        "4": "a",
        "5": "s",
        "7": "t",
        "8": "b",
        "9": "g",
        "@": "a",
        "$": "s",
        "!": "i",
        "|": "l",
    }
)


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


# Cyrillic and Greek letters that render like Latin ones: a common homograph trick.
_CONFUSABLES = str.maketrans(
    {
        "а": "a",
        "е": "e",
        "о": "o",
        "р": "p",
        "с": "c",
        "у": "y",
        "х": "x",
        "і": "i",
        "ј": "j",
        "ѕ": "s",
        "һ": "h",
        "ԁ": "d",
        "ɡ": "g",
        "α": "a",
        "ο": "o",
        "ν": "v",
        "ρ": "p",
        "ι": "i",
        "κ": "k",
        "τ": "t",
        "ε": "e",
        "υ": "u",
        "χ": "x",
    }
)


def _fold(value: str) -> str:
    folded = unicodedata.normalize("NFKC", value).lower().translate(_CONFUSABLES)
    folded = folded.translate(_TRANSLATION)
    folded = folded.replace("rn", "m").replace("vv", "w")
    folded = folded.replace("_", "-")
    return folded


def levenshtein(left: str, right: str, *, max_distance: int = 3) -> int:
    """Small bounded Levenshtein implementation (no external dependency)."""

    if left == right:
        return 0
    if abs(len(left) - len(right)) > max_distance:
        return max_distance + 1
    previous = list(range(len(right) + 1))
    for i, left_char in enumerate(left, start=1):
        current = [i]
        best = i
        for j, right_char in enumerate(right, start=1):
            value = min(
                current[j - 1] + 1,
                previous[j] + 1,
                previous[j - 1] + (left_char != right_char),
            )
            current.append(value)
            best = min(best, value)
        if best > max_distance:
            return max_distance + 1
        previous = current
    return previous[-1]


def check_typosquat(
    name: str, *, known: tuple[str, ...] = KNOWN_SKILL_NAMES
) -> TyposquatMatch | None:
    """Return the nearest known name when ``name`` is a likely imitation."""

    stripped = unicodedata.normalize("NFKC", name.strip())
    lowered = stripped.lower()
    if len(lowered) < 4:
        return None
    folded = _fold(lowered)
    # Only the exact spelling of a known name is the original.  A case variant or
    # a homograph that folds onto a known name is an imitation, not the original.
    if stripped in known:
        return None
    for item in known:
        if folded == _fold(item.lower()) and stripped != item:
            return TyposquatMatch(name=name, candidate=item, distance=0, normalised=folded)
    best: TyposquatMatch | None = None
    for candidate in known:
        candidate_lower = candidate.lower()
        candidate_folded = _fold(candidate_lower)
        distance = min(
            levenshtein(lowered, candidate_lower, max_distance=2),
            levenshtein(folded, candidate_folded, max_distance=2),
        )
        if distance > 2:
            continue
        # Very short candidates produce too many false positives.
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


__all__ = ["KNOWN_SKILL_NAMES", "TyposquatMatch", "check_typosquat", "levenshtein"]
