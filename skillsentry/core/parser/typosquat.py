"""Typosquat / homograph detection for skill names.

The known-name list is intentionally small and local: this is a supply-chain
warning signal, not a verdict by itself.  The matching rules are conservative
(normalised Levenshtein distance <= 2 for names of at least four characters)
and exact names are never flagged.
"""

from __future__ import annotations

from dataclasses import dataclass

KNOWN_SKILL_NAMES: tuple[str, ...] = (
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


def _fold(value: str) -> str:
    folded = value.lower().translate(_TRANSLATION)
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

    lowered = name.strip().lower()
    if len(lowered) < 4:
        return None
    folded = _fold(lowered)
    if lowered in {item.lower() for item in known} or folded in {_fold(item) for item in known}:
        return None
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
