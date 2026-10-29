"""
Typosquatting Detection Engine (Stage 1).

Identifies deceptive skill names designed to trick users or autonomous
agents into installing malicious clones of popular packages.

Algorithm: homoglyph folding → Damerau-Levenshtein distance ≤ 2 against
a curated dictionary of known legitimate skill names.

CL-D2-1 · REQ-TYPO-01 · Source: docs/02-architecture.md §2.3,
developer-2/03-functional-specifications.md Cap B.
"""

from __future__ import annotations

import importlib.resources
import json
import unicodedata
from pathlib import Path
from typing import Optional

from skillsentry_dev2.contracts import Finding, StageResult

# ── Homoglyph / Leet-Speak / Unicode Lookalike Folding Map (DEF-15) ─────

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

# Multi-char substitutions applied after single-char folding
MULTI_HOMOGLYPHS: list[tuple[str, str]] = [
    ("vv", "w"),
    ("rn", "m"),
    ("cl", "d"),
    ("nn", "m"),
]


def _fold_homoglyphs(name: str) -> str:
    """Apply NFKC normalization, Unicode lookalikes, and leet-speak folding (DEF-15)."""
    # Unicode NFKC normalization
    normalized = unicodedata.normalize("NFKC", name)
    folded = normalized.lower()
    # Single-char substitutions
    folded = "".join(HOMOGLYPH_MAP.get(c, c) for c in folded)
    # Multi-char substitutions
    for pattern, replacement in MULTI_HOMOGLYPHS:
        folded = folded.replace(pattern, replacement)
    return folded


# ── Damerau-Levenshtein Distance ────────────────────────────────────────

def _damerau_levenshtein(s1: str, s2: str) -> int:
    """Compute the Damerau-Levenshtein distance between two strings.

    Supports insertions, deletions, substitutions, and transpositions.
    """
    len1 = len(s1)
    len2 = len(s2)

    # Quick exit for trivial cases
    if s1 == s2:
        return 0
    if len1 == 0:
        return len2
    if len2 == 0:
        return len1

    # Create matrix
    d: list[list[int]] = [[0] * (len2 + 1) for _ in range(len1 + 1)]

    for i in range(len1 + 1):
        d[i][0] = i
    for j in range(len2 + 1):
        d[0][j] = j

    for i in range(1, len1 + 1):
        for j in range(1, len2 + 1):
            cost = 0 if s1[i - 1] == s2[j - 1] else 1

            d[i][j] = min(
                d[i - 1][j] + 1,       # deletion
                d[i][j - 1] + 1,       # insertion
                d[i - 1][j - 1] + cost,  # substitution
            )

            # Transposition
            if (
                i > 1
                and j > 1
                and s1[i - 1] == s2[j - 2]
                and s1[i - 2] == s2[j - 1]
            ):
                d[i][j] = min(d[i][j], d[i - 2][j - 2] + cost)

    return d[len1][len2]


# ── Known Skills Dictionary ────────────────────────────────────────────

# Curated list of ~55 popular/standard agent skill names.
# CL-D2-8: Now loaded from versioned JSON file with inline fallback.
# See data/known_skills_v1.json for the canonical source.
DICTIONARY_VERSION = "1.0.0"

_DICTIONARY_PATH = Path(__file__).resolve().parent.parent.parent / "data" / "known_skills_v1.json"


def _load_known_skills_from_file() -> list[str]:
    """Load known skill names from the versioned JSON package data file (DEF-15, N7)."""
    # 1. Package resources (works in wheel installs and editable installs)
    try:
        ref = importlib.resources.files("skillsentry_dev2.data").joinpath("known_skills_v1.json")
        with ref.open("r", encoding="utf-8") as f:
            data = json.load(f)
            entries = [entry["name"] for entry in data.get("entries", [])]
            if entries:
                return entries
    except Exception:
        pass

    # 2. Direct relative path to package data directory
    try:
        if _DICTIONARY_PATH.is_file():
            with open(_DICTIONARY_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                entries = [entry["name"] for entry in data.get("entries", [])]
                if entries:
                    return entries
    except Exception:
        pass

    return []


def _load_legitimate_pairs_from_file() -> frozenset[tuple[str, str]]:
    """Load legitimate pairs from the versioned JSON package data file (DEF-15, N7)."""
    # 1. Package resources
    try:
        ref = importlib.resources.files("skillsentry_dev2.data").joinpath("known_skills_v1.json")
        with ref.open("r", encoding="utf-8") as f:
            data = json.load(f)
            pairs = set()
            for pair in data.get("legitimate_pairs", []):
                if len(pair) == 2:
                    pairs.add((min(pair[0], pair[1]), max(pair[0], pair[1])))
            if pairs:
                return frozenset(pairs)
    except Exception:
        pass

    # 2. Direct relative path
    try:
        if _DICTIONARY_PATH.is_file():
            with open(_DICTIONARY_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
                pairs = set()
                for pair in data.get("legitimate_pairs", []):
                    if len(pair) == 2:
                        pairs.add((min(pair[0], pair[1]), max(pair[0], pair[1])))
                if pairs:
                    return frozenset(pairs)
    except Exception:
        pass

    return frozenset()


# Inline fallback list — used if data file is missing (e.g. in unit tests)
_FALLBACK_KNOWN_SKILLS: list[str] = [
    # Git/DevOps
    "git-translate", "git-helper", "git-commit", "git-review",
    "github-pr", "github-actions", "gitlab-ci",
    # Cloud
    "aws-sync", "aws-deploy", "aws-lambda", "azure-deploy",
    "cloud-sync", "cloud-backup", "cloud-deploy",
    # Container/K8s
    "docker-compose", "docker-build", "kubernetes-tools",
    "k8s-deploy", "helm-chart",
    # Communication
    "slack-notify", "slack-bot", "slack-message",
    "discord-bot", "teams-notify", "email-sender",
    # Data/AI
    "pdf-summarizer", "csv-analyzer", "json-formatter",
    "data-pipeline", "ml-trainer",
    # Web/API
    "api-tester", "http-client", "web-scraper",
    "url-shortener", "webhook-handler",
    # File/System
    "file-manager", "image-resizer", "video-converter",
    "backup-tool", "zip-extractor",
    # Security
    "password-gen", "ssh-manager", "cert-checker",
    "vuln-scanner", "secret-rotator",
    # Development
    "code-formatter", "lint-runner", "test-runner",
    "dependency-checker", "changelog-gen",
    # Weather/Utility
    "weather-fetch", "weather-bot", "time-tracker",
    "calculator", "translator",
]

# Resolve at module load: prefer versioned file, fall back to inline list
KNOWN_SKILLS: list[str] = _load_known_skills_from_file() or _FALLBACK_KNOWN_SKILLS

# Alias/dispute metadata: names that are legitimately close but NOT typosquats
LEGITIMATE_PAIRS: frozenset[tuple[str, str]] = (
    _load_legitimate_pairs_from_file()
    or frozenset({
        ("git-helper", "git-translate"),
        ("slack-notify", "slack-message"),
        ("cloud-sync", "cloud-backup"),
        ("aws-sync", "aws-deploy"),
    })
)


def _is_legitimate_pair(name1: str, name2: str) -> bool:
    """Check if two names are a known legitimate pair (not typosquats)."""
    pair = (min(name1, name2), max(name1, name2))
    return pair in LEGITIMATE_PAIRS


# ── Public API ──────────────────────────────────────────────────────────

def check_typosquat(
    candidate_name: str,
    known_skills: Optional[list[str]] = None,
) -> StageResult:
    """Check if a skill name is a potential typosquat of a known skill.

    Args:
        candidate_name: The name of the skill being audited.
        known_skills: Optional override for the known skills dictionary.

    Returns:
        StageResult with stage='typosquat' and findings if detected.
    """
    if known_skills is None:
        known_skills = KNOWN_SKILLS

    findings: list[Finding] = []
    signals: dict[str, float] = {"typosquat_detected": 0.0}

    if not candidate_name:
        return StageResult(stage="typosquat", findings=findings, signals=signals)

    # Normalize candidate
    candidate_lower = candidate_name.lower().strip()
    candidate_folded = _fold_homoglyphs(candidate_lower)

    best_match: Optional[str] = None
    best_distance: int = 999

    for known_name in known_skills:
        known_lower = known_name.lower()
        known_folded = _fold_homoglyphs(known_lower)

        # Check case-variant impersonation (DEF-15)
        if candidate_lower == known_lower:
            if candidate_name.strip() != known_name:
                findings.append(Finding(
                    stage="typosquat",
                    severity="medium",
                    message=(
                        f"Potential typosquat of '{known_name}' "
                        f"(case-variant impersonation: '{candidate_name}')"
                    ),
                ))
                signals["typosquat_detected"] = 100.0
                return StageResult(
                    stage="typosquat",
                    findings=findings,
                    signals=signals,
                )
            # Legitimate identical match
            continue

        # Check if homoglyph-folded version exactly matches a known name
        if candidate_folded == known_folded:
            # Exact match after folding = impersonation attempt
            if not _is_legitimate_pair(candidate_lower, known_lower):
                findings.append(Finding(
                    stage="typosquat",
                    severity="medium",
                    message=(
                        f"Potential typosquat of '{known_name}' "
                        f"(homoglyph impersonation: '{candidate_name}' folds to '{known_folded}')"
                    ),
                ))
                signals["typosquat_detected"] = 100.0
                return StageResult(
                    stage="typosquat",
                    findings=findings,
                    signals=signals,
                )

        # Compute distance on folded versions
        dist = _damerau_levenshtein(candidate_folded, known_folded)

        if dist <= 2 and dist > 0:
            if not _is_legitimate_pair(candidate_lower, known_lower):
                if dist < best_distance:
                    best_distance = dist
                    best_match = known_name

    if best_match is not None:
        findings.append(Finding(
            stage="typosquat",
            severity="medium",
            message=(
                f"Potential typosquat of '{best_match}' "
                f"(distance: {best_distance})"
            ),
        ))
        signals["typosquat_detected"] = 100.0

    return StageResult(
        stage="typosquat",
        findings=findings,
        signals=signals,
    )

