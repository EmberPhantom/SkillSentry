"""Deterministic evidence candidates for typed decision backends.

Candidates come only from deterministic anchor findings.  A backend may
classify a candidate, but it never supplies or invents the file, line, or code;
those stay code-owned and are copied into any finding that cites them.
"""

from __future__ import annotations

from skill_sentry.core.contracts import Severity, StageResult
from skill_sentry.core.decisions.base import EvidenceCandidate

MAX_CANDIDATES = 20
MAX_CODE_CHARS = 400


def build_candidates(
    anchors: StageResult,
    *,
    limit: int = MAX_CANDIDATES,
) -> tuple[list[EvidenceCandidate], int]:
    """Return ``(candidates, omitted)`` in anchor order.

    Notes, locationless findings, and duplicate ``(file, line)`` pairs are not
    candidates.  ``omitted`` counts anchors dropped by ``limit`` so callers can
    report the truncation instead of hiding it.
    """

    seen: set[tuple[str, int]] = set()
    candidates: list[EvidenceCandidate] = []
    omitted = 0
    for finding in anchors.findings:
        if finding.severity is Severity.NOTE:
            continue
        file = finding.evidence.file
        line = finding.evidence.line
        code = (finding.evidence.code or "").strip()
        if not file or not line or not code:
            continue
        key = (file, line)
        if key in seen:
            continue
        seen.add(key)
        if len(candidates) >= limit:
            omitted += 1
            continue
        try:
            candidates.append(
                EvidenceCandidate(
                    candidate_id=f"anchor-{len(candidates) + 1}",
                    file=file,
                    line=line,
                    code=code[:MAX_CODE_CHARS],
                    anchor_type=finding.finding_type or "anchor",
                )
            )
        except ValueError:
            # A file path the contract rejects is not evidence we can cite.
            continue
    return candidates, omitted


def candidate_state(candidates: list[EvidenceCandidate]) -> list[dict[str, object]]:
    """Serialise candidates for the decision state; no new locations are added."""

    return [
        {
            "candidate_id": candidate.candidate_id,
            "type": candidate.anchor_type,
            "file": candidate.file,
            "line": candidate.line,
            "code": candidate.code,
        }
        for candidate in candidates
    ]


__all__ = ["MAX_CANDIDATES", "build_candidates", "candidate_state"]
