"""Citation accuracy: anchor findings must point at the lines that carry the behaviour.

The ground truth is hand-annotated in tests/ground_truth/anchor_citations.json from
the fixture sources, so the score is not derived from the scanner's own output.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from skillsentry.core.parser import parse_skill
from skillsentry.core.semantic import scan_anchors

ROOT = Path(__file__).resolve().parents[2]
TRUTH = json.loads(
    (ROOT / "tests" / "ground_truth" / "anchor_citations.json").read_text(encoding="utf-8")
)


def _anchors(skill: str):  # type: ignore[no-untyped-def]
    return scan_anchors(parse_skill(ROOT / skill))


def test_citation_accuracy_meets_the_minimum() -> None:
    tolerance = TRUTH["tolerance"]
    cache: dict[str, object] = {}
    matched = 0
    misses: list[str] = []
    for item in TRUTH["malicious"]:
        if item["skill"] not in cache:
            cache[item["skill"]] = _anchors(item["skill"])
        stage = cache[item["skill"]]
        hit = any(
            finding.evidence.file == item["file"]
            and finding.evidence.line is not None
            and abs(finding.evidence.line - item["line"]) <= tolerance
            for finding in stage.findings  # type: ignore[attr-defined]
        )
        if hit:
            matched += 1
        else:
            misses.append(f"{item['skill']} {item['file']}:{item['line']} ({item['why']})")
    accuracy = matched / len(TRUTH["malicious"])
    assert accuracy >= TRUTH["minimum_accuracy"], (
        f"citation accuracy {accuracy:.2f}; missed: {misses}"
    )


@pytest.mark.parametrize("skill", TRUTH["benign"])
def test_benign_skills_get_no_critical_or_high_anchor(skill: str) -> None:
    stage = _anchors(skill)

    loud = [
        (finding.finding_type, finding.evidence.file, finding.evidence.line)
        for finding in stage.findings
        if finding.severity.value in ("critical", "high")
    ]
    assert loud == [], f"benign skill {skill} produced {loud}"
