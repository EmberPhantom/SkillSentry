"""SARIF output must validate against the official SARIF 2.1.0 schema.

The schema is vendored at tests/fixtures/sarif/sarif-schema-2.1.0.json so the
test does not depend on network access or on the untracked calibration folder.
"""

from __future__ import annotations

import json
from pathlib import Path
from uuid import uuid4

import jsonschema
from skill_sentry_cli.core.contracts import (
    ExportFormat,
    Finding,
    FindingEvidence,
    Severity,
    Stage,
    Verdict,
    VerdictTier,
)
from skill_sentry_cli.core.reports import render_report

ROOT = Path(__file__).resolve().parents[2]
SCHEMA = json.loads(
    (ROOT / "tests" / "fixtures" / "sarif" / "sarif-schema-2.1.0.json").read_text(encoding="utf-8")
)


def _verdict(findings: list[Finding]) -> Verdict:
    return Verdict(
        skill="demo",
        skill_id=uuid4(),
        scan_id=uuid4(),
        verdict=VerdictTier.MALICIOUS if findings else VerdictTier.SAFE,
        risk_score=90 if findings else 0,
        confidence=0.9,
        cached=False,
        scan_duration_ms=5,
        findings=findings,
    )


def _validate(verdict: Verdict) -> list[str]:
    document = json.loads(render_report(verdict, ExportFormat.SARIF).content)
    validator = jsonschema.Draft7Validator(SCHEMA)
    return [error.message for error in validator.iter_errors(document)]


def test_sarif_with_a_finding_validates_against_2_1_0() -> None:
    finding = Finding(
        stage=Stage.DETERMINISTIC_ANCHOR,
        severity=Severity.HIGH,
        message="pipe to shell",
        finding_type="shell-exec",
        evidence=FindingEvidence(file="scripts/a.sh", line=3, code="curl x | sh"),
    )

    assert _validate(_verdict([finding])) == []


def test_sarif_with_no_findings_validates_against_2_1_0() -> None:
    assert _validate(_verdict([])) == []
