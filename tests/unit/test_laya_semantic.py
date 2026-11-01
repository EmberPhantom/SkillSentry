"""Laya semantic analyzer: mapping, evidence provenance, and instruction floor."""

from __future__ import annotations

from pathlib import Path

from skill_sentry.core.contracts import Finding, FindingEvidence, Severity, Stage, StageResult
from skill_sentry.core.decisions import DecisionAnswer, MockDecisionClient
from skill_sentry.core.parser import parse_skill
from skill_sentry.core.semantic.candidates import MAX_CANDIDATES, build_candidates
from skill_sentry.core.semantic.laya_analyzer import analyze_semantics_laya


def _write_skill(root: Path, *, body: str = "Summarise the document.\n") -> Path:
    root.mkdir(parents=True, exist_ok=True)
    (root / "SKILL.md").write_text(
        "---\nname: demo-skill\ndescription: Summarise documents\n---\n" + body,
        encoding="utf-8",
    )
    (root / "scripts").mkdir(exist_ok=True)
    (root / "scripts" / "sync.py").write_text(
        "import os\ntoken = os.environ['API_TOKEN']\n",
        encoding="utf-8",
    )
    return root


def _anchor(
    *,
    file: str = "scripts/sync.py",
    line: int = 2,
    code: str = "token = os.environ['API_TOKEN']",
    finding_type: str = "credential-read",
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        stage=Stage.DETERMINISTIC_ANCHOR,
        severity=severity,
        message="anchor",
        type=finding_type,
        evidence=FindingEvidence(file=file, line=line, code=code),
    )


def _anchors(*findings: Finding) -> StageResult:
    return StageResult(stage=Stage.DETERMINISTIC_ANCHOR, findings=list(findings))


def test_candidates_come_only_from_located_non_note_anchors() -> None:
    anchors = _anchors(
        _anchor(),
        _anchor(severity=Severity.NOTE, line=9),
        _anchor(line=3, code=""),
        _anchor(),  # duplicate (file, line)
    )

    candidates, omitted = build_candidates(anchors)

    assert [c.candidate_id for c in candidates] == ["anchor-1"]
    assert candidates[0].file == "scripts/sync.py"
    assert candidates[0].line == 2
    assert omitted == 0


def test_candidates_over_limit_are_counted_not_silently_dropped() -> None:
    anchors = _anchors(*(_anchor(line=n, code=f"x{n}") for n in range(1, MAX_CANDIDATES + 6)))

    candidates, omitted = build_candidates(anchors)

    assert len(candidates) == MAX_CANDIDATES
    assert omitted == 5


def test_capability_finding_cites_code_owned_location(tmp_path: Path) -> None:
    package = parse_skill(_write_skill(tmp_path / "skill"))
    anchors = _anchors(_anchor())
    client = MockDecisionClient(
        answers={"cap_credentials": DecisionAnswer(noul=0.95, confidence=0.9)},
    )

    stage = analyze_semantics_laya(package, anchors, client)

    capability = [f for f in stage.findings if f.finding_type == "cap_credentials"]
    assert len(capability) == 1
    assert capability[0].severity is Severity.HIGH
    assert capability[0].evidence.file == "scripts/sync.py"
    assert capability[0].evidence.line == 2
    assert capability[0].evidence.code == "token = os.environ['API_TOKEN']"
    assert stage.signals["semantic"] >= 72
    assert stage.degraded is False


def test_below_threshold_capability_creates_no_finding(tmp_path: Path) -> None:
    package = parse_skill(_write_skill(tmp_path / "skill"))
    client = MockDecisionClient(
        answers={"cap_credentials": DecisionAnswer(noul=0.2, confidence=0.9)},
    )

    stage = analyze_semantics_laya(package, _anchors(_anchor()), client)

    assert not [f for f in stage.findings if f.finding_type == "cap_credentials"]


def test_benign_answer_cannot_lower_instruction_floor(tmp_path: Path) -> None:
    package = parse_skill(_write_skill(tmp_path / "skill"))
    anchors = _anchors(_anchor(finding_type="instruction-injection", severity=Severity.CRITICAL))
    benign = MockDecisionClient(
        "benign",
        answers={
            "deception": DecisionAnswer(choice="consistent", confidence=0.99),
            "cap_credentials": DecisionAnswer(noul=0.0, confidence=0.99),
        },
    )

    stage = analyze_semantics_laya(package, anchors, benign)

    assert stage.signals["semantic"] == 95
    assert stage.telemetry["instruction_floor"] == 95


def test_deceptive_answer_creates_high_finding_on_skill_md(tmp_path: Path) -> None:
    package = parse_skill(_write_skill(tmp_path / "skill"))
    client = MockDecisionClient(
        answers={"deception": DecisionAnswer(choice="deceptive", confidence=0.9)},
    )

    stage = analyze_semantics_laya(package, _anchors(), client)

    deception = [f for f in stage.findings if f.finding_type == "deception"]
    assert len(deception) == 1
    assert deception[0].severity is Severity.HIGH
    assert deception[0].evidence.file == "SKILL.md"
    assert stage.telemetry["is_deceptive"] is True


def test_low_confidence_caps_severity_and_adds_review_note(tmp_path: Path) -> None:
    package = parse_skill(_write_skill(tmp_path / "skill"))
    client = MockDecisionClient(
        answers={"cap_credentials": DecisionAnswer(noul=0.95, confidence=0.3)},
    )

    stage = analyze_semantics_laya(package, _anchors(_anchor()), client)

    capability = [f for f in stage.findings if f.finding_type == "cap_credentials"]
    assert capability[0].severity is Severity.MEDIUM
    assert any(f.finding_type == "semantic-low-confidence" for f in stage.findings)


def test_unanchored_capability_is_a_note_with_no_score(tmp_path: Path) -> None:
    package = parse_skill(_write_skill(tmp_path / "skill"))
    client = MockDecisionClient(
        "benign",
        answers={
            "cap_upload": DecisionAnswer(noul=0.95, confidence=0.9),
            "deception": DecisionAnswer(choice="consistent", confidence=0.9),
        },
    )

    stage = analyze_semantics_laya(package, _anchors(), client)

    assert not [f for f in stage.findings if f.finding_type == "cap_upload"]
    notes = [f for f in stage.findings if f.finding_type == "semantic-unanchored-capability"]
    assert len(notes) == 1
    assert notes[0].severity is Severity.NOTE
    assert stage.signals["semantic"] == 0


def test_truncated_context_is_reported(tmp_path: Path) -> None:
    package = parse_skill(_write_skill(tmp_path / "skill"))
    anchors = _anchors(*(_anchor(line=n, code=f"x{n}") for n in range(1, MAX_CANDIDATES + 4)))

    stage = analyze_semantics_laya(package, anchors, MockDecisionClient("benign"))

    truncated = [f for f in stage.findings if f.finding_type == "semantic-context-truncated"]
    assert len(truncated) == 1
    assert stage.telemetry["candidates_omitted"] == 3


def test_successful_stage_is_never_reported_clean_when_findings_exist(tmp_path: Path) -> None:
    package = parse_skill(_write_skill(tmp_path / "skill"))
    client = MockDecisionClient(
        answers={"cap_process": DecisionAnswer(noul=0.9, confidence=0.9)},
    )

    stage = analyze_semantics_laya(package, _anchors(_anchor()), client)

    assert not [f for f in stage.findings if f.finding_type == "semantic-clean"]


def _two_anchors() -> StageResult:
    return _anchors(
        _anchor(line=2, code="token = os.environ['API_TOKEN']"),
        _anchor(line=5, code="requests.post(url, data=payload)", finding_type="network-call"),
    )


def test_adjudication_cites_the_highest_probability_candidate(tmp_path: Path) -> None:
    package = parse_skill(_write_skill(tmp_path / "skill"))
    client = MockDecisionClient(
        "benign",
        answers={
            "cap_upload": DecisionAnswer(noul=0.95, confidence=0.9),
            "adj_anchor-1": DecisionAnswer(noul=0.10, confidence=0.9),
            "adj_anchor-2": DecisionAnswer(noul=0.92, confidence=0.9),
        },
    )

    stage = analyze_semantics_laya(package, _two_anchors(), client)

    capability = [f for f in stage.findings if f.finding_type == "cap_upload"]
    assert len(capability) == 1
    assert capability[0].evidence.line == 5
    assert capability[0].evidence.code == "requests.post(url, data=payload)"
    assert stage.telemetry["decisions"]["adjudicated"] is True


def test_low_adjudicated_probability_downgrades_capability_to_note(tmp_path: Path) -> None:
    package = parse_skill(_write_skill(tmp_path / "skill"))
    client = MockDecisionClient(
        "benign",
        answers={
            "cap_credentials": DecisionAnswer(noul=0.95, confidence=0.9),
            "adj_anchor-1": DecisionAnswer(noul=0.05, confidence=0.9),
            "adj_anchor-2": DecisionAnswer(noul=0.08, confidence=0.9),
        },
    )

    stage = analyze_semantics_laya(package, _two_anchors(), client)

    capability = [f for f in stage.findings if f.finding_type == "cap_credentials"]
    assert capability[0].severity is Severity.NOTE
    assert stage.signals["semantic"] == 0


class _AdjudicationFailsClient(MockDecisionClient):
    """Main questions answer normally; any adjudication call fails."""

    def decide(self, state, questions, *, timeout_s=None):  # type: ignore[no-untyped-def]
        if any(qid.startswith("adj_") for qid in questions):
            raise RuntimeError("adjudication pass timed out")
        return super().decide(state, questions, timeout_s=timeout_s)


def test_adjudication_failure_is_non_fatal_and_disclosed(tmp_path: Path) -> None:
    package = parse_skill(_write_skill(tmp_path / "skill"))
    client = _AdjudicationFailsClient(
        "benign",
        answers={"cap_upload": DecisionAnswer(noul=0.95, confidence=0.9)},
    )

    stage = analyze_semantics_laya(package, _two_anchors(), client)

    assert stage.degraded is False
    capability = [f for f in stage.findings if f.finding_type == "cap_upload"]
    assert capability[0].severity is not Severity.NOTE
    assert capability[0].evidence.line == 2  # first anchor, disclosed by the note
    notes = [f for f in stage.findings if f.finding_type == "semantic-adjudication-unavailable"]
    assert len(notes) == 1
    assert "timed out" in notes[0].message
