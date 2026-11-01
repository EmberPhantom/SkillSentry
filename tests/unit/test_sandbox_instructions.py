"""Sandbox execution plan (INT-4): baseline always present, additive anchors, fail-closed validation."""

from __future__ import annotations

from pathlib import Path

import pytest
from skill_sentry.core.contracts import Finding, FindingEvidence, Severity, Stage, StageResult
from skill_sentry.core.parser import parse_skill
from skill_sentry.core.sandbox.instructions import (
    BASELINE_CATEGORIES,
    InstructionCategory,
    SandboxExecutionPlan,
    build_plan,
    validate_plan,
)


def _skill(tmp_path: Path, *, entrypoint: bool = True) -> object:
    root = tmp_path / "skill"
    (root / "scripts").mkdir(parents=True)
    head = "entrypoint: python scripts/run.py\n" if entrypoint else ""
    (root / "SKILL.md").write_text(
        f"---\nname: demo\ndescription: Demo skill\n{head}---\nBody\n", encoding="utf-8"
    )
    (root / "scripts" / "run.py").write_text("print('hi')\n", encoding="utf-8")
    return parse_skill(root)


def _anchors(*types: str) -> StageResult:
    return StageResult(
        stage=Stage.DETERMINISTIC_ANCHOR,
        findings=[
            Finding(
                stage=Stage.DETERMINISTIC_ANCHOR,
                severity=Severity.HIGH,
                message=f"anchor {kind}",
                type=kind,
                evidence=FindingEvidence(file="scripts/run.py", line=1, code="x"),
            )
            for kind in types
        ],
    )


def test_baseline_checks_are_always_present(tmp_path: Path) -> None:
    plan = build_plan(_skill(tmp_path), StageResult(stage=Stage.DETERMINISTIC_ANCHOR), timeout_s=30)

    present = {item.category for item in plan.baseline_instructions}
    assert present == set(BASELINE_CATEGORIES)
    assert plan.validation_status == "valid"
    assert plan.problems == []


def test_anchors_only_add_checks_never_remove_baseline(tmp_path: Path) -> None:
    plan = build_plan(
        _skill(tmp_path),
        _anchors("credential-path", "dns-lookup"),
        timeout_s=30,
    )

    baseline = {item.category for item in plan.baseline_instructions}
    assert baseline == set(BASELINE_CATEGORIES)
    added = [item for item in plan.instructions if not item.required]
    assert {item.category for item in added} == {
        InstructionCategory.CREDENTIAL_CANARY_MONITOR,
        InstructionCategory.DNS_SINKHOLE_WATCH,
    }
    assert all(item.source.value == "deterministicAnchor" for item in added)


def test_unknown_anchor_types_add_nothing(tmp_path: Path) -> None:
    plan = build_plan(_skill(tmp_path), _anchors("some-other-rule"), timeout_s=30)

    assert len(plan.instructions) == len(BASELINE_CATEGORIES)


def test_missing_entrypoint_makes_the_plan_invalid(tmp_path: Path) -> None:
    plan = build_plan(
        _skill(tmp_path, entrypoint=False),
        StageResult(stage=Stage.DETERMINISTIC_ANCHOR),
        timeout_s=30,
    )

    assert plan.validation_status == "invalid"
    assert any("entrypoint" in problem for problem in plan.problems)
    assert any("declare 'entrypoint:'" in problem for problem in plan.problems)


def test_a_plan_missing_a_baseline_check_is_rejected(tmp_path: Path) -> None:
    plan = build_plan(_skill(tmp_path), StageResult(stage=Stage.DETERMINISTIC_ANCHOR), timeout_s=30)
    trimmed = plan.model_copy(
        update={
            "baseline_instructions": [
                item
                for item in plan.baseline_instructions
                if item.category is not InstructionCategory.EVASION_PROBE_WATCH
            ]
        }
    )

    problems = validate_plan(trimmed)

    assert any("EVASION_PROBE_WATCH" in problem for problem in problems)


def test_timeouts_are_clamped_into_bounds(tmp_path: Path) -> None:
    plan = build_plan(
        _skill(tmp_path), StageResult(stage=Stage.DETERMINISTIC_ANCHOR), timeout_s=10_000
    )

    assert all(1 <= item.timeout_s <= 600 for item in plan.instructions)
    assert plan.validation_status == "valid"


def test_plan_round_trips_through_json(tmp_path: Path) -> None:
    plan = build_plan(_skill(tmp_path), _anchors("raw-socket"), timeout_s=30)

    restored = SandboxExecutionPlan.model_validate_json(plan.model_dump_json())

    assert restored == plan


@pytest.mark.parametrize("bad", ["extra", "timeout"])
def test_unknown_or_out_of_range_fields_are_rejected(bad: str) -> None:
    from pydantic import ValidationError
    from skill_sentry.core.sandbox.instructions import SandboxActionInstruction

    if bad == "extra":
        with pytest.raises(ValidationError):
            SandboxActionInstruction(
                instruction_id="x",
                category=InstructionCategory.TRIGGER_EXECUTION,
                reason="r",
                source="baseline",
                check="c",
                timeout_s=5,
                required=True,
                surprise=1,  # type: ignore[call-arg]
            )
    else:
        with pytest.raises(ValidationError):
            SandboxActionInstruction(
                instruction_id="x",
                category=InstructionCategory.TRIGGER_EXECUTION,
                reason="r",
                source="baseline",
                check="c",
                timeout_s=0,
                required=True,
            )
