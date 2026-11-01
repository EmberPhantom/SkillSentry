"""Sandbox execution plan (INT-4).

The plan says what the sandbox is asked to check and why.  Baseline checks are
always present.  Checks derived from deterministic anchors only add to them, and
nothing can remove a baseline check.  Only the declared entrypoint may run, and a
plan that fails validation blocks execution, so the stage degrades instead of
running with a partial or unsafe plan.
"""

from __future__ import annotations

from enum import Enum
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from skillsentry.core.contracts import StageResult
from skillsentry.core.parser import SkillPackage

MAX_CHECK_TIMEOUT_S = 600


class InstructionCategory(str, Enum):
    TRIGGER_EXECUTION = "TRIGGER_EXECUTION"
    CREDENTIAL_CANARY_MONITOR = "CREDENTIAL_CANARY_MONITOR"
    DNS_SINKHOLE_WATCH = "DNS_SINKHOLE_WATCH"
    HTTP_EXFIL_MONITOR = "HTTP_EXFIL_MONITOR"
    EVASION_PROBE_WATCH = "EVASION_PROBE_WATCH"


class InstructionSource(str, Enum):
    BASELINE = "baseline"
    DETERMINISTIC_ANCHOR = "deterministicAnchor"


BASELINE_CATEGORIES: tuple[InstructionCategory, ...] = (
    InstructionCategory.TRIGGER_EXECUTION,
    InstructionCategory.CREDENTIAL_CANARY_MONITOR,
    InstructionCategory.DNS_SINKHOLE_WATCH,
    InstructionCategory.HTTP_EXFIL_MONITOR,
    InstructionCategory.EVASION_PROBE_WATCH,
)

# Anchor finding types that call for an extra watch, on top of the baseline.
_ANCHOR_WATCHES: dict[str, InstructionCategory] = {
    "credential-path": InstructionCategory.CREDENTIAL_CANARY_MONITOR,
    "secret-access": InstructionCategory.CREDENTIAL_CANARY_MONITOR,
    "dns-lookup": InstructionCategory.DNS_SINKHOLE_WATCH,
    "exfil-http-post": InstructionCategory.HTTP_EXFIL_MONITOR,
    "raw-socket": InstructionCategory.HTTP_EXFIL_MONITOR,
    "reverse-shell": InstructionCategory.HTTP_EXFIL_MONITOR,
    "sandbox-artifact": InstructionCategory.EVASION_PROBE_WATCH,
}


class SandboxActionInstruction(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instruction_id: str = Field(min_length=1, max_length=80)
    category: InstructionCategory
    reason: str = Field(min_length=1, max_length=500)
    source: InstructionSource
    check: str = Field(min_length=1, max_length=200)
    timeout_s: int = Field(ge=1, le=MAX_CHECK_TIMEOUT_S)
    required: bool


class SandboxExecutionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid")

    instructions: list[SandboxActionInstruction] = Field(default_factory=list)
    baseline_instructions: list[SandboxActionInstruction] = Field(default_factory=list)
    declared_entrypoint: list[str] = Field(default_factory=list)
    canary_context: str = ""
    validation_status: Literal["valid", "invalid"] = "invalid"
    problems: list[str] = Field(default_factory=list)


def _baseline(timeout_s: int) -> list[SandboxActionInstruction]:
    return [
        SandboxActionInstruction(
            instruction_id=f"baseline-{category.value.lower()}",
            category=category,
            reason="always checked for every skill",
            source=InstructionSource.BASELINE,
            check=category.value,
            timeout_s=timeout_s,
            required=True,
        )
        for category in BASELINE_CATEGORIES
    ]


def build_plan(
    package: SkillPackage,
    anchors: StageResult,
    *,
    timeout_s: int,
) -> SandboxExecutionPlan:
    """Build and validate the plan for one skill.

    Anchor-derived watches are additive and optional.  The plan is valid only when
    every baseline category is present, the entrypoint is declared, and every
    timeout is within bounds.
    """

    timeout = max(1, min(int(timeout_s), MAX_CHECK_TIMEOUT_S))
    baseline = _baseline(timeout)
    additions: list[SandboxActionInstruction] = []
    seen: set[tuple[str, str]] = set()
    for finding in anchors.findings:
        category = _ANCHOR_WATCHES.get(finding.finding_type or "")
        if category is None:
            continue
        key = (category.value, finding.evidence.file or "")
        if key in seen:
            continue
        seen.add(key)
        additions.append(
            SandboxActionInstruction(
                instruction_id=f"anchor-{len(additions) + 1}-{category.value.lower()}",
                category=category,
                reason=(finding.message or "deterministic anchor")[:500],
                source=InstructionSource.DETERMINISTIC_ANCHOR,
                check=category.value,
                timeout_s=timeout,
                required=False,
            )
        )

    plan = SandboxExecutionPlan(
        instructions=baseline + additions,
        baseline_instructions=baseline,
        declared_entrypoint=list(package.entrypoint or []),
        canary_context=(package.declared_intent or "")[:200],
    )
    problems = validate_plan(plan)
    plan.problems = problems
    plan.validation_status = "invalid" if problems else "valid"
    return plan


def validate_plan(plan: SandboxExecutionPlan) -> list[str]:
    """Return the reasons a plan must not run; an empty list means it may run."""

    problems: list[str] = []
    if not plan.declared_entrypoint:
        problems.append(
            "no declared entrypoint, so the scripts were not executed; declare 'entrypoint:' "
            "in SKILL.md so they can be tested. A fallback command is never guessed"
        )
    present = {instruction.category for instruction in plan.baseline_instructions}
    missing = [category.value for category in BASELINE_CATEGORIES if category not in present]
    if missing:
        problems.append(f"baseline checks missing: {', '.join(missing)}")
    for instruction in plan.instructions:
        if not 1 <= instruction.timeout_s <= MAX_CHECK_TIMEOUT_S:
            problems.append(f"timeout out of bounds for {instruction.instruction_id}")
    return problems


__all__ = [
    "BASELINE_CATEGORIES",
    "InstructionCategory",
    "InstructionSource",
    "SandboxActionInstruction",
    "SandboxExecutionPlan",
    "build_plan",
    "validate_plan",
]
