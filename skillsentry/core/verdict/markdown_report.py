"""Human-readable Markdown triage report."""

from __future__ import annotations

import html
from datetime import datetime
from typing import Any

from skillsentry.core.contracts import (
    ActiveDefense,
    Finding,
    Severity,
    Verdict,
    format_utc,
    utc_now,
)
from skillsentry.core.version import ENGINE_VERSION, GEMMA_BADGE

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.NOTE,
]


def _cell(value: object) -> str:
    return str(value).replace("|", "\\|").replace("\n", " ")


def _code(value: str) -> str:
    return "`" + value.replace("`", "\\`") + "`"


def _evidence_line(finding: Finding) -> str:
    evidence = finding.evidence
    parts: list[str] = []
    if evidence.file:
        location = evidence.file
        if evidence.line:
            location += f":{evidence.line}"
        parts.append(_code(location))
    for key in ("c2", "marker", "domain", "ip", "url", "path", "channel", "process"):
        value = getattr(evidence, key, None)
        if value:
            parts.append(f"{key}={_code(str(value))}")
    if evidence.ocr:
        parts.append(f"ocr={_code(evidence.ocr)}")
    if evidence.bbox:
        parts.append("bbox=" + _code(str(evidence.bbox)))
    return " · ".join(parts) if parts else "—"


def _active_defense_section(active: ActiveDefense | None) -> list[str]:
    lines = ["## ☠️ Active Defense (Poisoned Well)", ""]
    if active is None:
        lines.append("_Sandbox/deception stages did not run for this scan._")
        return lines
    if not active.triggered:
        lines.append("No active-defense events — nothing touched the honeypots ✓")
        if active.sandbox_evasion_detected:
            lines.append("")
            lines.append("**⚠️ Sandbox evasion probes were detected.**")
        return lines

    lines += [
        "| Field | Value |",
        "|:---|:---|",
        f"| Targeted assets | {_cell(', '.join(active.targeted_assets) or '—')} |",
        f"| Exfil channel | {_cell(active.exfil_channel.value if active.exfil_channel else '—')} |",
        f"| Canary marker | {_cell(active.canary_marker or '—')} |",
        f"| Secondary canary | {_cell(active.secondary_canary or '—')} |",
        f"| C2 indicators | {_cell(', '.join(active.c2_indicators) or '—')} |",
        f"| Encoding | {_cell(active.encoding or '—')} |",
        f"| Declared intent | {_cell(active.declared_intent or '—')} |",
        f"| Actual behavior | {_cell(active.actual_behavior or '—')} |",
        f"| Context-aware canary | {_cell(active.context_aware_canary.value if active.context_aware_canary else '—')} |",
        f"| Sandbox evasion | {'yes' if active.sandbox_evasion_detected else 'no'} |",
    ]
    if active.ioc_export:
        lines += ["", f"STIX bundle: {_code(active.ioc_export)}"]
    return lines


def _decision_lines(decision: dict[str, Any] | None) -> list[str]:
    if decision is None:
        return ["## Decision layer", "", "Not recorded for this export.", ""]
    error = decision.get("semantic_error")
    semantic = (
        f"degraded: {html.escape(str(error))}" if decision.get("semantic_degraded") else "complete"
    )
    threshold = decision.get("threshold")
    lines = [
        "## Decision layer",
        "",
        "| Field | Value |",
        "|:---|:---|",
        f"| Semantic backend | {_code(str(decision.get('decision_backend')))} |",
        f"| Checkpoint | {_code(str(decision.get('checkpoint') or 'n/a'))} |",
        f"| Model version | {_code(str(decision.get('model_version') or 'n/a'))} |",
        f"| Calibration | {_code(str(decision.get('calibration_version')))} |",
        f"| Capability threshold | {threshold if threshold is not None else 'n/a'} |",
        f"| Semantic stage | {semantic} |",
        f"| Vision | {_code(str(decision.get('vision_status')))} |",
        "",
    ]
    capabilities = decision.get("capabilities") or {}
    if capabilities:
        lines += ["Capability probabilities (advisory, not verdicts):", ""]
        lines += [f"- `{qid}`: {value:.2f}" for qid, value in sorted(capabilities.items())]
        lines.append("")
    return lines


def build_markdown(
    verdict: Verdict,
    *,
    generated_at: datetime | None = None,
    decision: dict[str, Any] | None = None,
) -> str:
    """Render a human triage report with line-accurate citations.

    ``decision`` is the report-safe summary from
    :func:`skillsentry.core.decisions.report.decision_summary`.  Omit it and the
    report says the decision layer was not recorded rather than implying clean.
    """
    generated = format_utc(generated_at or utc_now())
    lines: list[str] = [
        f"# SkillSentry Triage Report — {html.escape(verdict.skill)}",
        "",
        "| Field | Value |",
        "|:---|:---|",
        f"| Verdict | **{verdict.verdict.value}** |",
        f"| Risk score | {verdict.risk_score} / 100 |",
        f"| Confidence | {verdict.confidence:.2f} |",
        f"| Cached | {'⚡ yes' if verdict.cached else 'no'} |",
        f"| Scan duration | {verdict.scan_duration_ms} ms |",
        f"| Skill ID | {_code(str(verdict.skill_id))} |",
        f"| Scan ID | {_code(str(verdict.scan_id))} |",
        f"| Engine | {_code(ENGINE_VERSION)} |",
        f"| Generated | {generated} |",
        "",
    ]
    lines += _decision_lines(decision)
    lines += ["## Findings", ""]

    if not verdict.findings:
        lines.append("No findings. The skill is within the SAFE threshold.")
    else:
        for severity in _SEVERITY_ORDER:
            group = [f for f in verdict.findings if f.severity == severity]
            if not group:
                continue
            lines.append(f"### {severity.value.upper()} ({len(group)})")
            lines.append("")
            for finding in group:
                stage = finding.stage.value
                if decision is not None and finding.stage.value == "semantic":
                    stage = f"{stage} ({decision.get('decision_backend')})"
                kind = f" · `{finding.finding_type}`" if finding.finding_type else ""
                lines.append(f"- **{stage}**{kind} — {html.escape(finding.message)}")
                lines.append(f"  - Evidence: {_evidence_line(finding)}")
            lines.append("")

    lines.append("")
    lines += _active_defense_section(verdict.active_defense)

    if verdict.verdict.value == "MALICIOUS":
        lines += [
            "",
            "## Recommended action",
            "",
            "**Do not install this skill.** Preserve the SARIF/STIX exports and review the cited "
            "`file:line` evidence.",
        ]
    elif verdict.verdict.value == "SUSPICIOUS":
        lines += [
            "",
            "## Recommended action",
            "",
            "Review every cited finding with the skill's author before installing.",
        ]
    else:
        lines += ["", "## Recommended action", "", "Safe to install."]

    lines += [
        "",
        "---",
        "",
        f"*{GEMMA_BADGE}* · Generated by SkillSentry 2.0",
        "",
    ]
    return "\n".join(lines)


__all__ = ["build_markdown"]
