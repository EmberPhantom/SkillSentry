"""Human-readable Markdown triage report."""

from __future__ import annotations

import html
import re
from collections.abc import Sequence
from datetime import datetime
from typing import Any

from skill_sentry_cli.core.contracts import (
    ActiveDefense,
    Finding,
    Severity,
    StageResult,
    Verdict,
    format_utc,
    utc_now,
)
from skill_sentry_cli.core.verdict.status import degraded_reason, is_unscanned, shown_status
from skill_sentry_cli.core.version import ENGINE_VERSION, badge_for_backend

_SEVERITY_ORDER = [
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.NOTE,
]


_NEWLINES = ("\r\n", "\n", "\r")


def _single_line(value: str) -> str:
    for newline in _NEWLINES:
        value = value.replace(newline, " ")
    return value


def _text(value: object) -> str:
    """Escape untrusted prose for inline Markdown.

    Attacker-influenced text may carry HTML, newlines, or Markdown link and image
    syntax.  ``&``, ``<`` and ``>`` are entity-escaped so no tag renders, line
    breaks are flattened so a finding stays on its list item, backslashes are
    doubled first so they cannot neutralise the escapes added after them, and
    square brackets are escaped so ``[text](url)`` and ``![alt](url)`` cannot
    form a link or image.
    """
    text = html.escape(_single_line(str(value)), quote=False)
    text = text.replace("\\", "\\\\")
    return text.replace("[", "\\[").replace("]", "\\]")


def _cell(value: object) -> str:
    """Escape untrusted text for a Markdown table cell.

    Same escaping as :func:`_text`, plus pipes are escaped so they cannot split
    the row.
    """
    return _text(value).replace("|", "\\|")


def _code(value: str) -> str:
    """Wrap untrusted text in a Markdown code span that cannot be broken out of.

    Backslash escapes are not honoured inside code spans, so backticks are
    handled by choosing a fence longer than any backtick run in the value
    (padded with spaces when the value starts or ends with a backtick).
    Newlines are flattened because a code span cannot cross a list item line.
    """
    text = _single_line(value)
    longest = max((len(run) for run in re.findall(r"`+", text)), default=0)
    fence = "`" * (longest + 1)
    if longest:
        padding = " " if text.startswith("`") or text.endswith("`") else ""
        return f"{fence}{padding}{text}{padding}{fence}"
    return f"{fence}{text}{fence}"


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
    semantic = f"degraded: {_text(error)}" if decision.get("semantic_degraded") else "complete"
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
    stage_results: Sequence[StageResult] | None = None,
    backend: str | None = None,
) -> str:
    """Render a human triage report with line-accurate citations.

    ``decision`` is the report-safe summary from
    :func:`skill_sentry_cli.core.decisions.report.decision_summary`.  Omit it and the
    report says the decision layer was not recorded rather than implying clean.

    ``backend`` is the analysis backend that ran (``ollama``, ``gemini-api``, ...). Omit
    it and the footer says the backend is not recorded; pass it and the footer names the
    privacy badge for that backend.
    """
    generated = format_utc(generated_at or utc_now())
    lines: list[str] = [
        f"# SkillSentry Triage Report — {_text(verdict.skill)}",
        "",
        "| Field | Value |",
        "|:---|:---|",
        f"| Verdict | **{shown_status(verdict.verdict, stage_results)}** |",
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
                lines.append(f"- **{stage}**{kind} — {_text(finding.message)}")
                lines.append(f"  - Evidence: {_evidence_line(finding)}")
            lines.append("")

    lines.append("")
    lines += _active_defense_section(verdict.active_defense)

    unscanned = is_unscanned(verdict.verdict, stage_results)
    if unscanned:
        lines += [
            "",
            "## Recommended action",
            "",
            "**Do not install until the scan completes.** The verdict "
            f"({verdict.verdict.value}) is based on an incomplete scan: "
            f"{degraded_reason(stage_results)}. Resolve the cause and scan again.",
        ]
    elif verdict.verdict.value == "MALICIOUS":
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

    # The verdict does not record which analysis backend ran. Without the backend the
    # footer must not claim one (the local badge is wrong for cloud scans). With it, the
    # footer names the badge for the backend that ran.
    if backend is None:
        footer = "Generated by SkillSentry 2.0 · analysis backend not recorded in this report"
    else:
        footer = f"Generated by SkillSentry 2.0 · {badge_for_backend(backend)}"
    lines += ["", "---", "", footer, ""]
    return "\n".join(lines)


__all__ = ["build_markdown"]
