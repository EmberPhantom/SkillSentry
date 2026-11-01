"""SARIF 2.1.0 report writer (docs/05-api-reference.md §5.6)."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import quote

from skill_sentry.core.contracts import Finding, Severity, Verdict, format_utc, utc_now
from skill_sentry.core.version import ENGINE_VERSION

SARIF_SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json"
LEVEL_BY_SEVERITY: dict[Severity, str] = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.NOTE: "note",
}


def _slug(value: str, *, fallback: str = "finding", max_length: int = 64) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", value.lower()).strip("-")
    return (slug or fallback)[:max_length].strip("-") or fallback


def rule_id(finding: Finding) -> str:
    """``skillsentry/<stage>/<type>`` — §5.6."""
    kind = finding.finding_type or _slug(finding.message)
    return f"skillsentry/{finding.stage.value}/{_slug(kind)}"


def _artifact_uri(path: str | None) -> str | None:
    if not path:
        return None
    normalised = path.replace("\\", "/").lstrip("/")
    while normalised.startswith("./"):
        normalised = normalised[2:]
    return quote(normalised, safe="/-._~")


def _result(finding: Finding, rule_index: int) -> dict[str, Any]:
    result: dict[str, Any] = {
        "ruleId": rule_id(finding),
        "ruleIndex": rule_index,
        "level": LEVEL_BY_SEVERITY[finding.severity],
        "message": {"text": finding.message},
        "properties": {
            "stage": finding.stage.value,
            "severity": finding.severity.value,
            "evidence": finding.evidence.model_dump(by_alias=True, mode="json", exclude_none=True),
        },
    }
    uri = _artifact_uri(finding.evidence.file)
    if uri:
        physical: dict[str, Any] = {"artifactLocation": {"uri": uri}}
        if finding.evidence.line:
            physical["region"] = {"startLine": finding.evidence.line}
        result["locations"] = [{"physicalLocation": physical}]
    return result


def build_sarif(
    verdict: Verdict,
    *,
    generated_at=None,
    decision: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Build a schema-shaped SARIF 2.1.0 document for one verdict."""
    rules: dict[str, dict[str, Any]] = {}
    results: list[dict[str, Any]] = []

    for finding in verdict.findings:
        rid = rule_id(finding)
        if rid not in rules:
            rules[rid] = {
                "id": rid,
                "name": _slug(rid.rsplit("/", 1)[-1], fallback="finding"),
                "shortDescription": {"text": finding.message},
                "helpUri": "https://github.com/skillsentry/skillsentry#readme",
                "defaultConfiguration": {"level": LEVEL_BY_SEVERITY[finding.severity]},
                "properties": {
                    "stage": finding.stage.value,
                    "severity": finding.severity.value,
                    "tags": [finding.stage.value, finding.severity.value],
                },
            }
        results.append(_result(finding, list(rules).index(rid)))

    run_properties: dict[str, Any] = {
        "verdict": verdict.verdict.value,
        "riskScore": verdict.risk_score,
        "confidence": verdict.confidence,
        "cached": verdict.cached,
        "skill": verdict.skill,
        "skillId": str(verdict.skill_id),
        "scanId": str(verdict.scan_id),
        "engineVersion": ENGINE_VERSION,
        "generatedAt": format_utc(generated_at or utc_now()),
    }
    if verdict.active_defense is not None:
        run_properties["activeDefense"] = verdict.active_defense.model_dump(
            by_alias=True, mode="json", exclude_none=False
        )
    if decision is not None:
        # Report-safe summary only; see skill_sentry.core.decisions.report.
        run_properties["decisionLayer"] = decision

    return {
        "$schema": SARIF_SCHEMA,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "SkillSentry",
                        "informationUri": "https://github.com/skillsentry/skillsentry",
                        "version": ENGINE_VERSION,
                        "semanticVersion": ENGINE_VERSION,
                        "rules": list(rules.values()),
                    }
                },
                "automationDetails": {"id": f"skillsentry/{verdict.scan_id}"},
                "invocations": [{"executionSuccessful": True}],
                "results": results,
                "properties": run_properties,
                "columnKind": "utf16CodeUnits",
            }
        ],
    }


def build_sarif_text(verdict: Verdict) -> str:
    import json

    return json.dumps(build_sarif(verdict, generated_at=utc_now()), indent=2) + "\n"


__all__ = ["LEVEL_BY_SEVERITY", "SARIF_SCHEMA", "build_sarif", "build_sarif_text", "rule_id"]
