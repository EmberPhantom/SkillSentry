"""
SARIF 2.1.0 Report Generator.

Converts SkillSentry scan findings into valid Static Analysis Results
Interchange Format (SARIF) v2.1.0 JSON documents compliant with the OASIS
standard and GitHub Code Scanning requirements.

CL-D2-7 · REQ-D2-PS-02 · Source: docs/07-cli-reference.md §7.3.
"""

from __future__ import annotations

import json
from typing import Any


SARIF_SCHEMA_URI = "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json"
ENGINE_NAME = "SkillSentry"
ENGINE_VERSION = "2.0.0"


def _severity_to_sarif_level(severity: str) -> str:
    """Map SkillSentry finding severity to SARIF result level."""
    mapping = {
        "critical": "error",
        "high": "error",
        "medium": "warning",
        "low": "note",
        "note": "note",
    }
    return mapping.get(severity.lower(), "warning")


def generate_sarif_report(
    scan_results: list[dict[str, Any]],
    tool_version: str = ENGINE_VERSION,
) -> dict[str, Any]:
    """Generate a SARIF 2.1.0 document from a list of skill scan results.

    Args:
        scan_results: List of scan result dictionaries from cli/scanner.
        tool_version: SkillSentry version string.

    Returns:
        A dictionary adhering to the SARIF 2.1.0 schema.
    """
    rules_dict: dict[str, dict[str, Any]] = {}
    results_list: list[dict[str, Any]] = []

    for scan in scan_results:
        skill_name = scan.get("skill_name", "unknown-skill")
        findings = scan.get("findings", [])

        for finding in findings:
            stage = finding.get("stage", "general")
            severity = finding.get("severity", "medium")
            message_text = finding.get("message", "Security issue detected")
            evidence = finding.get("evidence", {}) or {}
            file_path = finding.get("file") or evidence.get("file", "SKILL.md")
            line_no = finding.get("line") or evidence.get("line", 1)
            pattern_id = evidence.get("pattern") or f"{stage}-{severity}"

            rule_id = f"SKS-{stage.upper()}-{pattern_id.upper().replace('_', '-')}"

            # Register rule metadata if not already present
            if rule_id not in rules_dict:
                rules_dict[rule_id] = {
                    "id": rule_id,
                    "name": pattern_id.replace("_", " ").title(),
                    "shortDescription": {
                        "text": f"SkillSentry {stage} analysis finding: {pattern_id}",
                    },
                    "defaultConfiguration": {
                        "level": _severity_to_sarif_level(severity),
                    },
                    "properties": {
                        "stage": stage,
                        "severity": severity,
                    },
                }

            # Build SARIF result
            sarif_result: dict[str, Any] = {
                "ruleId": rule_id,
                "level": _severity_to_sarif_level(severity),
                "message": {
                    "text": f"[{skill_name}] {message_text}",
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": str(file_path).replace("\\", "/"),
                            },
                            "region": {
                                "startLine": max(1, int(line_no)),
                            },
                        },
                    },
                ],
                "properties": {
                    "skillName": skill_name,
                    "stage": stage,
                    "severity": severity,
                },
            }

            results_list.append(sarif_result)

    sarif_doc: dict[str, Any] = {
        "$schema": SARIF_SCHEMA_URI,
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": ENGINE_NAME,
                        "version": tool_version,
                        "informationUri": "https://github.com/skillsentry/skillsentry",
                        "rules": list(rules_dict.values()),
                    },
                },
                "results": results_list,
            },
        ],
    }

    return sarif_doc


def sarif_to_json(sarif_doc: dict[str, Any], indent: int = 2) -> str:
    """Serialize SARIF dictionary to formatted JSON string."""
    return json.dumps(sarif_doc, indent=indent, ensure_ascii=False)

