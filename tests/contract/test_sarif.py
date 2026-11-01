"""SARIF 2.1.0 writer contract."""

from __future__ import annotations

import json

from skill_sentry.core.verdict.sarif_report import build_sarif, rule_id
from skill_sentry.server.demo_data import build_demo_store


def _verdict(name: str):
    return next(item.verdict for item in build_demo_store() if item.name == name)


def test_sarif_structure_for_malicious_skill():
    verdict = _verdict("cloud-sync-pro")
    sarif = build_sarif(verdict)
    json.dumps(sarif)  # must be JSON-serialisable

    assert sarif["version"] == "2.1.0"
    assert "sarif" in sarif["$schema"]
    assert len(sarif["runs"]) == 1
    run = sarif["runs"][0]
    driver = run["tool"]["driver"]
    assert driver["name"] == "SkillSentry"
    assert len(driver["rules"]) == len(verdict.findings)
    assert len({rule["id"] for rule in driver["rules"]}) == len(driver["rules"])

    assert len(run["results"]) == len(verdict.findings)
    for result, finding in zip(run["results"], verdict.findings, strict=True):
        assert result["ruleId"] == rule_id(finding)
        assert result["ruleIndex"] < len(driver["rules"])
        assert result["level"] in {"error", "warning", "note"}
        assert result["properties"]["stage"] == finding.stage.value

    assert run["properties"]["verdict"] == "MALICIOUS"
    assert run["properties"]["riskScore"] == 97
    assert run["properties"]["activeDefense"]["triggered"] is True
    assert run["properties"]["scanId"] == str(verdict.scan_id)


def test_sarif_critical_findings_have_file_and_line():
    verdict = _verdict("cloud-sync-pro")
    sarif = build_sarif(verdict)
    results = sarif["runs"][0]["results"]
    locations = [result["locations"][0] for result in results if "locations" in result]
    assert locations
    assert any(
        location["physicalLocation"]["artifactLocation"]["uri"] == "scripts/sync.sh"
        for location in locations
    )
    assert any(
        location["physicalLocation"].get("region", {}).get("startLine") == 7
        for location in locations
    )


def test_sarif_benign_skill_has_no_actionable_results():
    verdict = _verdict("pdf-summarizer")
    sarif = build_sarif(verdict)
    run = sarif["runs"][0]
    assert all(result["level"] == "note" for result in run["results"])
    assert all(
        rule["defaultConfiguration"]["level"] == "note" for rule in run["tool"]["driver"]["rules"]
    )
    assert run["properties"]["verdict"] == "SAFE"


def test_rule_id_is_stable_and_slugged():
    verdict = _verdict("slack-notif-mal")
    ids = [rule_id(finding) for finding in verdict.findings]
    assert "skillsentry/evasion/evasion-probe" in ids
    assert "skillsentry/poisonedWell/exfil-confirmed" in ids
    assert all(" " not in rule_id for rule_id in ids)
