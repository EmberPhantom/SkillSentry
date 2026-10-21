"""Verdict JSON Contract v1 — schema, aliases, and fail-safe invariants."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from skillsentry.core.contracts import (
    SCHEMA_MODELS,
    ActiveDefense,
    Finding,
    FindingEvidence,
    ScanOptions,
    ScanRequest,
    Severity,
    Stage,
    Verdict,
    VerdictTier,
    WSMessage,
    export_json_schemas,
)


def test_demo_store_roundtrips_through_json(store):
    for item in store:
        dumped = item.verdict.model_dump_json(by_alias=True)
        restored = Verdict.model_validate_json(dumped)
        assert restored == item.verdict


def test_wire_format_is_camel_case(store):
    payload = store[4].verdict.model_dump(by_alias=True, mode="json")
    assert set(payload) == {
        "skill",
        "skillId",
        "scanId",
        "verdict",
        "riskScore",
        "confidence",
        "cached",
        "scanDurationMs",
        "findings",
        "activeDefense",
    }
    assert payload["scanDurationMs"] == 87432
    assert payload["activeDefense"]["exfilChannel"] == "DNS_TUNNELING"
    assert payload["activeDefense"]["contextAwareCanary"] == "AWS"
    assert "scan_duration_ms" not in payload


def test_finding_type_uses_documented_alias():
    finding = Finding(
        stage=Stage.DETERMINISTIC_ANCHOR,
        severity=Severity.HIGH,
        message="nslookup",
        evidence=FindingEvidence(file="scripts/sync.sh", line=7),
        type="dns-lookup",
    )
    payload = finding.model_dump(by_alias=True)
    assert payload["type"] == "dns-lookup"
    assert "finding_type" not in payload


def test_active_defense_null_fields_are_preserved():
    active = ActiveDefense(triggered=False)
    payload = active.model_dump(by_alias=True, mode="json")
    assert payload["triggered"] is False
    assert payload["exfilChannel"] is None
    assert payload["c2Indicators"] == []


def test_malicious_verdicts_cite_file_and_line(store):
    for item in store:
        if item.verdict.verdict is not VerdictTier.MALICIOUS:
            continue
        cited = [
            finding
            for finding in item.verdict.findings
            if finding.evidence.file and finding.evidence.line
        ]
        assert cited, f"{item.name} is MALICIOUS without a file:line citation"


def test_every_stage_spelling_is_canonical():
    assert Stage.DETERMINISTIC_ANCHOR.value == "deterministicAnchor"
    assert Stage.POISONED_WELL.value == "poisonedWell"
    assert {stage.value for stage in Stage} == {
        "cache",
        "spec",
        "typosquat",
        "deterministicAnchor",
        "semantic",
        "vision",
        "sandbox",
        "poisonedWell",
        "evasion",
        "verdict",
    }


def test_request_models_are_snake_case():
    request = ScanRequest.model_validate(
        {
            "path": "fixtures/cloud-sync-pro",
            "options": {
                "no_cache": True,
                "backend": "local",
                "sandbox": True,
                "poisoned_well": False,
                "timeout_s": 45,
            },
        }
    )
    dumped = request.model_dump()
    assert dumped["options"]["no_cache"] is True
    assert dumped["options"]["poisoned_well"] is False
    assert dumped["options"]["timeout_s"] == 45
    assert "noCache" not in json.dumps(dumped)


def test_scan_options_reject_out_of_range_timeout():
    with pytest.raises(ValueError):
        ScanOptions(timeout_s=1)


def test_ws_message_serialises_timestamp_with_z(store):
    message = WSMessage(
        stage=Stage.VERDICT,
        skill="cloud-sync-pro",
        event="completed",
        ts="2026-10-21T09:31:07.412000Z",
        detail={"ok": True},
    )
    payload = json.loads(message.model_dump_json(by_alias=True))
    assert payload["ts"] == "2026-10-21T09:31:07.412Z"


def test_schema_export_is_complete_and_reproducible(tmp_path: Path):
    first = export_json_schemas(tmp_path / "one")
    second = export_json_schemas(tmp_path / "two")
    for key in ("verdict", "api"):
        assert first[key].read_bytes() == second[key].read_bytes()

    verdict_schema = json.loads(first["verdict"].read_text(encoding="utf-8"))
    assert verdict_schema["title"] == "Verdict"
    assert {
        "skill",
        "skillId",
        "scanId",
        "verdict",
        "riskScore",
        "confidence",
        "cached",
        "scanDurationMs",
    } <= set(verdict_schema["required"])
    assert "findings" in verdict_schema["properties"]
    assert "activeDefense" in verdict_schema["properties"]

    api_schema = json.loads(first["api"].read_text(encoding="utf-8"))
    assert set(SCHEMA_MODELS) == set(api_schema)
    assert "ScanRequest" in api_schema and "SkillDetail" in api_schema


def test_phase_contract_enum_values_are_stable():
    assert [tier.value for tier in VerdictTier] == ["SAFE", "SUSPICIOUS", "MALICIOUS"]
    assert Severity.CRITICAL.rank > Severity.HIGH.rank > Severity.MEDIUM.rank
