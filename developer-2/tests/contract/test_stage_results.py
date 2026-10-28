"""
Contract tests for StageResult, Finding, and SandboxActionInstruction.

Validates that data contracts conform to the frozen M0 specifications.
"""

import pytest

from skillsentry_dev2.contracts import (
    LEGAL_INTENT_KEYWORDS,
    SEVERITIES,
    STAGES,
    VERDICTS,
    Finding,
    PackageManifest,
    SandboxActionInstruction,
    ScriptFile,
    StageResult,
)


class TestFinding:
    def test_valid_construction(self):
        f = Finding(stage="spec", severity="high", message="Test finding")
        assert f.stage == "spec"
        assert f.severity == "high"

    def test_invalid_stage_rejected(self):
        with pytest.raises(ValueError, match="Invalid stage"):
            Finding(stage="nonexistent_stage", severity="high", message="bad")

    def test_invalid_severity_rejected(self):
        with pytest.raises(ValueError, match="Invalid severity"):
            Finding(stage="spec", severity="ultra", message="bad")

    def test_to_dict_minimal(self):
        f = Finding(stage="spec", severity="medium", message="test")
        d = f.to_dict()
        assert d["stage"] == "spec"
        assert d["severity"] == "medium"
        assert d["message"] == "test"
        assert "evidence" not in d

    def test_to_dict_with_evidence(self):
        f = Finding(
            stage="deterministicAnchor", severity="critical", message="cred read",
            file="scripts/evil.py", line=10,
            evidence_json={"pattern": "credential_read", "code": "open('~/.aws/credentials')"},
        )
        d = f.to_dict()
        assert d["evidence"]["file"] == "scripts/evil.py"
        assert d["evidence"]["line"] == 10
        assert d["evidence"]["pattern"] == "credential_read"

    def test_all_stages_valid(self):
        for stage in STAGES:
            f = Finding(stage=stage, severity="low", message=f"test {stage}")
            assert f.stage == stage

    def test_all_severities_valid(self):
        for sev in SEVERITIES:
            f = Finding(stage="spec", severity=sev, message=f"test {sev}")
            assert f.severity == sev

    def test_frozen_dataclass(self):
        f = Finding(stage="spec", severity="low", message="test")
        with pytest.raises(AttributeError):
            f.stage = "vision"


class TestStageResult:
    def test_valid_construction(self):
        r = StageResult(stage="spec")
        assert r.stage == "spec"
        assert r.findings == []
        assert r.signals == {}

    def test_invalid_stage_rejected(self):
        with pytest.raises(ValueError):
            StageResult(stage="invalid")

    def test_degraded_flag(self):
        r = StageResult(stage="semantic", degraded=True)
        assert r.degraded is True

    def test_signals_dict(self):
        r = StageResult(stage="deterministicAnchor", signals={"anchor_risk": 55.0})
        assert r.signals["anchor_risk"] == 55.0


class TestSandboxActionInstruction:
    def test_valid_construction(self):
        instr = SandboxActionInstruction(
            instruction_id="test-1",
            finding_id=None,
            target_package="test-skill",
            entrypoint_script="scripts/main.py",
            reason="Test execution",
            check_category="TRIGGER_EXECUTION",
        )
        assert instr.check_status == "required"

    def test_invalid_category_rejected(self):
        with pytest.raises(ValueError, match="Invalid check_category"):
            SandboxActionInstruction(
                instruction_id="bad",
                finding_id=None,
                target_package="test",
                entrypoint_script="",
                reason="bad",
                check_category="INVALID_CATEGORY",
            )

    def test_invalid_status_rejected(self):
        with pytest.raises(ValueError, match="Invalid check_status"):
            SandboxActionInstruction(
                instruction_id="bad",
                finding_id=None,
                target_package="test",
                entrypoint_script="",
                reason="bad",
                check_category="TRIGGER_EXECUTION",
                check_status="invalid_status",
            )

    def test_all_categories_valid(self):
        for cat in SandboxActionInstruction.VALID_CATEGORIES:
            instr = SandboxActionInstruction(
                instruction_id=f"test-{cat}",
                finding_id=None,
                target_package="test",
                entrypoint_script="",
                reason="test",
                check_category=cat,
            )
            assert instr.check_category == cat

    def test_frozen(self):
        instr = SandboxActionInstruction(
            instruction_id="test",
            finding_id=None,
            target_package="test",
            entrypoint_script="",
            reason="test",
            check_category="TRIGGER_EXECUTION",
        )
        with pytest.raises(AttributeError):
            instr.reason = "changed"


class TestIntentKeywords:
    def test_legal_keywords_nonempty(self):
        assert len(LEGAL_INTENT_KEYWORDS) > 0

    def test_generic_in_legal(self):
        assert "generic" in LEGAL_INTENT_KEYWORDS

    def test_aws_in_legal(self):
        assert "aws" in LEGAL_INTENT_KEYWORDS

