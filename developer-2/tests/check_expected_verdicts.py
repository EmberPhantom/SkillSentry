"""
Automated CI Regression Gate: Expected Verdicts Checker.

Validates that all test fixtures produce their expected verdicts,
risk score bands, and required findings when processed by the pipeline.

Can be run:
  1. As a pytest test suite: pytest tests/check_expected_verdicts.py
  2. As a standalone CLI gate: python tests/check_expected_verdicts.py [results.json]

Reference: docs/08-testing-and-evaluation.md §8.8
           developer-2/06-testing-and-evaluation-spec.md §5
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Any, Optional

import pytest

from skillsentry_dev2.contracts import Finding, StageResult
from skillsentry_dev2.core.parser.skill_parser import parse_package
from skillsentry_dev2.core.parser.typosquat import check_typosquat
from skillsentry_dev2.core.semantic.analyzer import analyze_semantics
from skillsentry_dev2.core.semantic.ast_anchor import scan_anchors
from skillsentry_dev2.core.semantic.sandbox_instructions import generate_sandbox_instructions
from skillsentry_dev2.core.vision.vision_scanner import scan_visual_assets
from skillsentry_dev2.mock_gemma import MockGemma, MockMode


EXPECTED_VERDICTS_PATH = Path(__file__).parent / "expected_verdicts.json"
DEV2_ROOT = Path(__file__).resolve().parents[1]


def load_expected_verdicts() -> dict[str, Any]:
    with open(EXPECTED_VERDICTS_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def run_pipeline_on_fixture(fixture_rel_path: str) -> dict[str, Any]:
    """Execute Dev 2 analysis pipeline on a fixture directory."""
    fixture_dir = DEV2_ROOT / fixture_rel_path
    if not fixture_dir.exists():
        raise FileNotFoundError(f"Fixture directory not found: {fixture_dir}")

    # DEF-01: Zero path cheating — evaluate honest content with MockMode.AUTO
    model_client = MockGemma(mode=MockMode.AUTO)

    all_findings: list[Finding] = []

    # Stage 1: Spec validation
    manifest, spec_result = parse_package(fixture_dir)
    if spec_result.findings:
        all_findings.extend(spec_result.findings)

    skill_name = manifest.name if manifest else fixture_dir.name

    # Stage 1: Typosquatting
    typosquat_result = check_typosquat(skill_name)
    all_findings.extend(typosquat_result.findings)
    typosquat_detected = typosquat_result.signals.get("typosquat_detected", 0.0) > 0.0

    # Stage 2: AST Anchors
    scripts = manifest.scripts if manifest else {}
    anchor_result, raw_anchors, anchor_block = scan_anchors(scripts)
    all_findings.extend(anchor_result.findings)
    s_anchors = anchor_result.signals.get("anchor_risk", 0.0)

    # Stage 2: Semantic Analysis
    if manifest:
        sem_result = analyze_semantics(manifest, anchor_block, raw_anchors, model_client)
        all_findings.extend(sem_result.findings)
        s_semantic = sem_result.signals.get("semantic_risk", 0.0)
        intent_keywords = sem_result.telemetry.get("intent_keywords", ["generic"]) if sem_result.telemetry else ["generic"]
    else:
        s_semantic = 0.0
        intent_keywords = ["generic"]

    # Stage 3: Vision Scanning
    if manifest and manifest.assets:
        vision_result = scan_visual_assets(manifest, model_client, fixture_dir)
        all_findings.extend(vision_result.findings)
        s_vision = vision_result.signals.get("vision_risk", 0.0)
    else:
        s_vision = 0.0

    # INT-4 Sandbox Instructions (DEF-17: pass declared scripts)
    has_traversal = any(
        f.stage == "spec" and (f.evidence_json or {}).get("type") in ("path_traversal", "symlink_escape")
        for f in all_findings
    )
    instructions = generate_sandbox_instructions(
        anchor_findings=raw_anchors,
        stage_findings=all_findings,
        intent_keywords=intent_keywords,
        package_name=skill_name,
        has_path_traversal=has_traversal,
        declared_scripts=list(scripts.keys()) if scripts else None,
    )

    # Risk score fusion formula (docs/02-architecture.md §2.3) with Authoritative Floors (DEF-03, N3, N6)
    w_anchors, w_semantic, w_vision = 0.15, 0.20, 0.20
    sum_w = w_anchors + w_semantic + w_vision
    weighted_sum = (w_anchors * s_anchors) + (w_semantic * s_semantic) + (w_vision * s_vision)
    base_risk = round(weighted_sum / sum_w) if sum_w > 0 else 0

    typosquat_bonus = 15 if typosquat_detected else 0
    total_risk = min(100, base_risk + typosquat_bonus)

    # Authoritative risk floors (DEF-03, N3, N6)
    has_evasion = any(a.pattern == "sandbox_evasion" for a in raw_anchors) or any(
        (f.evidence_json or {}).get("pattern") == "sandbox_evasion" for f in all_findings
    )
    has_critical_spec = any(
        f.stage == "spec" and (
            f.severity == "critical" or
            (f.evidence_json or {}).get("type") in ("path_traversal", "symlink_escape") or
            (f.evidence_json or {}).get("pattern") in ("reserved_device", "ntfs_ads")
        )
        for f in all_findings
    )
    anchor_patterns = {a.pattern for a in raw_anchors}
    has_cred_read = "credential_read" in anchor_patterns or any(
        (f.evidence_json or {}).get("pattern") == "credential_read" for f in all_findings
    )
    has_exfil = bool(anchor_patterns & {"requests_post", "nslookup", "urllib_post", "socket_connect"})
    has_cred_exfil = has_cred_read and has_exfil

    has_critical_vision = any(f.stage == "vision" and f.severity == "critical" for f in all_findings)
    has_critical_anchor = any(a.severity == "critical" for a in raw_anchors)
    has_high_anchor = any(a.severity == "high" for a in raw_anchors)
    is_degraded = spec_result.degraded or (manifest and sem_result.degraded) or (manifest and manifest.assets and vision_result.degraded)

    if has_evasion:
        total_risk = max(total_risk, 85)
    if has_critical_spec:
        total_risk = max(total_risk, 75)
    if has_cred_exfil:
        total_risk = max(total_risk, 75)
    if has_critical_vision:
        total_risk = max(total_risk, 71)
    if has_critical_anchor:
        total_risk = max(total_risk, 60)
    if has_high_anchor:
        total_risk = max(total_risk, 55)
    if is_degraded:
        total_risk = max(total_risk, 30)

    # Tier mapping: SAFE < 30 <= SUSPICIOUS <= 70 < MALICIOUS
    # Note: Typosquatting or degraded scans must never produce SAFE
    if total_risk < 30:
        verdict = "SUSPICIOUS" if (typosquat_detected or is_degraded) else "SAFE"
    elif total_risk <= 70:
        verdict = "SUSPICIOUS"
    else:
        verdict = "MALICIOUS"

    return {
        "skill": skill_name,
        "verdict": verdict,
        "riskScore": total_risk,
        "findings": [f.to_dict() for f in all_findings],
        "sandbox_instructions": instructions,
    }


def verify_fixture(fixture_key: str, expected: dict[str, Any], actual: dict[str, Any]) -> list[str]:
    """Verify actual result against expected verdict specifications."""
    errors: list[str] = []

    # 1. Verdict check
    if actual["verdict"] != expected["verdict"]:
        errors.append(
            f"Verdict mismatch for {fixture_key}: expected '{expected['verdict']}', got '{actual['verdict']}'"
        )

    # 2. Risk band check
    risk_min, risk_max = expected["risk_band"]
    actual_risk = actual["riskScore"]
    if not (risk_min <= actual_risk <= risk_max):
        errors.append(
            f"Risk score out of bounds for {fixture_key}: {actual_risk} not in [{risk_min}, {risk_max}]"
        )

    # 3. Required findings check
    actual_findings = actual.get("findings", [])
    for req in expected.get("required_findings", []):
        matched = False
        for f in actual_findings:
            if f["stage"] != req["stage"]:
                continue
            if "severity" in req and f["severity"] != req["severity"]:
                continue
            if "pattern" in req:
                ev = f.get("evidence", {})
                if ev.get("pattern") != req["pattern"] and req["pattern"] not in f.get("message", ""):
                    continue
            if "message_contains" in req and req["message_contains"] not in f.get("message", ""):
                continue
            if "file_contains" in req:
                ev = f.get("evidence", {})
                ev_file = ev.get("file", "")
                if req["file_contains"] not in ev_file:
                    continue
            matched = True
            break
        if not matched:
            errors.append(f"Missing required finding for {fixture_key}: {req}")

    return errors


class TestCheckExpectedVerdicts:
    """Pytest test suite validating all expected verdicts."""

    @pytest.fixture(scope="class")
    @classmethod
    def expected_specs(cls):
        return load_expected_verdicts()

    def test_all_fixtures_pass_verdict_gates(self, expected_specs):
        failures: list[str] = []
        for fixture_key, expected in expected_specs.items():
            actual = run_pipeline_on_fixture(fixture_key)
            errs = verify_fixture(fixture_key, expected, actual)
            if errs:
                failures.extend(errs)

        assert not failures, "Expected verdict regression failures:\n" + "\n".join(f"  - {e}" for e in failures)


def main() -> int:
    """CLI entrypoint for standalone execution or CI pipeline."""
    print("=" * 60)
    print("SkillSentry Expected Verdicts Regression Gate")
    print("=" * 60)

    expected_specs = load_expected_verdicts()
    all_passed = True

    for fixture_key, expected in expected_specs.items():
        try:
            actual = run_pipeline_on_fixture(fixture_key)
            errors = verify_fixture(fixture_key, expected, actual)
            if errors:
                all_passed = False
                print(f"[FAIL] {fixture_key}")
                for err in errors:
                    print(f"       -> {err}")
            else:
                print(f"[PASS] {fixture_key:35s} -> {actual['verdict']:10s} (Risk: {actual['riskScore']:3d})")
        except Exception as ex:
            all_passed = False
            print(f"[ERROR] {fixture_key}: {ex}")

    print("=" * 60)
    if all_passed:
        print("RESULT: ALL FIXTURES PASSED REGRESSION GATE")
        return 0
    else:
        print("RESULT: REGRESSION DETECTED")
        return 1


if __name__ == "__main__":
    sys.exit(main())
