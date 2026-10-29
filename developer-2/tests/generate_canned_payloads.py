"""
Generate Canned Payloads for Demo Mode (Interface I4).

Executes the pipeline across all 20 fixtures and exports exact,
schema-compliant Verdict JSON v1 payloads to tests/fixtures_canned_payloads.json
so Dev 1's mock/demo server uses shapes identical to real analysis results.

Source: docs/05-api-reference.md §5.5, docs/checklists/dev2-skill-analysis.md CL-D2-6/D2-8.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from skillsentry_dev2.contracts import Finding
from skillsentry_dev2.core.parser.skill_parser import parse_package
from skillsentry_dev2.core.parser.typosquat import check_typosquat
from skillsentry_dev2.core.semantic.analyzer import analyze_semantics
from skillsentry_dev2.core.semantic.ast_anchor import scan_anchors
from skillsentry_dev2.core.vision.vision_scanner import scan_visual_assets
from skillsentry_dev2.mock_gemma import MockGemma, MockMode


DEV2_ROOT = Path(__file__).resolve().parents[1]
OUTPUT_PATH = DEV2_ROOT / "tests" / "fixtures_canned_payloads.json"

FIXTURES = [
    # Benign fixtures (simulated scan durations)
    ("fixtures/benign/pdf-summarizer", False, 185),
    ("fixtures/benign/git-helper", False, 210),
    ("fixtures/benign/image-resizer", False, 320),
    ("fixtures/benign/weather-fetch", False, 290),
    ("fixtures/benign/csv-analyzer", False, 195),
    ("fixtures/benign/markdown-formatter", False, 175),
    ("fixtures/benign/docker-compose-helper", False, 230),
    ("fixtures/benign/slack-notifier", False, 260),
    ("fixtures/benign/ssh-keygen-helper", False, 200),
    ("fixtures/benign/multi-lang-tool", False, 310),
    ("fixtures/benign/json-formatter", False, 165),
    ("fixtures/benign/backup-tool", False, 180),
    # Malicious fixtures
    ("fixtures/malicious/invoice-helper", True, 850),
    ("fixtures/malicious/g1t-translate", True, 240),
    ("fixtures/malicious/obfuscation-only", True, 420),
    ("fixtures/malicious/instruction-poisoning", True, 380),
    ("fixtures/malicious/svg-borne", True, 920),
    ("fixtures/malicious/dns-tunneler", True, 350),
    ("fixtures/malicious/sl4ck-bot", True, 480),
    ("fixtures/malicious/credential-multi", True, 560),
]


def generate_payload(rel_path: str, is_malicious: bool, simulated_duration_ms: int) -> dict[str, Any]:
    fixture_dir = DEV2_ROOT / rel_path
    mock_mode = MockMode.DECEPTIVE if is_malicious else MockMode.BENIGN
    model_client = MockGemma(mode=mock_mode)

    all_findings: list[Finding] = []

    # Stage 1: Spec
    manifest, spec_res = parse_package(fixture_dir)
    all_findings.extend(spec_res.findings)
    skill_name = manifest.name if manifest else fixture_dir.name

    # Stage 1: Typosquat
    typo_res = check_typosquat(skill_name)
    all_findings.extend(typo_res.findings)
    typo_detected = typo_res.signals.get("typosquat_detected", 0.0) > 0.0

    # Stage 2: Anchors
    scripts = manifest.scripts if manifest else {}
    anchor_res, raw_anchors, anchor_block = scan_anchors(scripts)
    all_findings.extend(anchor_res.findings)
    s_anchors = anchor_res.signals.get("anchor_risk", 0.0)

    # Stage 2: Semantic
    if manifest:
        sem_res = analyze_semantics(manifest, anchor_block, raw_anchors, model_client)
        all_findings.extend(sem_res.findings)
        s_semantic = sem_res.signals.get("semantic_risk", 0.0)
    else:
        s_semantic = 0.0

    # Stage 3: Vision
    if manifest and manifest.assets:
        vis_res = scan_visual_assets(manifest, model_client, fixture_dir)
        all_findings.extend(vis_res.findings)
        s_vision = vis_res.signals.get("vision_risk", 0.0)
    else:
        s_vision = 0.0

    # Fusion formula
    w_anchors, w_semantic, w_vision = 0.15, 0.20, 0.20
    sum_w = w_anchors + w_semantic + w_vision
    weighted_sum = (w_anchors * s_anchors) + (w_semantic * s_semantic) + (w_vision * s_vision)
    base_risk = round(weighted_sum / sum_w) if sum_w > 0 else 0
    typo_bonus = 15 if typo_detected else 0
    total_risk = min(100, base_risk + typo_bonus)

    if total_risk < 30:
        verdict = "SAFE"
        confidence = 0.95
    elif total_risk <= 70:
        verdict = "SUSPICIOUS"
        confidence = 0.88
    else:
        verdict = "MALICIOUS"
        confidence = 0.98

    payload: dict[str, Any] = {
        "skill": skill_name,
        "verdict": verdict,
        "riskScore": total_risk,
        "confidence": confidence,
        "cached": False,
        "scanDurationMs": simulated_duration_ms,
        "findings": [f.to_dict() for f in all_findings],
    }

    # Active defense block (present for schema stability)
    if is_malicious and "invoice-helper" in rel_path:
        payload["activeDefense"] = {
            "triggered": True,
            "targetedAssets": ["~/.aws/credentials"],
            "exfilChannel": "HTTP_POST",
            "canaryMarker": "SKS-4e8a1d02",
            "secondaryCanary": "SKS-6b9c3f11",
            "c2Indicators": ["evil-collector.net"],
            "encoding": "base64",
            "sandboxEvasionDetected": False,
            "declaredIntent": "Invoice PDF processing and expense reporting",
            "contextAwareCanary": "AWS",
        }
    else:
        payload["activeDefense"] = {
            "triggered": False,
            "targetedAssets": [],
            "exfilChannel": None,
            "canaryMarker": None,
            "secondaryCanary": None,
            "c2Indicators": [],
            "encoding": None,
            "sandboxEvasionDetected": False,
            "declaredIntent": manifest.description if manifest else "",
            "contextAwareCanary": "GENERIC",
        }

    return payload


def main() -> None:
    canned_payloads: dict[str, Any] = {}
    for rel_path, is_mal, duration_ms in FIXTURES:
        p = generate_payload(rel_path, is_mal, duration_ms)
        canned_payloads[p["skill"]] = p
        print(f"Generated canned payload for: {p['skill']} ({p['verdict']}, risk {p['riskScore']})")

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(canned_payloads, f, indent=2)

    print(f"\nSaved all canned payloads to: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()

