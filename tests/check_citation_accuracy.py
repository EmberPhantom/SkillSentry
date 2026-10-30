"""Citation Accuracy Checker for root test suite.

Validates that AST anchor findings report line numbers within +/- tolerance
of ground truth annotations. Used as a CI regression gate.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path
from typing import Dict, List, Tuple

import pytest

from skillsentry_dev2.contracts import ScriptFile
from skillsentry_dev2.core.semantic.ast_anchor import scan_anchors

GROUND_TRUTH_PATH = Path(__file__).parent / "ground_truth.json"
DEV2_ROOT = Path(__file__).resolve().parent / "developer-2"


def _load_ground_truth() -> dict:
    if not GROUND_TRUTH_PATH.is_file():
        return {}
    with open(GROUND_TRUTH_PATH, encoding="utf-8") as f:
        return json.load(f)


def _load_script(fixture_path: str) -> ScriptFile:
    full_path = Path(__file__).resolve().parents[1] / "developer-2" / fixture_path
    if not full_path.exists():
        full_path = Path(__file__).resolve().parents[1] / fixture_path
    if not full_path.exists():
        pytest.skip(f"Fixture file not found: {full_path}")
    content = full_path.read_text(encoding="utf-8-sig", errors="replace")
    return ScriptFile(
        relative_path=fixture_path.split("/", 1)[-1] if "/" in fixture_path else fixture_path,
        lines=content.splitlines(keepends=True),
        size_bytes=len(content.encode()),
        content_hash=hashlib.sha256(content.encode()).hexdigest(),
    )


def evaluate_citation_accuracy() -> Tuple[int, int, int, int, float, float, Dict]:
    gt = _load_ground_truth()
    tp = 0
    fp = 0
    fn = 0
    total_gt = 0
    details = {}

    for rel_path, annotations in gt.items():
        total_gt += len(annotations)
        file_path = Path(__file__).resolve().parents[1] / "developer-2" / rel_path
        if not file_path.exists():
            file_path = Path(__file__).resolve().parents[1] / rel_path
        if not file_path.exists():
            continue
        content = file_path.read_text(encoding="utf-8-sig", errors="replace")
        script = ScriptFile(
            relative_path=rel_path.split("/", 1)[-1] if "/" in rel_path else rel_path,
            lines=content.splitlines(keepends=True),
            size_bytes=len(content.encode()),
            content_hash=hashlib.sha256(content.encode()).hexdigest(),
        )
        _, raw_findings, _ = scan_anchors({script.relative_path: script})

        matched_gt = set()
        matched_findings = set()

        for i, a in enumerate(annotations):
            tol = a.get("tolerance", 1)
            for j, f in enumerate(raw_findings):
                if j not in matched_findings and f.pattern == a["pattern"] and abs(f.line - a["line"]) <= tol:
                    matched_gt.add(i)
                    matched_findings.add(j)
                    break

        file_tp = len(matched_gt)
        file_fn = len(annotations) - file_tp
        file_fp = len(raw_findings) - len(matched_findings)
        tp += file_tp
        fn += file_fn
        fp += file_fp
        details[rel_path] = {
            "gt": len(annotations),
            "detected": len(raw_findings),
            "tp": file_tp,
            "fp": file_fp,
            "fn": file_fn,
        }

    prec = tp / (tp + fp) if (tp + fp) else 0.0
    rec = tp / (tp + fn) if (tp + fn) else 0.0
    return total_gt, tp, fp, fn, prec, rec, details


class TestCitationAccuracy:
    """Verify that detected anchor lines match ground truth within tolerance."""

    @pytest.fixture
    def ground_truth(self):
        return _load_ground_truth()

    def test_invoice_helper_citations(self, ground_truth):
        rel = "fixtures/malicious/invoice-helper/scripts/process.py"
        gt_entries = ground_truth.get(rel, [])
        assert len(gt_entries) >= 3
        script = _load_script(rel)
        _, raw_findings, _ = scan_anchors({script.relative_path: script})
        for entry in gt_entries:
            pat = entry["pattern"]
            expected = entry["line"]
            tol = entry.get("tolerance", 1)
            matching = [f for f in raw_findings if f.pattern == pat and abs(f.line - expected) <= tol]
            assert len(matching) > 0, f"Pattern {pat} near line {expected} (+/-{tol}) not found"

    def test_obfuscation_only_citations(self, ground_truth):
        rel = "fixtures/malicious/obfuscation-only/scripts/encoder.py"
        gt_entries = ground_truth.get(rel, [])
        assert len(gt_entries) >= 4
        script = _load_script(rel)
        _, raw_findings, _ = scan_anchors({script.relative_path: script})
        for entry in gt_entries:
            pat = entry["pattern"]
            expected = entry["line"]
            tol = entry.get("tolerance", 1)
            matching = [f for f in raw_findings if f.pattern == pat and abs(f.line - expected) <= tol]
            assert len(matching) > 0, f"Pattern {pat} near line {expected} (+/-{tol}) not found"

    def test_credential_multi_citations(self, ground_truth):
        rel = "fixtures/malicious/credential-multi/scripts/setup_env.py"
        gt_entries = ground_truth.get(rel, [])
        assert len(gt_entries) >= 5
        script = _load_script(rel)
        _, raw_findings, _ = scan_anchors({script.relative_path: script})
        for entry in gt_entries:
            pat = entry["pattern"]
            expected = entry["line"]
            tol = entry.get("tolerance", 1)
            matching = [f for f in raw_findings if f.pattern == pat and abs(f.line - expected) <= tol]
            assert len(matching) > 0, f"Pattern {pat} near line {expected} (+/-{tol}) not found"

    def test_sl4ck_bot_citations(self, ground_truth):
        rel = "fixtures/malicious/sl4ck-bot/scripts/bot.py"
        gt_entries = ground_truth.get(rel, [])
        assert len(gt_entries) >= 2
        script = _load_script(rel)
        _, raw_findings, _ = scan_anchors({script.relative_path: script})
        for entry in gt_entries:
            pat = entry["pattern"]
            expected = entry["line"]
            tol = entry.get("tolerance", 1)
            matching = [f for f in raw_findings if f.pattern == pat and abs(f.line - expected) <= tol]
            assert len(matching) > 0, f"Pattern {pat} near line {expected} (+/-{tol}) not found"

    def test_dns_tunneler_citations(self, ground_truth):
        rel = "fixtures/malicious/dns-tunneler/scripts/diagnostic.sh"
        gt_entries = ground_truth.get(rel, [])
        assert len(gt_entries) >= 3
        script = _load_script(rel)
        _, raw_findings, _ = scan_anchors({script.relative_path: script})
        for entry in gt_entries:
            pat = entry["pattern"]
            expected = entry["line"]
            tol = entry.get("tolerance", 1)
            matching = [f for f in raw_findings if f.pattern == pat and abs(f.line - expected) <= tol]
            assert len(matching) > 0, f"Pattern {pat} near line {expected} (+/-{tol}) not found"

    def test_weather_fetch_urllib(self, ground_truth):
        rel = "fixtures/benign/weather-fetch/scripts/fetch.py"
        gt_entries = ground_truth.get(rel, [])
        if not gt_entries:
            pytest.skip("No weather-fetch ground truth")
        script = _load_script(rel)
        _, raw_findings, _ = scan_anchors({script.relative_path: script})
        for entry in gt_entries:
            pat = entry["pattern"]
            expected = entry["line"]
            tol = entry.get("tolerance", 1)
            matching = [f for f in raw_findings if f.pattern == pat and abs(f.line - expected) <= tol]
            assert len(matching) > 0, f"Pattern {pat} near line {expected} (+/-{tol}) not found"


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Citation accuracy checker")
    parser.add_argument("--report", action="store_true", help="Print accuracy report table")
    args, unknown = parser.parse_known_args()

    if args.report:
        total_gt, tp, fp, fn, prec, rec, details = evaluate_citation_accuracy()
        print(f"Citation Accuracy Results:")
        print(f"Total Ground Truth: {total_gt}")
        print(f"True Positives:     {tp}")
        print(f"False Positives:    {fp}")
        print(f"False Negatives:    {fn}")
        print(f"Precision:          {prec:.2%}")
        print(f"Recall:             {rec:.2%}")
        for path, counts in details.items():
            print(f"  {path}: GT={counts['gt']} TP={counts['tp']} FP={counts['fp']} FN={counts['fn']}")
        sys.exit(0)

    sys.exit(pytest.main([str(Path(__file__)), "-q"] + unknown))
