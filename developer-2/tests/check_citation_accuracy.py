"""
Citation Accuracy Checker.

Validates that AST anchor findings report line numbers within ±tolerance
of ground truth annotations. Used as a CI regression gate.

Usage: pytest tests/check_citation_accuracy.py
"""

import json
from pathlib import Path

import pytest

from skillsentry_dev2.contracts import ScriptFile
from skillsentry_dev2.core.semantic.ast_anchor import scan_anchors


GROUND_TRUTH_PATH = Path(__file__).parent / "ground_truth.json"


def _load_ground_truth() -> dict:
    with open(GROUND_TRUTH_PATH) as f:
        return json.load(f)


def _load_script(fixture_path: str) -> ScriptFile:
    """Load a fixture script file as a ScriptFile object."""
    base = Path(__file__).resolve().parents[1]  # developer-2/
    full_path = base / fixture_path
    if not full_path.exists():
        pytest.skip(f"Fixture file not found: {full_path}")
    content = full_path.read_text(encoding="utf-8-sig", errors="replace")
    import hashlib
    return ScriptFile(
        relative_path=fixture_path.split("/", 1)[-1] if "/" in fixture_path else fixture_path,
        lines=content.splitlines(keepends=True),
        size_bytes=len(content.encode()),
        content_hash=hashlib.sha256(content.encode()).hexdigest(),
    )


class TestCitationAccuracy:
    """Verify that detected anchor lines match ground truth within tolerance."""

    @pytest.fixture
    def ground_truth(self):
        return _load_ground_truth()

    def test_invoice_helper_credential_read(self, ground_truth):
        gt_entries = ground_truth.get(
            "fixtures/malicious/invoice-helper/scripts/process.py", []
        )
        cred_gt = [e for e in gt_entries if e["pattern"] == "credential_read"]
        if not cred_gt:
            pytest.skip("No credential_read ground truth")

        script = _load_script("fixtures/malicious/invoice-helper/scripts/process.py")
        scripts = {script.relative_path: script}
        _, raw_findings, _ = scan_anchors(scripts)

        cred_findings = [f for f in raw_findings if f.pattern == "credential_read"]
        assert len(cred_findings) > 0, "credential_read pattern not detected"

        for gt_entry in cred_gt:
            expected_line = gt_entry["line"]
            tolerance = gt_entry.get("tolerance", 3)
            found_close = any(
                abs(f.line - expected_line) <= tolerance for f in cred_findings
            )
            assert found_close, (
                f"credential_read expected near line {expected_line} "
                f"(±{tolerance}), found at lines "
                f"{[f.line for f in cred_findings]}"
            )

    def test_invoice_helper_base64(self, ground_truth):
        gt_entries = ground_truth.get(
            "fixtures/malicious/invoice-helper/scripts/process.py", []
        )
        b64_gt = [e for e in gt_entries if e["pattern"] == "base64_decode"]
        if not b64_gt:
            pytest.skip("No base64_decode ground truth")

        script = _load_script("fixtures/malicious/invoice-helper/scripts/process.py")
        scripts = {script.relative_path: script}
        _, raw_findings, _ = scan_anchors(scripts)

        b64_findings = [f for f in raw_findings if f.pattern == "base64_decode"]
        assert len(b64_findings) > 0, "base64_decode pattern not detected"

        for gt_entry in b64_gt:
            expected_line = gt_entry["line"]
            tolerance = gt_entry.get("tolerance", 3)
            found_close = any(
                abs(f.line - expected_line) <= tolerance for f in b64_findings
            )
            assert found_close, (
                f"base64_decode expected near line {expected_line} "
                f"(±{tolerance}), found at lines "
                f"{[f.line for f in b64_findings]}"
            )

    def test_invoice_helper_requests_post(self, ground_truth):
        gt_entries = ground_truth.get(
            "fixtures/malicious/invoice-helper/scripts/process.py", []
        )
        rp_gt = [e for e in gt_entries if e["pattern"] == "requests_post"]
        if not rp_gt:
            pytest.skip("No requests_post ground truth")

        script = _load_script("fixtures/malicious/invoice-helper/scripts/process.py")
        scripts = {script.relative_path: script}
        _, raw_findings, _ = scan_anchors(scripts)

        rp_findings = [f for f in raw_findings if f.pattern == "requests_post"]
        assert len(rp_findings) > 0, "requests_post pattern not detected"

        for gt_entry in rp_gt:
            expected_line = gt_entry["line"]
            tolerance = gt_entry.get("tolerance", 3)
            found_close = any(
                abs(f.line - expected_line) <= tolerance for f in rp_findings
            )
            assert found_close, (
                f"requests_post expected near line {expected_line} "
                f"(±{tolerance}), found at lines "
                f"{[f.line for f in rp_findings]}"
            )

    def test_weather_fetch_urllib(self, ground_truth):
        gt_entries = ground_truth.get(
            "fixtures/benign/weather-fetch/scripts/fetch.py", []
        )
        urllib_gt = [e for e in gt_entries if e["pattern"] == "urllib"]
        if not urllib_gt:
            pytest.skip("No urllib ground truth")

        script = _load_script("fixtures/benign/weather-fetch/scripts/fetch.py")
        scripts = {script.relative_path: script}
        _, raw_findings, _ = scan_anchors(scripts)

        urllib_findings = [f for f in raw_findings if f.pattern == "urllib"]
        assert len(urllib_findings) > 0, "urllib pattern not detected"

        for gt_entry in urllib_gt:
            expected_line = gt_entry["line"]
            tolerance = gt_entry.get("tolerance", 3)
            found_close = any(
                abs(f.line - expected_line) <= tolerance for f in urllib_findings
            )
            assert found_close, (
                f"urllib expected near line {expected_line} "
                f"(±{tolerance}), found at lines "
                f"{[f.line for f in urllib_findings]}"
            )

