"""Evasion cases: which obfuscations the deterministic checks catch, and which they miss.

A case the checks miss is a strict xfail with a reason and a pointer to the docs. It fails
loudly if the gap closes, so the docs and `expected_verdicts.json` are updated, and it is never
silently dropped or loosened. See docs/security/evasion-limits.md.
"""

from __future__ import annotations

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # tests/, not tests/unit/
import check_expected_verdicts as harness

CASES = harness.evasion_expected()


def _param(name: str, expected: dict):  # type: ignore[no-untyped-def]
    gap = expected.get("known_gap")
    marks = (
        [pytest.mark.xfail(strict=True, reason=f"known gap: {gap['reason']} ({gap['tracking']})")]
        if gap
        else []
    )
    return pytest.param(name, expected, id=name, marks=marks)


@pytest.mark.parametrize(("name", "expected"), [_param(n, e) for n, e in CASES.items()])
def test_the_evasion_case_is_caught(name: str, expected: dict):
    assert harness.evasion_caught(name, expected), (
        f"{name}: {harness.scan_evasion_case(name)} is below "
        f"{expected['min_verdict']} / risk {expected.get('min_risk', 0)}"
    )


def test_every_fixture_has_an_expectation_and_the_reverse():
    on_disk = {path.name for path in harness.EVASION_FIXTURES.iterdir() if path.is_dir()}
    assert on_disk == set(CASES)


def test_every_known_gap_has_a_reason_and_a_documented_anchor():
    docs = Path(__file__).resolve().parents[2] / "docs" / "security" / "evasion-limits.md"
    text = docs.read_text(encoding="utf-8")
    for name, expected in CASES.items():
        gap = expected.get("known_gap")
        if gap is None:
            continue
        assert gap["reason"].strip(), name
        tracking = gap["tracking"]
        assert tracking.startswith("docs/security/evasion-limits.md#"), name
        anchor = tracking.split("#", 1)[1]
        assert f"(#{anchor})" in text or _slug_exists(text, anchor), (
            f"{name}: no section for #{anchor}"
        )


def _slug_exists(text: str, anchor: str) -> bool:
    for line in text.splitlines():
        if line.startswith("#"):
            slug = line.lstrip("# ").strip().lower().replace(" ", "-")
            slug = "".join(ch for ch in slug if ch.isalnum() or ch == "-")
            if slug == anchor:
                return True
    return False


def test_every_case_is_caught_today():
    results = {item.skill: item.status for item in harness.check_evasion()}

    assert set(results.values()) == {"PASS"}, results


def _with_a_gap(monkeypatch, *, caught: bool):  # type: ignore[no-untyped-def]
    cases = {
        "gap-case": {
            "min_verdict": "SUSPICIOUS",
            "known_gap": {"reason": "r", "tracking": "docs/security/evasion-limits.md#x"},
        },
        "plain-case": {"min_verdict": "SUSPICIOUS"},
    }
    monkeypatch.setattr(harness, "evasion_expected", lambda: cases)
    monkeypatch.setattr(harness, "evasion_caught", lambda name, expected: caught)


def test_the_harness_reports_a_missed_known_gap_separately_from_a_failure(monkeypatch):
    _with_a_gap(monkeypatch, caught=False)

    statuses = {item.skill: item.status for item in harness.check_evasion()}

    assert statuses == {"gap-case": "KNOWN-GAP", "plain-case": "FAIL"}


def test_a_known_gap_that_gets_caught_is_a_failure_not_a_quiet_pass(monkeypatch):
    _with_a_gap(monkeypatch, caught=True)

    statuses = {item.skill: item.status for item in harness.check_evasion()}

    assert statuses == {"gap-case": "FAIL", "plain-case": "PASS"}
