"""Static fixture-corpus acceptance tests (no Docker, deterministic model)."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
from skillsentry.core.cache import SQLiteStore
from skillsentry.core.contracts import ScanOptions
from skillsentry.core.engine import ScanEngine
from skillsentry.core.models.mock import MockGemma

ROOT = Path(__file__).resolve().parents[2]
FIXTURES = ROOT / "fixtures"
EXPECTED = json.loads((ROOT / "tests" / "expected_verdicts.json").read_text(encoding="utf-8"))


def _expected() -> dict[str, dict]:
    return EXPECTED["skills"]


def test_fixture_corpus_discovers_every_skill():
    store = SQLiteStore(":memory:")
    engine = ScanEngine(store=store, model=MockGemma(profile="benign"))
    try:
        roots = engine.discover(FIXTURES)
    finally:
        engine.close()
        store.close()

    names = {root.name for root in roots}
    assert names == set(_expected())
    assert roots == sorted(roots, key=lambda item: item.as_posix())


@pytest.mark.parametrize("name", sorted(_expected()))
def test_static_fixture_expected_verdict(name: str, tmp_path: Path):
    spec = _expected()[name]
    assert spec.get("static") is True
    store = SQLiteStore(tmp_path / f"{name}.sqlite")
    engine = ScanEngine(store=store, model=MockGemma())
    try:
        roots = {root.name: root for root in engine.discover(FIXTURES)}
        outcome = engine.scan(
            roots[name],
            options=ScanOptions(sandbox=False, backend="demo", no_cache=True),
        )
    finally:
        engine.close()
        store.close()

    verdict = outcome.verdict
    assert verdict.verdict.value == spec["verdict"], (name, verdict.verdict, verdict.findings)
    if "min_risk" in spec:
        assert verdict.risk_score >= spec["min_risk"], (name, verdict.risk_score)
    if "max_risk" in spec:
        assert verdict.risk_score <= spec["max_risk"], (name, verdict.risk_score)
    assert verdict.cached is False
