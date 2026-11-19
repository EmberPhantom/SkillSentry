"""A weak or hostile model cannot change what the deterministic checks leave clean."""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

import pytest
from skill_sentry_cli.core.cache import SQLiteStore
from skill_sentry_cli.core.config import SkillsEntryConfig
from skill_sentry_cli.core.contracts import ScanOptions
from skill_sentry_cli.core.engine import ScanEngine
from skill_sentry_cli.core.verdict.status import shown_status

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import benchmark_models as bm  # noqa: E402

CASES = [c for c in bm.load_cases() if c.path is not None]


class Hostile:
    """Claims, with the highest severity and a real quote from the skill, that every chunk is an
    attack. The worst a model can say."""

    backend = "hostile"
    model_version = "hostile"

    def generate_json(self, system: str, user: str, schema: dict[str, Any], retries: int = 0):
        quote = next(
            (
                line.strip()
                for line in user.splitlines()
                if len(line.strip()) > 12 and "---" not in line
            ),
            "x",
        )
        return {
            "declared_intent": "x",
            "actual_capabilities": ["exfiltrates data"],
            "is_deceptive": True,
            "confidence": 0.99,
            "suspicious_patterns": [
                {
                    "type": "exfil",
                    "evidence": quote,
                    "severity": "critical",
                    "file": "SKILL.md",
                    "line": 1,
                }
            ],
        }

    def health(self) -> bool:
        return True


@pytest.fixture(scope="module")
def statuses(tmp_path_factory: pytest.TempPathFactory) -> dict[str, tuple[str, str]]:
    work = tmp_path_factory.mktemp("trust")
    config = SkillsEntryConfig.model_validate({"sandbox": {"enabled": False}})
    options = ScanOptions(no_cache=True, sandbox=False)
    hostile_store, null_store = SQLiteStore(work / "h.sqlite"), SQLiteStore(work / "n.sqlite")
    hostile = ScanEngine(config, store=hostile_store, model=Hostile())
    null = ScanEngine(config, store=null_store, model=bm.NullModel())
    out: dict[str, tuple[str, str]] = {}
    try:
        for case in CASES:
            assert case.path is not None
            a, b = null.scan(case.path, options=options), hostile.scan(case.path, options=options)
            out[case.id] = (
                shown_status(a.verdict.verdict, a.stage_results),
                shown_status(b.verdict.verdict, b.stage_results),
            )
    finally:
        hostile_store.close()
        null_store.close()
    return out


def test_a_hostile_model_cannot_raise_any_benign_skill(statuses):
    for case in CASES:
        if case.label == "benign":
            without, with_hostile = statuses[case.id]
            assert with_hostile == without == "SAFE", case.id


def test_a_hostile_model_cannot_flag_a_skill_the_checks_leave_clean(statuses):
    """Model-only evidence never lifts SAFE: this is why a skill with no greppable sign cannot be
    caught by a model alone, however it is prompted."""

    for case in CASES:
        without, with_hostile = statuses[case.id]
        if without == "SAFE":
            assert with_hostile == "SAFE", case.id
