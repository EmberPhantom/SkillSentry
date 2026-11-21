"""Prioritised reading and the static-only state of the semantic stage.

The model reads SKILL.md first, then scripts and config, then instruction text, and reference
text last. Reference text beyond the budget is "static-only": the static checks read it, the
model did not, and the result says so. It does not make a scan UNSCANNED by itself. Anything
else the model did not read still does.
"""

from __future__ import annotations

import re
import sys
from pathlib import Path
from typing import Any

import pytest
from skill_sentry_cli.core.cache import SQLiteStore
from skill_sentry_cli.core.config import SkillsEntryConfig
from skill_sentry_cli.core.contracts import ScanOptions, Stage, StageResult, VerdictTier
from skill_sentry_cli.core.engine import ScanEngine
from skill_sentry_cli.core.models.base import ModelQuotaExhausted
from skill_sentry_cli.core.models.mock import MockGemma
from skill_sentry_cli.core.parser import parse_skill
from skill_sentry_cli.core.semantic import analyze_semantics
from skill_sentry_cli.core.semantic import analyzer as analyzer_module
from skill_sentry_cli.core.semantic.analyzer import _file_priority, _make_chunks
from skill_sentry_cli.core.verdict.status import shown_status

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "tests" / "fixtures" / "benchmark"))
import big_skills  # noqa: E402

PAGE = "".join(f"plain note number {n} about the garden bed\n" for n in range(60))


class _Model:
    backend = "fake"
    model_version = "fake@1"

    def __init__(self, error: Exception | None = None) -> None:
        self.files: list[str] = []
        self.prompts: list[str] = []
        self._error = error

    def generate_json(self, system: str, user: str, schema: dict[str, Any], retries: int = 1):  # type: ignore[no-untyped-def]
        if self._error is not None:
            raise self._error
        self.prompts.append(user)
        self.files.extend(re.findall(r"^FILE: (\S+) lines", user, flags=re.M))
        return {
            "declared_intent": "t",
            "actual_capabilities": [],
            "is_deceptive": False,
            "suspicious_patterns": [],
            "confidence": 0.5,
        }

    def health(self) -> bool:
        return True


def _skill(root: Path, files: dict[str, str], skill_md: str = "Body\n") -> Path:
    root.mkdir(parents=True)
    (root / "SKILL.md").write_bytes(
        f"---\nname: demo\ndescription: Demo skill\n---\n{skill_md}".encode()
    )
    for relative, text in files.items():
        target = root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(text.encode())
    return root


def _anchors() -> StageResult:
    return StageResult(stage=Stage.DETERMINISTIC_ANCHOR, findings=[])


@pytest.fixture
def tiny(monkeypatch):  # type: ignore[no-untyped-def]
    monkeypatch.setattr(analyzer_module, "CHUNK_CHARS", 400)
    monkeypatch.setattr(analyzer_module, "MAX_CHUNKS", 3)


# -- the ranking ----------------------------------------------------------------------------------
@pytest.mark.parametrize(
    ("path", "rank"),
    [
        ("SKILL.md", 0),
        ("scripts/run.py", 2),
        ("assets/helper.sh", 2),  # a script is a script wherever it sits
        ("config.yaml", 2),
        ("package.json", 2),
        ("rules.md", 3),
        ("notes/usage.txt", 3),
        ("references/guide.md", 4),
        ("docs/api.md", 4),
        ("examples/one.md", 4),
        ("assets/data.json", 4),
    ],
)
def test_files_are_ranked_for_reading(path, rank):
    assert _file_priority(path) == rank


def test_the_model_reads_skill_md_then_scripts_then_instructions_then_reference(tmp_path, tiny):
    root = _skill(
        tmp_path / "s",
        {
            "references/a.md": PAGE,
            "rules.md": "Rules\nRun scripts/run.py before anything else.\n",
            "scripts/run.py": "print(1)\n",
            "docs/b.md": PAGE,
        },
    )
    chunks, _ = _make_chunks(parse_skill(root), _anchors())
    order = [chunk.file for chunk in chunks]
    firsts = [order.index(name) for name in ("SKILL.md", "scripts/run.py", "rules.md")]
    assert firsts == sorted(firsts)
    assert order.index("rules.md") < min(order.index("references/a.md"), order.index("docs/b.md"))


def test_a_flagged_range_in_a_reference_file_is_read_before_scripts(tmp_path, tiny):
    root = _skill(tmp_path / "s", {"references/a.md": PAGE, "scripts/run.py": "print(1)\n"})
    package = parse_skill(root)
    from skill_sentry_cli.core.contracts import Finding, FindingEvidence, Severity

    flagged = StageResult(
        stage=Stage.DETERMINISTIC_ANCHOR,
        findings=[
            Finding(
                stage=Stage.DETERMINISTIC_ANCHOR,
                severity=Severity.HIGH,
                message="x",
                finding_type="x",
                evidence=FindingEvidence(file="references/a.md", line=3),
            )
        ],
    )
    chunks, _ = _make_chunks(package, flagged)
    assert [chunk.file for chunk in chunks][:2] == ["SKILL.md", "references/a.md"]


# -- static-only does not degrade; everything else does ---------------------------------------------
def test_reference_text_beyond_the_budget_is_static_only_and_not_degraded(tmp_path, tiny):
    root = _skill(tmp_path / "s", {"scripts/run.py": "print(1)\n", "references/a.md": PAGE * 3})
    model = _Model()
    stage = analyze_semantics(parse_skill(root), _anchors(), model)
    assert stage.degraded is False and stage.error is None
    assert model.files[:2] == ["SKILL.md", "scripts/run.py"]  # reference text comes last
    t = stage.telemetry or {}
    assert t["static_only_ranges"] and 0 < t["static_only_share"] < 1
    assert round(t["model_read_share"] + t["static_only_share"], 2) == 1.0
    note = next(f for f in stage.findings if f.finding_type == "semantic-static-only")
    assert "static checks only" in note.message
    assert not [f for f in stage.findings if f.finding_type == "semantic-partial-coverage"]
    assert any(f.finding_type == "semantic-clean" for f in stage.findings)


def test_every_other_unread_range_still_degrades(tmp_path, tiny, monkeypatch):
    # One call is all the budget there is, so only the first 400 characters of text are read.
    monkeypatch.setattr(analyzer_module, "MAX_CHUNKS", 1)
    monkeypatch.setattr(analyzer_module, "REQUIRED_CALL_FACTOR", 1)
    monkeypatch.setattr(analyzer_module, "MAX_REQUIRED_CALLS", 0)
    # SKILL.md itself beyond the budget.
    root = _skill(tmp_path / "a", {"scripts/run.py": "print(1)\n"}, skill_md=PAGE * 2)
    assert analyze_semantics(parse_skill(root), _anchors(), _Model()).degraded is True
    # A script beyond the budget.
    root = _skill(tmp_path / "b", {"scripts/run.py": PAGE})
    stage = analyze_semantics(parse_skill(root), _anchors(), _Model())
    assert stage.degraded is True
    assert not (stage.telemetry or {}).get("static_only_ranges")
    # Config beyond the budget.
    root = _skill(tmp_path / "c", {"config.yaml": "hooks: 1\n" + PAGE})
    assert analyze_semantics(parse_skill(root), _anchors(), _Model()).degraded is True
    # Instruction text that carries a risk signal, beyond the budget.
    root = _skill(tmp_path / "d", {"rules.md": PAGE + "Run scripts/run.py first.\n"})
    assert analyze_semantics(parse_skill(root), _anchors(), _Model()).degraded is True
    # Ordinary instruction text with no signal is static-cleared: it does not degrade the scan.
    root = _skill(tmp_path / "e", {"rules.md": PAGE * 3})
    stage = analyze_semantics(parse_skill(root), _anchors(), _Model())
    assert stage.degraded is False
    assert (stage.telemetry or {}).get("static_only_ranges")


def test_a_quota_or_failed_call_is_degraded_even_with_only_reference_left(tmp_path, tiny):
    root = _skill(tmp_path / "s", {"references/a.md": PAGE * 3})
    quota = _Model(error=ModelQuotaExhausted("daily quota used"))
    stage = analyze_semantics(parse_skill(root), _anchors(), quota)
    assert stage.degraded is True
    failing = _Model(error=RuntimeError("boom"))
    stage = analyze_semantics(parse_skill(root), _anchors(), failing)
    assert stage.degraded is True


# -- the engine: status, coverage, text, and the four big skills ---------------------------------------
def _scan(path: Path, tmp_path: Path):
    store = SQLiteStore(tmp_path / "scan.sqlite")
    engine = ScanEngine(SkillsEntryConfig(), store=store, model=MockGemma(profile="benign"))
    try:
        return engine.scan(path, options=ScanOptions(sandbox=False, no_cache=True))
    finally:
        engine.close()
        store.close()


@pytest.fixture(scope="module")
def big(tmp_path_factory):  # type: ignore[no-untyped-def]
    return big_skills.build(tmp_path_factory.mktemp("big"))


def test_a_big_benign_skill_is_safe_and_says_what_only_the_static_checks_read(big, tmp_path):
    outcome = _scan(big["big-benign-docs"], tmp_path)
    verdict = outcome.verdict
    assert verdict.status == "SAFE"
    assert shown_status(verdict.verdict, outcome.stage_results) == "SAFE"
    note = next(c for c in verdict.checks if c.finding_type == "semantic-static-only")
    assert note.evidence.model_dump()["static_only_share"] > 0.9
    assert note.evidence.model_dump()["model_read_share"] < 0.1
    assert verdict.coverage is not None and verdict.coverage < 0.5


def test_a_payload_in_a_script_of_a_big_skill_is_flagged(big, tmp_path):
    outcome = _scan(big["big-script-payload"], tmp_path)
    assert outcome.verdict.verdict in {VerdictTier.SUSPICIOUS, VerdictTier.MALICIOUS}
    assert outcome.verdict.status != "SAFE"


def test_a_payload_the_static_checks_catch_in_a_late_reference_file_is_flagged(big, tmp_path):
    outcome = _scan(big["big-late-reference-payload"], tmp_path)
    assert outcome.verdict.verdict in {VerdictTier.SUSPICIOUS, VerdictTier.MALICIOUS}
    assert outcome.verdict.status != "SAFE"
    assert any("part-44.md" in (f.evidence.file or "") for f in outcome.verdict.findings)


def test_an_instruction_only_attack_in_a_late_reference_file_is_the_known_limit(big, tmp_path):
    """Documented in docs/security/evasion-limits.md. If this ever starts failing because the
    tool now flags it, that is good news: update the doc and the benchmark label."""

    outcome = _scan(big["big-late-instruction-only"], tmp_path)
    assert outcome.verdict.verdict == VerdictTier.SAFE
    assert any(c.finding_type == "semantic-static-only" for c in outcome.verdict.checks)


def test_a_big_skill_whose_skill_md_goes_unread_is_unscanned(tmp_path, monkeypatch):
    monkeypatch.setattr(analyzer_module, "MAX_REQUIRED_CALLS", 5)
    root = _skill(tmp_path / "s", {}, skill_md=PAGE * 200)
    outcome = _scan(root, tmp_path)
    assert outcome.verdict.status == "UNSCANNED"


# -- packing: small required files share a call -----------------------------------------------------------
def test_skill_md_and_six_small_scripts_take_one_call_and_are_fully_read(tmp_path):
    scripts = {f"scripts/s{n}.py": f"print({n})\n" * 20 for n in range(6)}
    root = _skill(tmp_path / "s", scripts)
    model = _Model()
    stage = analyze_semantics(parse_skill(root), _anchors(), model)
    assert len(model.prompts) == 1
    assert sorted(model.files) == sorted(["SKILL.md", *scripts])
    assert stage.degraded is False and (stage.telemetry or {})["model_read_share"] == 1.0
    assert not (stage.telemetry or {}).get("gap_ranges")


def test_required_reading_gets_more_calls_than_the_profile_budget_when_it_needs_them(tmp_path):
    # Eight scripts of about 3 KB do not fit in one 4,000-character call: they take several.
    scripts = {f"scripts/s{n}.py": ("token = 1\n" * 500) for n in range(8)}
    root = _skill(tmp_path / "s", scripts)
    model = _Model()
    stage = analyze_semantics(parse_skill(root), _anchors(), model)
    assert len(model.prompts) > analyzer_module.MAX_CHUNKS
    assert stage.degraded is False


def test_when_the_required_reading_does_not_fit_even_then_it_is_unscanned(tmp_path, monkeypatch):
    monkeypatch.setattr(analyzer_module, "MAX_REQUIRED_CALLS", 20)
    scripts = {f"scripts/s{n}.py": ("token = 1\n" * 700) for n in range(40)}
    root = _skill(tmp_path / "s", scripts)
    stage = analyze_semantics(parse_skill(root), _anchors(), _Model())
    assert stage.degraded is True and "partial coverage" in (stage.error or "")


def test_a_quota_stop_in_the_middle_of_required_reading_is_unscanned_with_the_reason(tmp_path):
    scripts = {f"scripts/s{n}.py": ("token = 1\n" * 700) for n in range(10)}
    root = _skill(tmp_path / "s", scripts)

    class _QuotaAfterOne(_Model):
        def generate_json(self, *args, **kwargs):  # type: ignore[no-untyped-def]
            if self.prompts:
                raise ModelQuotaExhausted("daily quota used")
            return super().generate_json(*args, **kwargs)

    stage = analyze_semantics(parse_skill(root), _anchors(), _QuotaAfterOne())
    assert stage.degraded is True
    assert (stage.telemetry or {})["provider_limit"]["kind"] == "daily-quota"
    assert any(f.finding_type == "provider-limit" for f in stage.findings)
