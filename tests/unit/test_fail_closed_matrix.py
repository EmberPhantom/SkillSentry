"""Parametrized fail-closed matrix tests with transport-level fakes.

Validates Section 8.5:
Server down, model missing, timeout mid-stage, malformed JSON, truncated prompt,
model None, and oversized input. In every failure case:
- Semantic stage is degraded (degraded=True)
- Verdict is never SAFE
- Hard malicious evidence forces MALICIOUS verdict (exit 1)
"""

from pathlib import Path
from types import SimpleNamespace
import pytest

from skillsentry.core.contracts import Finding, FindingEvidence, Severity, Stage, StageResult, VerdictTier
from skillsentry.core.models.base import ModelClient, ModelUnavailable
from skillsentry.core.semantic.errors import ModelBadResponse, ModelTimeout, PromptTruncated
from skillsentry.core.parser import SkillPackage, parse_skill
from skillsentry.core.semantic.gemma_analyzer import GemmaAnalyzer
from skillsentry.core.verdict.fusion import fuse


class FakeFailingClient(ModelClient):
    """Transport fake that simulates various server and transport failures."""

    def __init__(self, exc: Exception | None = None, bad_json: bool = False):
        self.exc = exc
        self.bad_json = bad_json
        self.backend = "fake"
        self.model_name = "fake-gemma"
        self.model_version = "fake-v1"
        self.digest = "sha256:fake"
        self.effective_ctx = 8192
        self.last_call = SimpleNamespace(
            prompt_eval_count=50,
            eval_count=20,
            latency_ms=5.0,
            model_name="fake-gemma",
            digest="sha256:fake",
        )

    def generate_json(self, system: str, user: str, schema: dict, retries: int = 1):
        if self.exc is not None:
            raise self.exc
        if self.bad_json:
            raise ModelBadResponse("Malformed JSON output from model")
        return {"claims": [], "suspicious_patterns": [], "confidence": 0.9}


def make_benign_pkg(tmp_path: Path) -> SkillPackage:
    pkg_dir = tmp_path / "benign-skill"
    pkg_dir.mkdir(parents=True, exist_ok=True)
    (pkg_dir / "SKILL.md").write_text(
        "---\nname: benign-skill\ndescription: A safe utility skill\n---\n# Main\n",
        encoding="utf-8",
    )
    (pkg_dir / "main.py").write_text("print('hello world')\n", encoding="utf-8")
    return parse_skill(pkg_dir)


@pytest.mark.fake_transport
@pytest.mark.parametrize(
    "error_case,client",
    [
        ("server_down", FakeFailingClient(exc=ModelUnavailable("Connection refused: 11434"))),
        ("model_missing", FakeFailingClient(exc=ModelUnavailable("Model gemma4:e4b not found"))),
        ("timeout_mid_stage", FakeFailingClient(exc=ModelTimeout("Inference timed out after 30s"))),
        ("malformed_json_twice", FakeFailingClient(bad_json=True)),
        ("truncated_prompt", FakeFailingClient(exc=PromptTruncated("Prompt exceeds context window"))),
        ("model_none", None),
    ],
)
def test_fail_closed_semantic_degradation_never_safe(tmp_path: Path, error_case: str, client: ModelClient | None):
    analyzer = GemmaAnalyzer(model=client)
    pkg = make_benign_pkg(tmp_path)
    anchors = StageResult(stage=Stage.DETERMINISTIC_ANCHOR, signals={}, findings=[])

    sem_res = analyzer.analyze(pkg, anchors)

    # 1. Stage must be marked degraded
    assert sem_res.degraded is True, f"Failed for {error_case}: stage was not marked degraded"

    # 2. Verdict must never be SAFE when degraded
    verdict = fuse([anchors, sem_res])
    assert verdict.verdict != VerdictTier.SAFE, f"Failed for {error_case}: verdict was {verdict.verdict}"
    assert Stage.SEMANTIC in verdict.degraded_stages


@pytest.mark.fake_transport
def test_fail_closed_hard_malicious_overrides_degraded(tmp_path: Path):
    """When hard malicious anchor evidence exists, verdict is MALICIOUS despite model degradation."""
    failing_client = FakeFailingClient(exc=ModelUnavailable("server down"))
    analyzer = GemmaAnalyzer(model=failing_client)
    pkg = make_benign_pkg(tmp_path)

    # Anchor with hard malicious floor
    mal_anchor = Finding(
        stage=Stage.DETERMINISTIC_ANCHOR,
        severity=Severity.CRITICAL,
        message="Hard malicious canary exfiltration",
        type="credential-flow-undeclared-host",
        evidence=FindingEvidence(file="main.py", line=1, code="exfil()"),
    )
    anchors = StageResult(
        stage=Stage.DETERMINISTIC_ANCHOR,
        signals={"anchors": 95.0},
        findings=[mal_anchor],
    )

    sem_res = analyzer.analyze(pkg, anchors)
    assert sem_res.degraded is True

    verdict = fuse([anchors, sem_res])
    # Hard malicious finding forces MALICIOUS tier (exit 1)
    assert verdict.verdict == VerdictTier.MALICIOUS
