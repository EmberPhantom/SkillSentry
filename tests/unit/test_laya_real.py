"""Real-Laya integration: runs only where the ``laya`` extra is installed.

The base suite stays offline.  Run these with the laya environment, for example
``.venv-laya``.  They need a checkpoint (downloaded on first use) and enough
memory to load it; a load failure is a real failure, not a skip.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest
from skill_sentry_cli.core.config import DecisionSettings
from skill_sentry_cli.core.decisions import LayaDecisionClient, semantic_questions
from skill_sentry_cli.core.parser import parse_skill
from skill_sentry_cli.core.semantic import scan_anchors
from skill_sentry_cli.core.semantic.laya_analyzer import build_decision_state

REPO = Path(__file__).resolve().parents[2]
CASES = REPO / "tests" / "fixtures" / "decisions" / "cases"

pytestmark = pytest.mark.skipif(
    importlib.util.find_spec("laya") is None,
    reason='requires the laya extra: pip install "skill-sentry-cli[laya]"',
)


@pytest.fixture(scope="module")
def client() -> LayaDecisionClient:
    settings = DecisionSettings(checkpoint="english", device="cpu", timeout_s=600)
    laya_client = LayaDecisionClient(settings)
    yield laya_client
    laya_client.close()


def _decide(client: LayaDecisionClient, case: str):  # type: ignore[no-untyped-def]
    package = parse_skill(CASES / case)
    state, *_ = build_decision_state(package, scan_anchors(package))
    return client.decide(state, semantic_questions(), timeout_s=600)


def test_health_probe_is_true_when_laya_imports(client: LayaDecisionClient) -> None:
    assert client.health() is True


@pytest.mark.parametrize("case", ["benign_env_log_level", "mal_aws_exfil"])
def test_real_answers_parse_into_the_typed_contract(client: LayaDecisionClient, case: str) -> None:
    result = _decide(client, case)

    assert set(result.answers) == set(semantic_questions())
    assert result.backend == "laya"
    assert result.checkpoint
    for answer in result.answers.values():
        assert answer.abstention or (
            answer.choice is not None or answer.score is not None or answer.noul is not None
        )


def test_real_malicious_case_scores_above_benign(client: LayaDecisionClient) -> None:
    benign = _decide(client, "benign_env_log_level").answers["cap_upload"].noul
    malicious = _decide(client, "mal_aws_exfil").answers["cap_upload"].noul

    assert benign is not None
    assert malicious is not None
    assert malicious >= benign
