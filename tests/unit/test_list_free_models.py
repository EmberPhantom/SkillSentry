"""The roster script: keys only from the environment, no remote request without one, dated output."""

from __future__ import annotations

import importlib.util
import json
from datetime import UTC, datetime
from pathlib import Path

import httpx
import pytest

SCRIPT = Path(__file__).resolve().parents[2] / "scripts" / "list_free_models.py"
spec = importlib.util.spec_from_file_location("list_free_models", SCRIPT)
assert spec and spec.loader
roster_module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(roster_module)

KEY = "sk-roster-KEY-0123456789abcdef"
NOW = datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC)


class Provider:
    """A fake of every provider's /models and /chat/completions, recording each request."""

    def __init__(self) -> None:
        self.requests: list[httpx.Request] = []
        self.chat_status = 200

    def __call__(self, request: httpx.Request) -> httpx.Response:
        self.requests.append(request)
        host, path = request.url.host, request.url.path
        if path.endswith("/models"):
            if host == "openrouter.ai":
                return httpx.Response(
                    200,
                    json={
                        "data": [
                            {
                                "id": "meta/llama-3.1-8b:free",
                                "context_length": 131072,
                                "pricing": {"prompt": "0", "completion": "0"},
                            },
                            {
                                "id": "vendor/paid-70b",
                                "context_length": 8000,
                                "pricing": {"prompt": "0.001", "completion": "0.002"},
                            },
                            {
                                "id": "vendor/free-by-price-32b",
                                "pricing": {"prompt": "0", "completion": "0"},
                            },
                        ]
                    },
                )
            if host == "api.groq.com":
                return httpx.Response(
                    200,
                    json={
                        "data": [
                            {"id": "llama-3.3-70b-versatile", "context_window": 131072},
                            {"id": "whisper-large-v3"},
                            {"id": "meta-llama/llama-guard-4-12b"},
                            {"id": "openai/gpt-oss-20b", "context_window": 131072},
                        ]
                    },
                )
            if host == "integrate.api.nvidia.com":
                return httpx.Response(200, json={"data": [{"id": "nvidia/some-model-49b"}]})
            return httpx.Response(
                200, json={"data": [{"id": "gemma3:1b"}, {"id": "gemma4:e4b-it-qat"}]}
            )
        status = self.chat_status
        if status != 200:
            return httpx.Response(
                status,
                json={"error": {"message": f"nope, key {KEY}"}},
                headers={"Retry-After": "7"},
            )
        return httpx.Response(
            200,
            json={"choices": [{"message": {"content": "ok"}}]},
            headers={"x-ratelimit-remaining-requests": "19", "x-other": "x"},
        )


def _build(env: dict[str, str], providers: list[str], **kwargs):  # type: ignore[no-untyped-def]
    fake = Provider()
    fake.chat_status = kwargs.pop("chat_status", 200)
    client = httpx.Client(transport=httpx.MockTransport(fake))
    roster = roster_module.build_roster(
        providers,
        env=env,
        client=client,
        do_probe=kwargs.pop("do_probe", True),
        probe_limit=kwargs.pop("probe_limit", 3),
        now=NOW,
        **kwargs,
    )
    return roster, fake


def test_a_provider_without_a_key_is_skipped_and_nothing_is_sent():
    roster, fake = _build({}, ["openrouter", "nim", "groq"])

    assert [entry["status"] for entry in roster["providers"].values()] == ["skipped"] * 3
    assert "OPENROUTER_API_KEY is not set" in roster["providers"]["openrouter"]["reason"]
    assert fake.requests == []


def test_only_the_providers_with_a_key_are_contacted():
    roster, fake = _build({"GROQ_API_KEY": KEY}, ["openrouter", "groq"], do_probe=False)

    assert roster["providers"]["openrouter"]["status"] == "skipped"
    assert roster["providers"]["groq"]["status"] == "ok"
    assert {request.url.host for request in fake.requests} == {"api.groq.com"}


def test_the_key_goes_only_in_the_authorization_header():
    _, fake = _build({"GROQ_API_KEY": KEY}, ["groq"])

    for request in fake.requests:
        assert request.headers["Authorization"] == f"Bearer {KEY}"
        assert KEY not in str(request.url) and KEY not in request.content.decode()


def test_openrouter_keeps_the_free_models_by_suffix_or_price():
    roster, _ = _build({"OPENROUTER_API_KEY": KEY}, ["openrouter"], do_probe=False)

    ids = [model["id"] for model in roster["providers"]["openrouter"]["models"]]
    assert ids == ["meta/llama-3.1-8b:free", "vendor/free-by-price-32b"]


def test_all_models_keeps_the_paid_ones_too():
    roster, _ = _build({"OPENROUTER_API_KEY": KEY}, ["openrouter"], do_probe=False, only_free=False)

    assert "vendor/paid-70b" in [m["id"] for m in roster["providers"]["openrouter"]["models"]]


def test_models_that_do_not_chat_are_left_out_and_each_gets_a_profile():
    roster, _ = _build({"GROQ_API_KEY": KEY}, ["groq"], do_probe=False)

    models = {m["id"]: m for m in roster["providers"]["groq"]["models"]}
    assert set(models) == {"llama-3.3-70b-versatile", "openai/gpt-oss-20b"}
    assert models["llama-3.3-70b-versatile"]["profile"] == "large"
    assert models["openai/gpt-oss-20b"]["profile"] == "reasoning"
    assert models["llama-3.3-70b-versatile"]["context"] == 131072


def test_a_probe_records_the_status_the_time_and_the_limits_the_provider_reports():
    roster, fake = _build({"GROQ_API_KEY": KEY}, ["groq"])

    probe = roster["providers"]["groq"]["models"][0]["probe"]
    assert probe["ok"] is True and probe["status"] == 200 and probe["ms"] >= 0
    assert probe["rate_limits"] == {"x-ratelimit-remaining-requests": "19"}
    body = json.loads(
        next(r for r in fake.requests if r.url.path.endswith("chat/completions")).content
    )
    assert body["max_tokens"] == 8 and body["messages"][0]["content"] == "Reply with the word ok."


def test_a_failed_probe_records_the_error_and_never_the_key():
    roster, _ = _build({"GROQ_API_KEY": KEY}, ["groq"], chat_status=429)

    probe = roster["providers"]["groq"]["models"][0]["probe"]
    assert probe["ok"] is False and probe["status"] == 429
    assert probe["rate_limits"] == {"retry-after": "7"}
    assert KEY not in json.dumps(roster) and "***" in probe["error"]


def test_the_number_of_probes_is_capped():
    roster, fake = _build({"GROQ_API_KEY": KEY}, ["groq"], probe_limit=1)

    chats = [r for r in fake.requests if r.url.path.endswith("chat/completions")]
    assert len(chats) == 1 and roster["providers"]["groq"]["probed"] == 1


def test_no_probe_sends_no_chat_request():
    _, fake = _build({"GROQ_API_KEY": KEY}, ["groq"], do_probe=False)

    assert not [r for r in fake.requests if r.url.path.endswith("chat/completions")]


def test_the_local_server_needs_no_key_and_is_listed_but_not_probed_by_default():
    roster, fake = _build({}, ["local"])

    assert roster["providers"]["local"]["status"] == "ok"
    assert [m["id"] for m in roster["providers"]["local"]["models"]] == [
        "gemma3:1b",
        "gemma4:e4b-it-qat",
    ]
    assert not [r for r in fake.requests if r.url.path.endswith("chat/completions")]
    assert all(
        r.url.host == "localhost" and "Authorization" not in r.headers for r in fake.requests
    )


def test_the_local_server_is_probed_only_on_request():
    roster, fake = _build({}, ["local"], probe_local=True)

    assert roster["providers"]["local"]["probed"] == 2
    assert [r for r in fake.requests if r.url.path.endswith("chat/completions")]


def test_a_provider_that_will_not_list_is_an_error_entry_not_a_crash():
    def refuse(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, json={"error": {"message": f"bad {KEY}"}})

    roster = roster_module.build_roster(
        ["groq"],
        env={"GROQ_API_KEY": KEY},
        client=httpx.Client(transport=httpx.MockTransport(refuse)),
        do_probe=False,
        probe_limit=3,
        now=NOW,
    )

    entry = roster["providers"]["groq"]
    assert entry["status"] == "error" and "401" in entry["reason"]
    assert KEY not in json.dumps(roster)


def test_the_roster_is_dated_and_has_no_key_anywhere():
    roster, _ = _build(
        {"GROQ_API_KEY": KEY, "OPENROUTER_API_KEY": KEY}, ["groq", "openrouter"], chat_status=401
    )

    assert roster["generated_at"] == "2026-11-19T12:00:00Z"
    assert KEY not in json.dumps(roster)


def test_main_writes_a_dated_file_and_prints_a_summary(tmp_path: Path, capsys):
    target = tmp_path / "r.json"

    code = roster_module.main(
        ["--providers", "groq", "--output", str(target), "--no-probe"],
        env={"GROQ_API_KEY": KEY},
        client_factory=lambda: httpx.Client(transport=httpx.MockTransport(Provider())),
    )

    out = capsys.readouterr().out
    assert code == 0
    assert json.loads(target.read_text())["providers"]["groq"]["status"] == "ok"
    assert "llama-3.3-70b-versatile" in out and KEY not in out and KEY not in target.read_text()


def test_main_with_no_keys_makes_no_remote_request_and_still_writes(tmp_path: Path):
    fake = Provider()

    code = roster_module.main(
        ["--providers", "openrouter", "nim", "groq", "--stdout"],
        env={},
        client_factory=lambda: httpx.Client(transport=httpx.MockTransport(fake)),
    )

    assert code == 0 and fake.requests == []


def test_the_script_is_executable_in_git_and_never_reads_a_key_from_a_file():
    text = SCRIPT.read_text(encoding="utf-8")

    assert "os.environ" in text
    assert "open(" not in text and ".env" not in text.replace("os.environ", "")
    with pytest.raises(SystemExit):
        roster_module.main(["--providers", "not-a-provider"], env={})
