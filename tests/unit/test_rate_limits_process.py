"""A folder scan in a real process against a server that rate limits, runs out of quota and is slow."""

from __future__ import annotations

import http.server
import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import ClassVar

import pytest

KEY = "sk-test-KEY-0123456789abcdef"
REPLY = {
    "declared_intent": "x",
    "actual_capabilities": [],
    "suspicious_patterns": [],
    "is_deceptive": False,
    "confidence": 0.5,
}


class _Server(http.server.ThreadingHTTPServer):
    ok_before_quota = 10**6
    delay_s = 0.0
    requests = 0
    lock = threading.Lock()


class _Handler(http.server.BaseHTTPRequestHandler):
    auth_seen: ClassVar[list[str]] = []

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
        server: _Server = self.server  # type: ignore[assignment]
        with server.lock:
            server.requests += 1
            number = server.requests
        if server.delay_s:
            time.sleep(server.delay_s)
        if number > server.ok_before_quota:
            self._send(
                429,
                {"error": {"message": f"Rate limit reached: requests per day (RPD). key {KEY}"}},
            )
            return
        self._send(
            200,
            {
                "choices": [{"message": {"content": json.dumps(REPLY)}, "finish_reason": "stop"}],
                "usage": {"total_tokens": 40},
            },
        )


@pytest.fixture
def server():
    srv = _Server(("127.0.0.1", 0), _Handler)
    thread = threading.Thread(target=srv.serve_forever, daemon=True)
    thread.start()
    yield srv
    srv.shutdown()
    srv.server_close()


def _folder(tmp_path: Path, count: int) -> Path:
    folder = tmp_path / "skills"
    for index in range(1, count + 1):
        skill = folder / f"s{index}"
        skill.mkdir(parents=True)
        (skill / "SKILL.md").write_text(
            f"---\nname: s{index}\ndescription: Print note {index}.\n---\n\nHello {index}.\n",
            encoding="utf-8",
        )
    return folder


def _scan(tmp_path: Path, server: _Server, folder: Path, *, limits: str = "", extra=()):
    port = server.server_address[1]
    config = tmp_path / "skillsentry.toml"
    config.write_text(
        '[model]\nbackend = "openai"\n[model.provider]\n'
        f'base_url = "http://127.0.0.1:{port}/v1"\nmodel = "m-1"\napi_key_env = "MY_KEY"\n'
        f"{limits}[sandbox]\nenabled = false\n",
        encoding="utf-8",
    )
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    env = {
        **os.environ,
        "PYTHONUTF8": "1",
        "PYTHONIOENCODING": "utf-8",
        "MY_KEY": KEY,
        "SKILLSENTRY_CONFIG": str(config),
        "SKILLSENTRY_DB": str(tmp_path / "db.sqlite"),
        "HOME": str(home),
        "USERPROFILE": str(home),
    }
    env.pop("SKILLSENTRY_DEV", None)
    started = time.monotonic()
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "skill_sentry_cli",
            "scan",
            str(folder),
            "--no-sandbox",
            "--no-cache",
            "--format",
            "json",
            *extra,
        ],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        env=env,
        timeout=180,
        cwd=str(tmp_path),
    )
    return result, time.monotonic() - started


def _statuses(result: subprocess.CompletedProcess[str]) -> list[str]:
    return [row["verdict"] for row in json.loads(result.stdout)]


def test_a_folder_scan_that_hits_the_daily_quota_stops_asking_and_says_how_far_it_got(
    tmp_path, server
):
    server.ok_before_quota = 2
    result, _ = _scan(tmp_path, server, _folder(tmp_path, 5))

    assert result.returncode == 4, result.stdout + result.stderr
    statuses = _statuses(result)
    assert statuses[:2] == ["SAFE", "SAFE"]
    # The rest are UNSCANNED, never silently SAFE: the model never read them.
    assert len(statuses) == 5 and all(s != "SAFE" for s in statuses[2:])
    assert server.requests == 3  # two answers and the one that said "quota": then it stopped
    assert result.stderr.count("quota for m-1 is used up") == 1  # one message, not one per skill
    assert (
        "the model read 2 of 5 skill(s) in full; 3 had its model analysis cut short"
        in result.stderr
    )
    assert KEY not in result.stdout + result.stderr


def test_a_scan_the_deadline_cannot_pace_does_not_sleep_past_it_and_sends_nothing_late(
    tmp_path, server
):
    result, wall = _scan(
        tmp_path,
        server,
        _folder(tmp_path, 3),
        limits="requests_per_minute = 1\n",
        extra=("--max-time", "10"),
    )

    assert result.returncode == 4, result.stdout + result.stderr
    assert _statuses(result)[0] == "SAFE"
    assert all(s != "SAFE" for s in _statuses(result)[1:])
    assert server.requests == 1  # the second request would have waited about a minute
    assert "the request was not sent" in result.stderr
    assert wall < 50  # it did not sleep a minute


def test_slow_replies_are_waited_for_and_the_scan_finishes_clean(tmp_path, server):
    server.delay_s = 0.4
    result, _ = _scan(tmp_path, server, _folder(tmp_path, 3), limits="requests_per_minute = 100\n")

    assert result.returncode == 0, result.stdout + result.stderr
    assert _statuses(result) == ["SAFE", "SAFE", "SAFE"]
    assert "quota" not in result.stderr
