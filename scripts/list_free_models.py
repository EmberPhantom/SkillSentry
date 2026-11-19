#!/usr/bin/env python3
"""List the models each provider offers today, and which of them answer, as a dated roster.

Provider limits and model lists change often, so a list written by hand goes stale. This asks
each provider's own ``/models`` endpoint, keeps the free ones where the provider says which are
free, optionally sends each a one-token request to see whether it really answers, and writes the
result as JSON.

    python scripts/list_free_models.py                       # every provider that has a key set
    python scripts/list_free_models.py --providers local     # only the server on this machine
    python scripts/list_free_models.py --providers groq --probe-limit 10
    python scripts/list_free_models.py --no-probe            # list only, send no chat request

Rules this script keeps:

* **Keys come only from the environment** (``OPENROUTER_API_KEY``, ``NVIDIA_API_KEY``,
  ``GROQ_API_KEY``). It never asks for one, never reads one from a file, never prints one, and
  scrubs it from every message it records.
* **No request goes to a remote provider without its key.** A provider whose variable is unset is
  reported as skipped and nothing is sent. The local server needs no key and never leaves the
  machine.
* **Probes are few by default.** A free tier has a daily request cap and failed calls count
  against it, so each provider gets ``--probe-limit`` probes (3) unless ``--probe-all`` is given.
* **Local models are not probed unless asked** (``--probe-local``): a probe loads the model, and a
  large one needs more memory than a small machine has free.
* A probe sends the fixed text "Reply with the word ok." and nothing from any skill.
"""

from __future__ import annotations

import argparse
import json
import os
import sys
import time
from collections.abc import Callable, Mapping
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import httpx

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from skill_sentry_cli.core.models.profiles import classify
from skill_sentry_cli.core.models.providers import PRESETS

LOCAL_URL = "http://localhost:11434/v1"
PROBE_TEXT = "Reply with the word ok."
NOT_CHAT = ("whisper", "tts", "guard", "playai", "embed", "moderation", "rerank", "transcrib")
RATE_HEADERS = ("retry-after", "x-ratelimit")
DEFAULT_OUTPUT = Path("docs/operations/model-roster")
PROVIDERS = ("openrouter", "nim", "groq", "local")


def _key_for(provider: str, env: Mapping[str, str]) -> str:
    if provider == "local":
        return ""
    return env.get(PRESETS[provider].api_key_env, "").strip()


def _base_url(provider: str) -> str:
    return LOCAL_URL if provider == "local" else PRESETS[provider].base_url


def _scrub(text: str, key: str) -> str:
    return text.replace(key, "***") if len(key) >= 6 else text


def _headers(key: str) -> dict[str, str]:
    return {"Accept": "application/json", **({"Authorization": f"Bearer {key}"} if key else {})}


def _is_free(provider: str, item: dict[str, Any]) -> bool:
    """Whether the provider says this model is free. Only OpenRouter says so per model."""

    if provider == "openrouter":
        pricing = item.get("pricing") or {}
        free_price = str(pricing.get("prompt")) == "0" and str(pricing.get("completion")) == "0"
        return str(item.get("id", "")).endswith(":free") or free_price
    return True  # NIM and Groq list what the key may use; the local server costs nothing.


def list_models(provider: str, client: httpx.Client, key: str) -> list[dict[str, Any]]:
    """The provider's chat models, as ``{id, free, context, profile}``."""

    response = client.get(f"{_base_url(provider)}/models", headers=_headers(key), timeout=30)
    response.raise_for_status()
    listed = response.json().get("data", [])
    models: list[dict[str, Any]] = []
    for item in listed:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        model_id = str(item["id"])
        if any(word in model_id.lower() for word in NOT_CHAT):
            continue
        models.append(
            {
                "id": model_id,
                "free": _is_free(provider, item),
                "context": item.get("context_length") or item.get("context_window"),
                "profile": classify(model_id),
            }
        )
    return sorted(models, key=lambda model: model["id"])


def probe(provider: str, client: httpx.Client, key: str, model_id: str) -> dict[str, Any]:
    """One tiny request: does this model answer, how fast, and what limits does it report."""

    body = {
        "model": model_id,
        "messages": [{"role": "user", "content": PROBE_TEXT}],
        "max_tokens": 8,
        "temperature": 0,
    }
    started = time.monotonic()
    try:
        response = client.post(
            f"{_base_url(provider)}/chat/completions", headers=_headers(key), json=body, timeout=60
        )
    except httpx.HTTPError as exc:
        return {"ok": False, "status": None, "error": _scrub(type(exc).__name__, key)}
    elapsed = round((time.monotonic() - started) * 1000)
    limits = {
        name: value
        for name, value in response.headers.items()
        if name.lower().startswith(RATE_HEADERS)
    }
    result: dict[str, Any] = {
        "ok": response.status_code == 200,
        "status": response.status_code,
        "ms": elapsed,
    }
    if limits:
        result["rate_limits"] = limits
    if response.status_code != 200:
        try:
            message = response.json().get("error", {})
            message = message.get("message") if isinstance(message, dict) else message
        except ValueError:
            message = None
        result["error"] = _scrub(
            " ".join(str(message or response.reason_phrase).split())[:160], key
        )
    return result


def build_roster(
    providers: list[str],
    *,
    env: Mapping[str, str],
    client: httpx.Client,
    do_probe: bool,
    probe_limit: int | None,
    only_free: bool = True,
    probe_local: bool = False,
    now: datetime | None = None,
) -> dict[str, Any]:
    """The roster: one entry per provider, ``skipped`` when its key is not set."""

    stamp = (now or datetime.now(UTC)).replace(microsecond=0)
    roster: dict[str, Any] = {
        "generated_at": stamp.isoformat().replace("+00:00", "Z"),
        "note": (
            "Lists and limits change often. Verify before relying on a row. A probe sends only "
            f"the text {PROBE_TEXT!r}. Failed calls count against a free tier's daily cap."
        ),
        "providers": {},
    }
    for provider in providers:
        key = _key_for(provider, env)
        if provider != "local" and not key:
            roster["providers"][provider] = {
                "status": "skipped",
                "reason": f"{PRESETS[provider].api_key_env} is not set; nothing was sent",
            }
            continue
        try:
            models = list_models(provider, client, key)
        except (httpx.HTTPError, ValueError) as exc:
            status = getattr(getattr(exc, "response", None), "status_code", None)
            roster["providers"][provider] = {
                "status": "error",
                "reason": _scrub(
                    f"could not list models ({type(exc).__name__}{f' {status}' if status else ''})",
                    key,
                ),
            }
            continue
        if only_free:
            models = [model for model in models if model["free"]]
        if do_probe and (provider != "local" or probe_local):
            for model in models[: len(models) if probe_limit is None else probe_limit]:
                model["probe"] = probe(provider, client, key, model["id"])
        roster["providers"][provider] = {
            "status": "ok",
            "base_url": _base_url(provider),
            "models": models,
            "probed": sum(1 for model in models if "probe" in model),
        }
    return roster


def markdown(roster: dict[str, Any]) -> str:
    lines = [f"Roster generated {roster['generated_at']}", ""]
    for name, entry in roster["providers"].items():
        if entry["status"] != "ok":
            lines.append(f"- {name}: {entry['status']} ({entry['reason']})")
            continue
        lines += [f"- {name}: {len(entry['models'])} model(s), {entry['probed']} probed"]
        for model in entry["models"]:
            probed = model.get("probe")
            state = (
                ""
                if probed is None
                else (" ok" if probed["ok"] else f" FAILED {probed.get('status')}")
            )
            lines.append(f"    {model['id']}  [{model['profile']}]{state}")
    return "\n".join(lines) + "\n"


def main(
    argv: list[str] | None = None,
    *,
    env: Mapping[str, str] | None = None,
    client_factory: Callable[[], httpx.Client] = httpx.Client,
) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument("--providers", nargs="*", choices=PROVIDERS, default=list(PROVIDERS))
    parser.add_argument("--no-probe", action="store_true", help="list only; send no chat request")
    parser.add_argument(
        "--probe-limit", type=int, default=3, help="probes per provider (default 3)"
    )
    parser.add_argument("--probe-all", action="store_true", help="probe every listed model")
    parser.add_argument(
        "--probe-local", action="store_true", help="also probe the local server (loads each model)"
    )
    parser.add_argument("--all-models", action="store_true", help="keep models that are not free")
    parser.add_argument(
        "--output",
        type=Path,
        help="write the JSON here (default: a dated file under docs/operations/model-roster/)",
    )
    parser.add_argument(
        "--stdout", action="store_true", help="print the JSON instead of writing a file"
    )
    args = parser.parse_args(argv)

    environment = os.environ if env is None else env
    with client_factory() as client:
        roster = build_roster(
            args.providers,
            env=environment,
            client=client,
            do_probe=not args.no_probe,
            probe_limit=None if args.probe_all else args.probe_limit,
            only_free=not args.all_models,
            probe_local=args.probe_local,
        )
    text = json.dumps(roster, indent=2) + "\n"
    if args.stdout:
        sys.stdout.write(text)
    else:
        target = args.output or DEFAULT_OUTPUT / f"roster-{roster['generated_at'][:10]}.json"
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(text, encoding="utf-8")
        sys.stdout.write(markdown(roster) + f"\nwrote {target}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
