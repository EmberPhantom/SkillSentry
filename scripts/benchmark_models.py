#!/usr/bin/env python3
"""A labelled precision benchmark: how well does each model, behind the harness, tell skills apart?

It scans a labelled set of skills with each model and reports, per model, how the verdicts compare
with the labels, what the model added on top of the deterministic checks, and how the model
behaved (replies that were valid first time, truncation, timeouts, 429s, quotes that exist in the
skill, tokens, time, and how often the verdict flipped across repeats).

The set (``tests/fixtures/benchmark/labels.json``) is the 14-skill verification corpus, the
evasion fixtures, and larger benign and malicious sets. Every skill carries a label (benign,
malicious, or invalid) and whether the deterministic checks alone should decide it. The skills
are inert text and code; the sandbox is off unless ``--sandbox`` is given, so the numbers are
for the static checks plus the model.

    python scripts/benchmark_models.py --model ollama=gemma3:1b --model ollama=qwen2.5-coder:1.5b
    python scripts/benchmark_models.py --model groq=llama-3.1-8b-instant      # needs GROQ_API_KEY

``--model PROVIDER=MODEL_ID``: ``ollama`` (a model on this machine, native API), ``gemini``,
``openai`` (with ``--base-url``), or a preset (``openrouter``, ``nim``, ``groq``). A provider
that needs a key is skipped, with no network call, when its key is not in the environment. A model
on this machine larger than 4 GB is refused unless ``--allow-large``.

Results are written to ``docs/operations/model-matrix/<date>/``. The raw rows are appended to
``rows.jsonl`` as they are produced, so a run that is stopped (a quota, a crash, Ctrl-C) is
resumed by running the same command again: rows already there are not repeated.

The matrix compares the first repeat with the labels. Flips are counted across all repeats. A
skill the sandbox or model could not read is UNSCANNED and is counted apart, never as SAFE.
"""

from __future__ import annotations

import argparse
import contextlib
import datetime as dt
import hashlib
import json
import os
import statistics
import sys
import tempfile
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import httpx

REPO = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.path.insert(0, str(REPO))

LABELS = REPO / "tests" / "fixtures" / "benchmark" / "labels.json"
DEFAULT_OUT = REPO / "docs" / "operations" / "model-matrix"
LARGE_MODEL_BYTES = 4 * 1024**3
POSITIVE = {"SUSPICIOUS", "MALICIOUS"}
STATUSES = ("SAFE", "SUSPICIOUS", "MALICIOUS", "UNSCANNED", "INVALID SKILL")
RANK = {"SAFE": 0, "SUSPICIOUS": 1, "MALICIOUS": 2}


# -- the labelled set ---------------------------------------------------------------------------
@dataclass(frozen=True)
class Case:
    id: str
    set: str
    label: str  # benign | malicious | invalid
    category: str
    decided_by: str  # anchors | model
    path: Path | None = None
    corpus_name: str | None = None
    expected_status: str | None = None
    note: str = ""


def load_cases(labels: Path = LABELS, *, repo: Path = REPO) -> list[Case]:
    data = json.loads(labels.read_text(encoding="utf-8"))
    cases = []
    for item in data["cases"]:
        path = repo / item["path"] if "path" in item else None
        cases.append(
            Case(
                id=item["id"],
                set=item["set"],
                label=item["label"],
                category=item["category"],
                decided_by=item["decided_by"],
                path=path,
                corpus_name=item.get("name") if item.get("source") == "corpus" else None,
                expected_status=item.get("expected_status"),
                note=item.get("note", ""),
            )
        )
    return cases


def materialise(cases: list[Case], work: Path) -> dict[str, Path]:
    """Folder for each case; the corpus skills are built under ``work``."""

    folders: dict[str, Path] = {}
    corpus = None
    for case in cases:
        if case.path is not None:
            folders[case.id] = case.path
            continue
        if corpus is None:
            from verify_corpus import build_corpus

            root = work / "corpus"
            root.mkdir(parents=True, exist_ok=True)
            corpus = build_corpus(root)
        assert case.corpus_name is not None
        folders[case.id] = corpus[case.corpus_name]
    return folders


# -- measuring one model's calls ------------------------------------------------------------------
def _first_line_needle(text: str) -> str:
    lines = text.strip().splitlines()
    first = lines[0] if lines else ""
    return " ".join(first.lower().split())[:200]


def parse_reply(path: str, body: dict[str, Any]) -> dict[str, Any]:
    """Text, token counts and stop reason from a reply, for the API the path names."""

    out: dict[str, Any] = {"text": None, "tokens_in": None, "tokens_out": None, "truncated": False}
    if path.endswith("/chat/completions"):
        choice = (body.get("choices") or [{}])[0]
        out["text"] = (choice.get("message") or {}).get("content")
        out["truncated"] = choice.get("finish_reason") == "length"
        usage = body.get("usage") or {}
        out["tokens_in"], out["tokens_out"] = (
            usage.get("prompt_tokens"),
            usage.get("completion_tokens"),
        )
    elif path.endswith("/api/generate"):
        out["text"] = body.get("response")
        out["truncated"] = body.get("done_reason") == "length"
        out["tokens_in"], out["tokens_out"] = body.get("prompt_eval_count"), body.get("eval_count")
    elif ":generateContent" in path:
        candidate = (body.get("candidates") or [{}])[0]
        parts = (candidate.get("content") or {}).get("parts") or []
        out["text"] = "".join(p.get("text", "") for p in parts if isinstance(p, dict))
        out["truncated"] = candidate.get("finishReason") == "MAX_TOKENS"
        usage = body.get("usageMetadata") or {}
        out["tokens_in"], out["tokens_out"] = (
            usage.get("promptTokenCount"),
            usage.get("candidatesTokenCount"),
        )
    return out


def judge_reply(text: str | None, skill_text: str) -> dict[str, Any]:
    """Is the reply valid JSON for the semantic schema, and are its quotes in the skill?"""

    from skill_sentry_cli.core.models._json import parse_json_object, validate_json
    from skill_sentry_cli.core.semantic.prompts import SEMANTIC_SCHEMA, SEMANTIC_SCHEMA_COMPACT

    result = {"valid": False, "quotes": 0, "quotes_found": 0}
    if not text:
        return result
    try:
        parsed = parse_json_object(text)
    except ValueError:
        return result
    for schema in (SEMANTIC_SCHEMA, SEMANTIC_SCHEMA_COMPACT):
        try:
            validate_json(parsed, schema)
            result["valid"] = True
            break
        except ValueError:
            continue
    if not result["valid"]:
        return result
    haystack = " ".join(skill_text.lower().split())
    for pattern in parsed.get("suspicious_patterns", []):
        needle = _first_line_needle(str(pattern.get("evidence", "")))
        result["quotes"] += 1
        if len(needle) >= 4 and needle in haystack:
            result["quotes_found"] += 1
    return result


class Meter(httpx.BaseTransport):
    """Records every request a model client makes, then passes it on unchanged.

    The record holds counts, timings and token numbers, never the key or the skill text.
    """

    def __init__(self, inner: httpx.BaseTransport | None = None) -> None:
        self.inner = inner or httpx.HTTPTransport()
        self.calls: list[dict[str, Any]] = []
        self.skill_text = ""
        self._seen: set[str] = set()

    def begin(self, skill_text: str) -> None:
        self.calls = []
        self.skill_text = skill_text
        self._seen = set()

    def handle_request(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path
        if request.method != "POST":
            return self.inner.handle_request(request)
        from skill_sentry_cli.core.models._json import RETRY_MARKER

        digest = hashlib.sha256(request.content).hexdigest()
        # A retry after a refused reply carries a reminder, so it is told by that, not only by
        # being a repeat of an earlier request.
        first_attempt = digest not in self._seen and RETRY_MARKER.encode() not in request.content
        self._seen.add(digest)
        record: dict[str, Any] = {"first_attempt": first_attempt, "timeout": False, "status": None}
        started = time.monotonic()
        try:
            response = self.inner.handle_request(request)
        except httpx.TimeoutException:
            record.update(timeout=True, latency_s=round(time.monotonic() - started, 2))
            self.calls.append(record)
            raise
        response.read()
        record["status"] = response.status_code
        record["latency_s"] = round(time.monotonic() - started, 2)
        if response.status_code == 200:
            try:
                body = json.loads(response.content)
            except ValueError:
                body = {}
            parsed = parse_reply(path, body if isinstance(body, dict) else {})
            record.update(
                tokens_in=parsed["tokens_in"],
                tokens_out=parsed["tokens_out"],
                truncated=parsed["truncated"],
                **judge_reply(parsed["text"], self.skill_text),
            )
        self.calls.append(record)
        return response

    def close(self) -> None:
        self.inner.close()


# -- targets (a provider and a model) ----------------------------------------------------------------
@dataclass
class Target:
    name: str  # provider=model
    provider: str
    model: str
    skipped: str | None = None
    settings: dict[str, Any] = field(default_factory=dict)

    @property
    def key_variable(self) -> str:
        from skill_sentry_cli.core.models.providers import PRESETS

        if self.provider in PRESETS:
            return PRESETS[self.provider].api_key_env
        return {"gemini": "GEMINI_API_KEY"}.get(self.provider, "")


def resolve_target(
    spec: str, *, base_url: str | None, key_env: str, allow_large: bool, ollama_url: str
) -> Target:
    """Turn ``provider=model`` into a target, or a skipped one with the reason. No model is
    called here; a remote provider is only checked for its key in the environment."""

    provider, _, model = spec.partition("=")
    provider, model = provider.strip().lower(), model.strip()
    target = Target(spec, provider, model)
    if not model:
        target.skipped = "no model id (use provider=model)"
        return target
    if provider == "ollama":
        target.settings = {
            "backend": "local",
            "ollama_model": model,
            "ollama_url": ollama_url,
            "ollama_num_ctx": 4096,
            "ollama_keep_alive": "10m",
        }
        try:
            listing = httpx.get(f"{ollama_url.rstrip('/')}/api/tags", timeout=3).json()
        except (httpx.HTTPError, ValueError):
            target.skipped = f"Ollama is not reachable at {ollama_url}"
            return target
        entry = next((m for m in listing.get("models", []) if m.get("name") == model), None)
        if entry is None:
            target.skipped = f"{model} is not pulled in Ollama"
        elif entry.get("size", 0) > LARGE_MODEL_BYTES and not allow_large:
            gib = entry["size"] / 1024**3
            target.skipped = f"{model} is {gib:.1f} GB; pass --allow-large to load it"
        return target
    if provider in {"gemini", "openai", "openrouter", "nim", "groq"}:
        variable = key_env if provider == "openai" else target.key_variable
        if not os.environ.get(variable):
            target.skipped = f"{variable} is not set (no request was made)"
            return target
        if provider == "gemini":
            target.settings = {"backend": "cloud", "gemini_model": model}
        else:
            provider_settings: dict[str, Any] = {"model": model}
            if provider == "openai":
                if not base_url:
                    target.skipped = "--base-url is required for the openai provider"
                    return target
                provider_settings.update(base_url=base_url, api_key_env=key_env)
            target.settings = {"backend": provider, "provider": provider_settings}
        return target
    target.skipped = f"unknown provider {provider!r}"
    return target


def build_client(target: Target, meter: Meter) -> Any:
    from skill_sentry_cli.core.config import SkillsEntryConfig
    from skill_sentry_cli.core.models.selector import select_model

    config = SkillsEntryConfig.model_validate({"model": target.settings})
    client = select_model(config, backend=target.settings["backend"], probe=True)
    client._client = httpx.Client(transport=meter, timeout=getattr(client, "timeout_s", 180.0))
    return client, config


class NullModel:
    """Says nothing is wrong. Scanning with it gives the verdict the deterministic checks reach
    alone, so what a real model adds can be measured against it. It makes no request."""

    backend = "none"
    model_version = "none"

    def generate_json(self, *args: Any, **kwargs: Any) -> dict[str, Any]:
        from skill_sentry_cli.core.models.mock import CLEAN_RESPONSE

        return dict(CLEAN_RESPONSE)

    def health(self) -> bool:
        return True


# -- scanning --------------------------------------------------------------------------------------
def skill_text_of(folder: Path) -> str:
    parts = []
    for file in sorted(folder.rglob("*")):
        if file.is_file() and file.stat().st_size < 1_000_000:
            with contextlib.suppress(OSError, UnicodeDecodeError):
                parts.append(file.read_text(encoding="utf-8"))
    return "\n".join(parts)


def scan_row(
    engine: Any, case: Case, folder: Path, meter: Meter | None, *, sandbox: bool
) -> dict[str, Any]:
    from skill_sentry_cli.core.contracts import ScanOptions, Stage
    from skill_sentry_cli.core.engine import ScanError
    from skill_sentry_cli.core.verdict.status import shown_status

    if meter is not None:
        meter.begin(skill_text_of(folder) if folder.is_dir() else "")
    started = time.monotonic()
    row: dict[str, Any] = {"skill": case.id}
    try:
        outcome = engine.scan(folder, options=ScanOptions(no_cache=True, sandbox=sandbox))
    except ScanError as exc:
        row.update(
            status="INVALID SKILL" if exc.code == "invalid_skill" else "ERROR", error=str(exc)[:200]
        )
        row["wall_s"] = round(time.monotonic() - started, 2)
        return row
    row["wall_s"] = round(time.monotonic() - started, 2)
    row["status"] = shown_status(outcome.verdict.verdict, outcome.stage_results)
    row["risk"] = outcome.verdict.risk_score
    row["confidence"] = outcome.verdict.confidence
    semantic = next((r for r in outcome.stage_results if r.stage is Stage.SEMANTIC), None)
    if semantic is not None:
        telemetry = semantic.telemetry or {}
        row["semantic_s"] = round((telemetry.get("durationMs") or 0) / 1000, 2)
        row["semantic_degraded"] = bool(semantic.degraded)
        row["provider_limit"] = telemetry.get("provider_limit")
        row["semantic_findings"] = sorted(
            {f.finding_type for f in semantic.findings if f.severity.value != "note"}
        )
    row["anchor_findings"] = sorted(
        {
            f.finding_type
            for r in outcome.stage_results
            if r.stage is not Stage.SEMANTIC
            for f in r.findings
            if f.severity.value not in {"note", "low"}
        }
    )
    if meter is not None:
        row["calls"] = meter.calls
    return row


def done_keys(rows_file: Path) -> set[tuple[str, str, int]]:
    keys: set[tuple[str, str, int]] = set()
    if rows_file.exists():
        for line in rows_file.read_text(encoding="utf-8").splitlines():
            with contextlib.suppress(ValueError, KeyError):
                row = json.loads(line)
                keys.add((row["target"], row["skill"], int(row["repeat"])))
    return keys


def append_row(rows_file: Path, row: dict[str, Any]) -> None:
    with rows_file.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")


def read_rows(rows_file: Path) -> list[dict[str, Any]]:
    if not rows_file.exists():
        return []
    return [json.loads(line) for line in rows_file.read_text(encoding="utf-8").splitlines() if line]


# -- the numbers ---------------------------------------------------------------------------------------
def _ratio(num: float, den: float) -> float | None:
    return None if den == 0 else round(num / den, 3)


def confusion(cases: dict[str, Case], status_of: dict[str, str]) -> dict[str, Any]:
    """Counts of the verdicts against the labels. Positive means SUSPICIOUS or worse.

    UNSCANNED and errors are counted apart. ``strict`` counts UNSCANNED as a flag, which is what
    a pipeline that fails on UNSCANNED sees.
    """

    cell = Counter()
    fp, fn, unscanned = [], [], []
    by_status: dict[str, Counter[str]] = defaultdict(Counter)
    for skill, status in status_of.items():
        case = cases.get(skill)
        if case is None or case.label == "invalid":
            continue
        by_status[case.label][status] += 1
        if status in {"UNSCANNED", "ERROR", "INVALID SKILL"}:
            cell[f"unscanned_{case.label}"] += 1
            unscanned.append(skill)
            continue
        flagged = status in POSITIVE
        if case.label == "malicious":
            cell["tp" if flagged else "fn"] += 1
            if not flagged:
                fn.append(skill)
        else:
            cell["fp" if flagged else "tn"] += 1
            if flagged:
                fp.append(skill)
    tp, fp_n, fn_n = cell["tp"], cell["fp"], cell["fn"]
    precision, recall = _ratio(tp, tp + fp_n), _ratio(tp, tp + fn_n)
    f1 = (
        None
        if not precision or not recall
        else round(2 * precision * recall / (precision + recall), 3)
    )
    strict_tp = tp + cell["unscanned_malicious"]
    strict_fp = fp_n + cell["unscanned_benign"]
    strict_p, strict_r = (
        _ratio(strict_tp, strict_tp + strict_fp),
        _ratio(strict_tp, strict_tp + fn_n),
    )
    return {
        "tp": tp,
        "fp": fp_n,
        "fn": fn_n,
        "tn": cell["tn"],
        "unscanned_benign": cell["unscanned_benign"],
        "unscanned_malicious": cell["unscanned_malicious"],
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "strict_precision": strict_p,
        "strict_recall": strict_r,
        "false_positives": sorted(fp),
        "false_negatives": sorted(fn),
        "unscanned": sorted(unscanned),
        "by_status": {label: dict(counts) for label, counts in by_status.items()},
    }


def contribution(
    cases: dict[str, Case], baseline: dict[str, str], model: dict[str, str]
) -> dict[str, Any]:
    """What the model changed against the deterministic checks alone, and whether it was right.

    The baseline is a scan with a model that reports nothing wrong. A move up the SAFE,
    SUSPICIOUS, MALICIOUS scale is right for a malicious skill and wrong for a benign one.
    """

    counts: Counter[str] = Counter()
    changes = []
    for skill, status in model.items():
        case, base = cases.get(skill), baseline.get(skill)
        if case is None or base is None or case.label == "invalid":
            continue
        if status not in RANK or base not in RANK:
            counts["not_comparable"] += 1  # UNSCANNED or an error on either side
            continue
        if status == base:
            counts["same"] += 1
            continue
        up = RANK[status] > RANK[base]
        right = up == (case.label == "malicious")
        counts[f"{'up' if up else 'down'}_{'right' if right else 'wrong'}"] += 1
        changes.append(
            {"skill": skill, "from": base, "to": status, "label": case.label, "right": right}
        )
    return {
        **{
            k: counts[k]
            for k in ("same", "up_right", "up_wrong", "down_right", "down_wrong", "not_comparable")
        },
        "changes": changes,
    }


def call_metrics(rows: list[dict[str, Any]]) -> dict[str, Any]:
    calls = [call for row in rows for call in row.get("calls", [])]
    first = [c for c in calls if c["first_attempt"] and c.get("status") == 200]
    quotes = sum(c.get("quotes", 0) for c in calls)
    walls = sorted(r["wall_s"] for r in rows if "wall_s" in r)
    return {
        "calls": len(calls),
        "valid_first_time": _ratio(sum(1 for c in first if c.get("valid")), len(first)),
        "invalid_replies": sum(1 for c in calls if c.get("status") == 200 and not c.get("valid")),
        "retries": sum(1 for c in calls if not c["first_attempt"]),
        "truncated": sum(1 for c in calls if c.get("truncated")),
        "timeouts": sum(1 for c in calls if c.get("timeout")),
        "rate_limited_429": sum(1 for c in calls if c.get("status") == 429),
        "other_errors": sum(1 for c in calls if c.get("status") not in (200, 429, None)),
        "quotes": quotes,
        "quote_found_rate": _ratio(sum(c.get("quotes_found", 0) for c in calls), quotes),
        "tokens_in": sum(c.get("tokens_in") or 0 for c in calls),
        "tokens_out": sum(c.get("tokens_out") or 0 for c in calls),
        "tokens_known": all(c.get("tokens_in") is not None for c in first) if first else None,
        "wall_mean_s": round(statistics.fmean(walls), 2) if walls else None,
        "wall_median_s": round(statistics.median(walls), 2) if walls else None,
        "wall_p95_s": round(walls[min(len(walls) - 1, int(0.95 * len(walls)))], 2)
        if walls
        else None,
        "wall_total_s": round(sum(walls), 1),
    }


def flips(rows: list[dict[str, Any]]) -> dict[str, Any]:
    """Skills whose status differed between repeats, among skills with at least two repeats."""

    seen: dict[str, list[str]] = defaultdict(list)
    for row in rows:
        seen[row["skill"]].append(row["status"])
    repeated = {skill: statuses for skill, statuses in seen.items() if len(statuses) >= 2}
    flipped = sorted(skill for skill, statuses in repeated.items() if len(set(statuses)) > 1)
    return {
        "skills_repeated": len(repeated),
        "flipped": len(flipped),
        "flip_rate": _ratio(len(flipped), len(repeated)),
        "flipped_skills": flipped,
    }


def summarize(cases: list[Case], rows: list[dict[str, Any]]) -> dict[str, Any]:
    by_id = {case.id: case for case in cases}
    targets = list(dict.fromkeys(row["target"] for row in rows))
    first_status = {
        target: {
            row["skill"]: row["status"]
            for row in rows
            if row["target"] == target and row["repeat"] == 1
        }
        for target in targets
    }
    baseline = first_status.get("baseline", {})
    out: dict[str, Any] = {"cases": {}, "targets": {}}
    out["cases"] = {
        f"{s}/{label}": n
        for (s, label), n in sorted(Counter((c.set, c.label) for c in cases).items())
    }
    for target in targets:
        target_rows = [r for r in rows if r["target"] == target]
        statuses = first_status[target]
        entry: dict[str, Any] = {
            "scanned": len(statuses),
            "confusion": confusion(by_id, statuses),
            "calls": call_metrics(target_rows),
            "flips": flips(target_rows),
        }
        subsets: dict[str, Any] = {}
        for decided in ("anchors", "model"):
            ids = {c.id for c in cases if c.decided_by == decided}
            subsets[decided] = confusion(by_id, {s: v for s, v in statuses.items() if s in ids})
        entry["by_decided_by"] = {
            k: {x: v[x] for x in ("tp", "fp", "fn", "tn", "recall", "precision")}
            for k, v in subsets.items()
        }
        sets = {}
        for set_name in sorted({c.set for c in cases}):
            ids = {c.id for c in cases if c.set == set_name}
            conf = confusion(by_id, {s: v for s, v in statuses.items() if s in ids})
            sets[set_name] = {
                x: conf[x]
                for x in ("tp", "fp", "fn", "tn", "unscanned_benign", "unscanned_malicious")
            }
        entry["by_set"] = sets
        if target != "baseline" and baseline:
            entry["contribution"] = contribution(by_id, baseline, statuses)
        entry["schema_failures"] = sorted(
            {
                r["skill"]
                for r in target_rows
                if any(c.get("status") == 200 and not c.get("valid") for c in r.get("calls", []))
            }
        )
        stopped = [
            r for r in target_rows if (r.get("provider_limit") or {}).get("kind") == "daily-quota"
        ]
        if stopped:
            entry["stopped_by_quota"] = stopped[0]["provider_limit"]["message"]
        out["targets"][target] = entry
    return out


# -- the report ---------------------------------------------------------------------------------------
def _fmt(value: Any) -> str:
    return "-" if value is None else (f"{value:.3f}" if isinstance(value, float) else str(value))


def markdown(
    summary: dict[str, Any], *, date: str, skipped: list[Target], sandbox: bool, repeats: int
) -> str:
    lines = [
        f"# Model matrix, {date}",
        "",
        f"Generated by `scripts/benchmark_models.py`. Sandbox: {'on' if sandbox else 'off (static checks and the model)'}. "
        f"Repeats per skill: {repeats}. The confusion matrix uses the first repeat; flips use all of them.",
        "",
        "## Skills",
        "",
        "| Set | Label | Skills |",
        "|:---|:---|--:|",
    ]
    for key, count in summary["cases"].items():
        set_name, label = key.split("/")
        lines.append(f"| {set_name} | {label} | {count} |")
    lines += [
        "",
        "Positive means SUSPICIOUS or MALICIOUS. A malicious skill that is flagged is a true positive; a benign one that is flagged is a false positive. "
        "UNSCANNED skills (the model or the sandbox could not finish) are counted apart and never as SAFE. `baseline` is a scan with a model that reports nothing: the deterministic checks alone.",
        "",
        "## Verdicts against the labels",
        "",
        "| Model | Scanned | TP | FP | FN | TN | Unscanned (benign / malicious) | Precision | Recall | F1 | Strict precision | Strict recall |",
        "|:---|--:|--:|--:|--:|--:|:--|--:|--:|--:|--:|--:|",
    ]
    for name, t in summary["targets"].items():
        c = t["confusion"]
        lines.append(
            f"| {name} | {t['scanned']} | {c['tp']} | {c['fp']} | {c['fn']} | {c['tn']} | {c['unscanned_benign']} / {c['unscanned_malicious']} "
            f"| {_fmt(c['precision'])} | {_fmt(c['recall'])} | {_fmt(c['f1'])} | {_fmt(c['strict_precision'])} | {_fmt(c['strict_recall'])} |"
        )
    lines += [
        "",
        "Strict counts UNSCANNED as a flag, which is what a pipeline that fails on UNSCANNED sees.",
        "",
    ]
    lines += [
        "## By set",
        "",
        "| Model | Set | TP | FP | FN | TN | Unscanned (benign / malicious) |",
        "|:---|:---|--:|--:|--:|--:|:--|",
    ]
    for name, t in summary["targets"].items():
        for set_name, s in t["by_set"].items():
            lines.append(
                f"| {name} | {set_name} | {s['tp']} | {s['fp']} | {s['fn']} | {s['tn']} | {s['unscanned_benign']} / {s['unscanned_malicious']} |"
            )
    lines += [
        "",
        "## Who should decide",
        "",
        "Skills labelled `anchors` should be decided by the deterministic checks alone; `model` ones need the intent read.",
        "",
        "| Model | Group | TP | FN | Recall | FP | TN |",
        "|:---|:---|--:|--:|--:|--:|--:|",
    ]
    for name, t in summary["targets"].items():
        for group, g in t["by_decided_by"].items():
            lines.append(
                f"| {name} | {group} | {g['tp']} | {g['fn']} | {_fmt(g['recall'])} | {g['fp']} | {g['tn']} |"
            )
    lines += ["", "## False positives and false negatives", ""]
    for name, t in summary["targets"].items():
        c = t["confusion"]
        lines += [
            f"**{name}**",
            "",
            f"- False positives ({len(c['false_positives'])}): {', '.join(c['false_positives']) or 'none'}",
            f"- False negatives ({len(c['false_negatives'])}): {', '.join(c['false_negatives']) or 'none'}",
            f"- Unscanned ({len(c['unscanned'])}): {', '.join(c['unscanned']) or 'none'}",
            "",
        ]
    lines += [
        "## What the model added",
        "",
        "Compared with the deterministic checks alone (`baseline`). A move up is right for a malicious skill and wrong for a benign one.",
        "",
        "| Model | Same | Up, right | Up, wrong | Down, right | Down, wrong | Not comparable |",
        "|:---|--:|--:|--:|--:|--:|--:|",
    ]
    for name, t in summary["targets"].items():
        if "contribution" in t:
            k = t["contribution"]
            lines.append(
                f"| {name} | {k['same']} | {k['up_right']} | {k['up_wrong']} | {k['down_right']} | {k['down_wrong']} | {k['not_comparable']} |"
            )
    for name, t in summary["targets"].items():
        for change in t.get("contribution", {}).get("changes", []):
            lines.append(
                f"- {name}: `{change['skill']}` {change['from']} -> {change['to']} ({change['label']}, {'right' if change['right'] else 'wrong'})"
            )
    lines += [
        "",
        "## Model behaviour",
        "",
        "| Model | Calls | Valid first time | Invalid | Retries | Truncated | Timeouts | 429 | Quote found | Tokens in / out | Wall mean / median / p95 | Flip rate |",
        "|:---|--:|--:|--:|--:|--:|--:|--:|--:|:--|:--|--:|",
    ]
    for name, t in summary["targets"].items():
        if name == "baseline":
            continue
        m, f = t["calls"], t["flips"]
        tokens = f"{m['tokens_in']} / {m['tokens_out']}" if m["tokens_known"] else "not reported"
        lines.append(
            f"| {name} | {m['calls']} | {_fmt(m['valid_first_time'])} | {m['invalid_replies']} | {m['retries']} | {m['truncated']} | {m['timeouts']} | {m['rate_limited_429']} "
            f"| {_fmt(m['quote_found_rate'])} ({m['quotes']}) | {tokens} | {_fmt(m['wall_mean_s'])} / {_fmt(m['wall_median_s'])} / {_fmt(m['wall_p95_s'])} s | {_fmt(f['flip_rate'])} ({f['flipped']}/{f['skills_repeated']}) |"
        )
    for name, t in summary["targets"].items():
        failed = t.get("schema_failures")
        if failed:
            lines.append(
                f"- {name} gave a reply that failed the schema on {len(failed)} skill(s): {', '.join(failed)}"
            )
    for name, t in summary["targets"].items():
        if t["flips"]["flipped_skills"]:
            lines.append(f"- {name} flipped: {', '.join(t['flips']['flipped_skills'])}")
        if "stopped_by_quota" in t:
            lines.append(f"- {name} stopped by a quota: {t['stopped_by_quota']}")
    if skipped:
        lines += ["", "## Not run", ""] + [f"- `{t.name}`: {t.skipped}" for t in skipped]
    lines += [
        "",
        "## How to read this",
        "",
        "- Quote found is the share of the model's quoted evidence that exists in the skill (after the same whitespace and case folding the analyzer uses). The analyzer drops quotes that do not, so this is how much the model invented.",
        "- A flip is a skill whose status differed between repeats at temperature 0; remaining differences come from the server, not from sampling.",
        "- The sandbox is off unless stated, so a skill that only the sandbox can catch counts as a false negative here.",
        "",
    ]
    return "\n".join(lines)


# -- main ------------------------------------------------------------------------------------------
def run(args: argparse.Namespace) -> int:
    from skill_sentry_cli.core.cache import SQLiteStore
    from skill_sentry_cli.core.config import SkillsEntryConfig
    from skill_sentry_cli.core.engine import ScanEngine

    cases = load_cases()
    if args.only:
        cases = [c for c in cases if c.id in set(args.only)]
    if args.sets:
        cases = [c for c in cases if c.set in set(args.sets)]
    if args.limit_skills:
        cases = cases[: args.limit_skills]
    out_dir = args.out / args.date
    out_dir.mkdir(parents=True, exist_ok=True)
    rows_file = out_dir / "rows.jsonl"
    done = done_keys(rows_file)

    targets = [
        resolve_target(
            spec,
            base_url=args.base_url,
            key_env=args.key_env,
            allow_large=args.allow_large,
            ollama_url=args.ollama_url,
        )
        for spec in args.model
    ]
    skipped = [t for t in targets if t.skipped]
    for target in skipped:
        print(f"skipped {target.name}: {target.skipped}", flush=True)
    runnable = [t for t in targets if not t.skipped]
    exit_code = 0
    stopped: dict[str, str] = {}

    with tempfile.TemporaryDirectory(
        prefix="skillsentry-bench-", ignore_cleanup_errors=True
    ) as tmp:
        work = Path(tmp)
        os.environ["HOME"] = str(work / "home")
        os.environ["USERPROFILE"] = str(work / "home")
        (work / "home").mkdir()
        folders = materialise(cases, work)
        store = SQLiteStore(work / "bench.sqlite")
        config = SkillsEntryConfig.model_validate({"sandbox": {"enabled": args.sandbox}})

        baseline = ScanEngine(config, store=store, model=NullModel())
        for case in cases:
            if ("baseline", case.id, 1) in done:
                continue
            row = scan_row(baseline, case, folders[case.id], None, sandbox=args.sandbox)
            append_row(rows_file, {"target": "baseline", "repeat": 1, **row})
        print(f"baseline: {len(cases)} skills", flush=True)

        for target in runnable:
            print(
                f"privacy: skill content goes to {target.provider} ({target.model})"
                if target.provider != "ollama"
                else f"model: {target.name} on this machine",
                flush=True,
            )
            meter = Meter()
            try:
                client, target_config = build_client(target, meter)
            except Exception as exc:  # the model is not usable: say so, keep going
                print(f"skipped {target.name}: {str(exc)[:200]}", flush=True)
                target.skipped = str(exc)[:200]
                skipped.append(target)
                continue
            engine = ScanEngine(target_config, store=store, model=client)
            stop = False
            for repeat in range(1, args.repeat + 1):
                for case in cases:
                    if (target.name, case.id, repeat) in done or stop:
                        continue
                    row = scan_row(engine, case, folders[case.id], meter, sandbox=args.sandbox)
                    limit = row.get("provider_limit") or {}
                    if limit:
                        # The provider's limits cut this scan short, so it is not a result for
                        # the model. Leave it out, so a later run does it again.
                        print(f"stopped {target.name}: {limit.get('message')}", flush=True)
                        if limit.get("kind") == "daily-quota":
                            stop, exit_code = True, 4
                            stopped[target.name] = limit.get("message", "")
                        continue
                    append_row(rows_file, {"target": target.name, "repeat": repeat, **row})
                    print(
                        f"{target.name:34} #{repeat} {case.id:34} {row['status']:14} {row['wall_s']}s",
                        flush=True,
                    )
            with contextlib.suppress(Exception):
                client.close()
        # Windows will not delete a database file that is still open.
        with contextlib.suppress(Exception):
            store.close()

    rows = read_rows(rows_file)
    summary = summarize(cases, [r for r in rows if r["skill"] in {c.id for c in cases}])
    summary["date"], summary["sandbox"], summary["repeats"] = args.date, args.sandbox, args.repeat
    summary["not_run"] = {t.name: t.skipped for t in skipped}
    for name, message in stopped.items():
        if name in summary["targets"]:
            summary["targets"][name]["stopped_by_quota"] = message
    (out_dir / "summary.json").write_text(
        json.dumps(summary, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )
    (out_dir / "matrix.md").write_text(
        markdown(
            summary, date=args.date, skipped=skipped, sandbox=args.sandbox, repeats=args.repeat
        ),
        encoding="utf-8",
    )
    print(f"wrote {out_dir}/matrix.md, summary.json, rows.jsonl")
    return exit_code


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument(
        "--model",
        action="append",
        default=[],
        metavar="PROVIDER=MODEL",
        help="repeatable; default: the two small local models",
    )
    parser.add_argument(
        "--base-url", help="address of an OpenAI-compatible server (provider openai)"
    )
    parser.add_argument(
        "--key-env",
        default="OPENAI_API_KEY",
        help="environment variable that holds the key for provider openai",
    )
    parser.add_argument("--ollama-url", default="http://localhost:11434")
    parser.add_argument(
        "--allow-large", action="store_true", help="allow a local model larger than 4 GB"
    )
    parser.add_argument(
        "--repeat",
        type=int,
        default=3,
        help="scans per skill and model (flip rate needs 2 or more)",
    )
    parser.add_argument("--sandbox", action="store_true", help="run the Docker sandbox as well")
    parser.add_argument("--only", nargs="*", help="run only these skill ids")
    parser.add_argument(
        "--sets", nargs="*", help="run only these sets (corpus, evasion, benign-new, malicious-new)"
    )
    parser.add_argument(
        "--limit-skills", type=int, help="run only the first N skills (a smoke test)"
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--date", default=dt.date.today().isoformat())
    args = parser.parse_args(argv)
    if not args.model:
        args.model = ["ollama=gemma3:1b", "ollama=qwen2.5-coder:1.5b"]
    return run(args)


if __name__ == "__main__":
    raise SystemExit(main())
