#!/usr/bin/env python
"""Capture raw evidence of a live Ollama run. Never fabricates: any failure is recorded
and the script exits non-zero. Output: docs/evidence/live-ollama-<UTC date>.md (+ raw files)."""
from __future__ import annotations
import datetime as dt, hashlib, json, os, pathlib, platform, re, subprocess, sys

ROOT = pathlib.Path(__file__).resolve().parents[1]
OUT = ROOT / "docs" / "evidence"
MODEL = os.environ.get("SKILLSENTRY_MODEL_NAME", "gemma4:e4b")
BENIGN = os.environ.get("EVID_BENIGN", "fixtures/benign/pdf-summarizer")
MALICIOUS = os.environ.get("EVID_MALICIOUS", "fixtures/malicious/cloud-sync-pro")
PY = sys.executable
# Check `skillsentry scan --help` and adjust SCAN_FLAGS to flags that exist in this build.
SCAN_FLAGS = ["--format", "json", "--no-cache", "--no-sandbox"]


def redact(text: str) -> str:
    for p in {str(ROOT), str(ROOT).replace("\\", "\\\\"), str(pathlib.Path.home()),
              str(pathlib.Path.home()).replace("\\", "\\\\")}:
        text = text.replace(p, "<path>")
    return re.sub(r"[A-Za-z]:\\{1,2}[^\s\"']*", "<path>", text)


def run(cmd, timeout=900):
    try:
        p = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, timeout=timeout)
        return p.returncode, redact(p.stdout), redact(p.stderr)
    except Exception as exc:  # recorded, never hidden
        return 255, "", redact(f"{type(exc).__name__}: {exc}")


def find_keys(obj, keys, found=None):
    found = {} if found is None else found
    if isinstance(obj, dict):
        for k, v in obj.items():
            if k in keys:
                found.setdefault(k, []).append(v)
            find_keys(v, keys, found)
    elif isinstance(obj, list):
        for v in obj:
            find_keys(v, keys, found)
    return found


def main() -> int:
    OUT.mkdir(parents=True, exist_ok=True)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d")
    steps, problems = [], []

    def step(name, cmd, save=None):
        code, out, err = run(cmd)
        steps.append((name, cmd, code, out, err))
        if save:
            (OUT / save).write_text(out, encoding="utf-8")
        if code != 0:
            problems.append(f"{name}: exit {code}")
        return code, out

    _, ollama_list = step("ollama list", ["ollama", "list"])
    step(f"ollama show {MODEL}", ["ollama", "show", MODEL])
    step("skillsentry doctor", [PY, "-m", "skillsentry.cli", "doctor"])

    list_id = None
    for line in ollama_list.splitlines():
        parts = line.split()
        if parts and parts[0] == MODEL and len(parts) > 1:
            list_id = parts[1]
    if not list_id:
        problems.append(f"{MODEL} not found in `ollama list`")

    scans = {}
    for label, path in (("benign", BENIGN), ("malicious", MALICIOUS)):
        if not (ROOT / path).exists():
            problems.append(f"fixture missing: {path}")
            continue
        code, out = step(f"scan {label}", [PY, "-m", "skillsentry.cli", "scan", path, *SCAN_FLAGS],
                         save=f"live-scan-{label}-{stamp}.json")
        try:
            scans[label] = json.loads(out)
        except Exception:
            problems.append(f"scan {label}: stdout is not JSON")

    claim_ok = True
    facts = {}
    for label, data in scans.items():
        keys = find_keys(data, {"eval_count", "prompt_eval_count", "digest", "model_digest", "backend", "model_backend"})
        facts[label] = keys
        ev = [v for v in keys.get("eval_count", []) if isinstance(v, (int, float))]
        if not ev or sum(ev) <= 0:
            claim_ok = False
            problems.append(f"{label}: no eval_count > 0 in report (telemetry missing or model not called)")
        digests = [str(v) for k in ("digest", "model_digest") for v in keys.get(k, [])]
        if list_id and not any(d.replace("sha256:", "").startswith(list_id) for d in digests):
            claim_ok = False
            problems.append(f"{label}: report digest does not match `ollama list` id {list_id}")
        backends = [str(v) for k in ("backend", "model_backend") for v in keys.get(k, [])]
        if "ollama" not in backends:
            claim_ok = False
            problems.append(f"{label}: backend 'ollama' not recorded in report")
    if len(scans) < 2:
        claim_ok = False
    claim_ok = claim_ok and not problems

    lines = [f"# Live Ollama evidence ({stamp})", "",
             f"- LIVE_CLAIM_ALLOWED: **{str(claim_ok).lower()}**",
             f"- Commit: `{run(['git', 'rev-parse', 'HEAD'])[1].strip()}`",
             f"- Platform: {platform.platform()} / Python {platform.python_version()}",
             f"- Model requested: `{MODEL}`; id from `ollama list`: `{list_id}`", ""]
    if problems:
        lines += ["## Problems", *[f"- {p}" for p in problems], ""]
    lines += ["## Extracted telemetry (from the scan JSON reports)", "```json",
              json.dumps(facts, indent=2, default=str), "```", ""]
    for name, cmd, code, out, err in steps:
        lines += [f"## `{' '.join(cmd[:1] + cmd[1:])}`".replace(PY, "python"), f"exit code: {code}", "```text",
                  "\n".join(out.splitlines()[:120]), "```"]
        if err.strip():
            lines += ["stderr:", "```text", "\n".join(err.splitlines()[:40]), "```"]
        lines.append("")
    lines += ["## Raw files (sha256)"]
    for f in sorted(OUT.glob(f"live-scan-*-{stamp}.json")):
        lines.append(f"- `{f.name}`: `{hashlib.sha256(f.read_bytes()).hexdigest()}`")
    report = OUT / f"live-ollama-{stamp}.md"
    report.write_text("\n".join(lines) + "\n", encoding="utf-8")
    print(f"wrote {report.relative_to(ROOT)}; LIVE_CLAIM_ALLOWED={claim_ok}")
    return 0 if claim_ok else 3


if __name__ == "__main__":
    raise SystemExit(main())

