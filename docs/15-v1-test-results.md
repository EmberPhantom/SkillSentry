# 15 · Version 1 test results (measured)

Every number here was measured on the development machine on 2026-10-30, with the commands shown. Nothing is a target. Results that need the real model are marked **pending** and are run on the test machine with `scripts/acceptance.sh --e2e`.

## Unit and contract tests

```text
.venv\Scripts\python -m pytest tests -q
480 passed, 5 skipped
```

`scripts/check.sh` (ruff lint and format on `skillsentry tests scripts`, pytest, schema drift, demo smoke) passes on the same commit.

SARIF output is checked against the official 2.1.0 schema (vendored at `tests/fixtures/sarif/sarif-schema-2.1.0.json`) in `tests/unit/test_sarif_schema.py`: both a finding case and an empty case validate with zero errors.

The skips are the real-Laya tests (the `laya` extra is not installed) and two Windows-only checks (reserved device names cannot be created on Windows).

## Static detection (labelled decision corpus)

`tests/fixtures/decisions/labels.json`, 18 malicious and 20 benign cases. `invoice-helper` is vision-only and excluded from the static count.

| Measure | Result | Floor (test) |
|:---|:---|:---|
| Malicious flagged (critical or high anchor) | 17 of 18 | 17 |
| Benign flagged | 0 of 20 | 0 |

Citation accuracy on the hand-annotated malicious lines of `cloud-sync-pro` and `slack-notif-mal`: 5 of 5, within one line (`tests/ground_truth/anchor_citations.json`). Floor 80%.

## Sandbox (Docker Desktop 29.9.2, demo model)

These runs test the sandbox and fusion path only. The model was the deterministic demo model, so they say nothing about the real model's accuracy.

```text
.venv\Scripts\python scripts\e2e_fixtures.py --model-backend demo --repeat 10
E2E PASS (40/40 across 10 run(s))

.venv\Scripts\python scripts\e2e_fixtures.py --model-backend demo --repeat 3
E2E PASS (12/12 across 3 run(s))
```

| Skill | Verdict | Risk (all 10 runs) | Expected |
|:---|:---|:---|:---|
| cloud-sync-pro | MALICIOUS | 95 | MALICIOUS, at least 91 |
| slack-notif-mal | MALICIOUS | 100 | MALICIOUS, at least 100 (evasion) |
| git-helper | SAFE | 8 | SAFE |
| pdf-summarizer | SAFE | 0 | SAFE |

Each skill gave the same verdict and score on every run, and no stage degraded. Earlier runs before the evasion-floor fix scored `slack-notif-mal` at 95; that is the regression the fix closed.

## Real model (Gemma 4 E4B, Ollama)

**Pending.** The model is installed and verified (`gemma4:e4b-it-qat`, digest `ee6656371218…`), but it does not load on the development machine: the Ollama runner fails with an out-of-memory error at startup. Latency, accuracy on the real skills and the fixture E2E with the real model are measured on the test machine.

## Packaging

| Check | Result |
|:---|:---|
| Wheel builds with the dashboard inside | yes |
| Fresh-venv install, `skillsentry --version` | 2.0.0 |
| Server image builds, serves dashboard and API, runs as UID 10001 | yes |
| `skillsentry doctor` on the development machine | ready for a full scan |

## Not measured yet

- Cached and uncached scan latency with the real model (targets: under 2 s and under 90 s).
- Accuracy of the real model on real skills (`scripts/batch_skills.py`).
- Chaos at the engine level is measured in `tests/unit/test_chaos.py` (7 tests): Docker unavailable, sandbox error and unexpected runner exception mid-batch; sandbox timeout; model outage mid-batch; storage failure at persist (no verdict, no cache entry); CLI batch continuing after one skill fails (exit 3).
- Not measured: a real Docker-daemon outage during a batch, a real model timeout, and disk-full on the real cache file. The unit tests inject these failures; they do not produce them.

## Test-machine checklist (real model and real skills)

Run in this order on the machine with Ollama, Docker and the real skills. Record each number in this file as measured.

1. `ollama pull gemma4:e4b-it-qat`, then `skillsentry doctor`. It must print `ready for a full scan`.
2. `scripts\check.sh` (or `bash scripts/check.sh`). Must pass.
3. `skillsentry sandbox build`, then `scripts/e2e_fixtures.py --repeat 3` with the real model (not `--model-backend demo`). Record the verdict, risk and latency per skill.
4. `scripts/acceptance.sh --e2e <skills-dir>`, with the 66 unique local skills from a scratch copy. Record crashes, degraded stages, time per skill and peak memory.
5. Triage every non-SAFE result by hand (`docs/08`). Record false positives with the reason.
6. Latency: cached scan (target under 2 s) and uncached scan (target under 90 s). Record the measured numbers, and the cause and fallback if a target is missed.
