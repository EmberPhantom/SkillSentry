# 15 · Version 1 test results (measured)

Every number here was measured on the development machine on 2026-10-30, with the commands shown. Nothing is a target. Results that need the real model are marked **pending** and are run on the test machine with `scripts/acceptance.sh --e2e`.

## Unit and contract tests

```text
.venv\Scripts\python -m pytest tests -q
438 passed, 5 skipped
```

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
- SARIF validation against the official 2.1.0 schema.
- A chaos run (Docker, model and timeout failures during a batch).
