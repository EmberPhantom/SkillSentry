# 10 · Developer Guide

> Environment setup, repository layout, integration workflow, coding standards, extension guides, and the roadmap. Written for the 3-developer core team — Dev 1 (Backend + AI Integration) · Dev 2 (Backend — Skill Analysis) · Dev 3 (Frontend) — and future contributors. Roles & workload: [11-team-and-workload.md](11-team-and-workload.md).

---

## 10.1 Environment Setup

```bash
# 1. Prereqs: Python 3.11+, Docker, Node 20+, Ollama
ollama pull gemma4:e4b-it-qat                 # local model (~night-before for demos)

# 2. Backend
git clone https://github.com/<org>/skillsentry && cd skillsentry
python -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"                   # ruff, pytest, etc.
skill-sentry init                          # skillsentry.toml with defaults

# 3. Frontend (ui/)
cd ui && npm install && npm run dev       # Vite dev server → proxies to :8000

# 4. Parallel development without the real API
python -m skill_sentry.server.demo_mode --port 8000   # mock server, canned verdicts
```

**Verify your setup:** `skill-sentry scan fixtures/benign/pdf-summarizer` → SAFE; `skill-sentry scan fixtures/malicious/cloud-sync-pro` → MALICIOUS with Poisoned Well correlation.

## 10.2 Repository Structure & Ownership

Full annotated tree: [02-architecture.md](02-architecture.md) §2.6. **Authoritative ownership: [11-team-and-workload.md](11-team-and-workload.md)** — summary:

| Area | Owner | Modules |
|:---|:---|:---|
| **Dev 1 · Backend + AI Integration** | Sandbox, deception, models, verdict/reports, server | `core/sandbox/`, `core/poisoned_well/`, `core/evasion/`, `core/models/` (Ollama + Gemini clients), `core/verdict/` (fusion, SARIF), `server/`, `cli.py`, `skill/`, fixtures `cloud-sync-pro` + `slack-notif-mal` |
| **Dev 2 · Backend (Skill Analysis)** | Malicious-instruction detection | `core/parser/` (spec validator, typosquat), `core/semantic/` (AST anchors, analyzer, prompts), `core/vision/`, `core/cache/`, fixtures (4 benign + `invoice-helper` + `g1t-translate`), eval harness |
| **Dev 3 · Frontend (only)** | UI + demo assets | `ui/` (app shell, triage table, live console WS, IOC graph React Flow, Gemma's Eye View viewer, `--demo-mode` UI integration), README GIF, backup demo video |

## 10.3 Workload Assignment & Milestones

See **[11-team-and-workload.md](11-team-and-workload.md)** for the full work breakdown: work packages per developer, milestones **M0–M5** with entry/exit criteria, stage-level RACI, interface contracts I1–I5, definitions of done, and swing tasks for rebalancing. (This replaces the plan's original hour-by-hour 3-dev division.)

## 10.4 Integration Contracts & Workflow Rules

Full interface spec (I1–I5) with producers, consumers, and delivery milestones: [11-team-and-workload.md](11-team-and-workload.md) §11.6.

| Contract | Producer | Consumer | Format |
|:---|:---|:---|:---|
| `POST /scan` → `scan_id` | Dev 1 (server) | Dev 3 | JSON |
| `WS /scan/{id}/stream` | Dev 1 (server) | Dev 3 LiveConsole | `{stage, skill, event, ts}` |
| Verdict object | Dev 1 (verdict engine) | Dev 3 triage table | JSON schema v1 (frozen at M0) |
| SARIF report file | Dev 1 (verdict engine) | Dev 3 export button | SARIF 2.1.0-style |
| Model client (I2) + mock Ollama | Dev 1 | Dev 2 (semantic/vision) | Typed protocol + canned JSON |
| `StageResult` (I3) | Dev 2 (analysis stages) | Dev 1 (orchestrator) | Shared dataclass |
| Demo canned payloads (I4) | Dev 2 (from fixtures) | Dev 1 `demo_mode` → Dev 3 | Schema-identical JSON |

**Rules that prevent merge hell:**

1. Dev 3 builds against Dev 1's **mock server** (`demo_mode`) returning canned Verdict JSON until the real API is ready; switch is base-URL only.
2. The verdict schema **freezes at M0 exit** and does not change — backward-compatible additions only, ever.
3. Stage identifiers, WS event names, and severity enums are shared constants (single source of truth module) — no stringly-typed duplicates.
4. Cross-cutting changes (schema, weights, stage list) require sign-off from all three devs in the PR description.
5. Every interface ships with its mock before its real implementation; contract tests validate producer **and** consumer sides in CI.

## 10.5 Build Plan (Milestones)

Work is organized as milestones **M0–M5** with entry/exit criteria instead of fixed hours — full breakdown per developer in [11-team-and-workload.md](11-team-and-workload.md) §11.4.

| Milestone | Theme | Exit gate (abridged) |
|:---|:---|:---|
| **M0** | Contracts & scaffold | Verdict v1 frozen; mock server streaming canned WS; all devs unblocked |
| **M1** | Sandbox base + deterministic analysis | Benign fixture runs clean in sandbox; anchors + semantic emit valid JSON; cache < 2 s |
| **M2** | Deception, vision, live pipeline | Poisoned Well confirms on `cloud-sync-pro`; evasion auto-fails `slack-notif-mal`; vision flags `invoice-helper` |
| **M3** | Verdict, reports, E2E | Eval sheet targets met; SARIF validates; STIX export works |
| **M4** | Hardening & rehearsal | Chaos Run ×2 clean; demo script runs 3× back-to-back |
| **M5** | Stabilization (Phase 1) | pip/Docker packaging, 20-skill corpus, precision/recall published |

**Scope rule (hard):** the sandbox stays simple — no syscall tracing, no real signing until Phase 2.

## 10.6 Coding Standards — Spec (proposed)

| Area | Standard |
|:---|:---|
| Python | 3.11+, type hints everywhere, `ruff check` + `ruff format`, docstrings on public functions |
| TypeScript | `strict: true`, ESLint + Prettier, no `any` in contract types (generated from the frozen schema) |
| Tests | pytest (backend) colocated under `tests/`; Vitest + React Testing Library (UI); contract tests validate real API **and** mock server |
| Commits | Conventional commits (`feat:`, `fix:`, `docs:`, `test:`); PRs require one review + green CI |
| Secrets | Never commit canary *formats* that resemble real keys beyond the documented fake patterns; `GEMINI_API_KEY` via env only; pre-commit secret scan |
| Docs | Public behavior changes ship with doc updates in the same PR |

## 10.7 Extension Guides

### Add a new pipeline stage

1. Create `core/<stage>/` with a single entry point `run(context: ScanContext) -> StageResult`.
2. Register the stage identifier in the shared constants module (WS events, DB CHECK constraint, findings `stage` enum) + add a DB migration if the CHECK changes.
3. Emit WS events (`started/progress/finding/completed`) — the LiveConsole renders unknown stages generically.
4. Add a fusion weight in `verdict/fusion.py` (weights are config; renormalization is automatic) **or** document it as an override signal.
5. Add unit tests + at least one fixture that exercises the stage; update `tests/expected_verdicts.json`.

### Add a new fixture

1. Place under `fixtures/benign/` or `fixtures/malicious/` following the existing structure (`SKILL.md` + scripts/assets).
2. Obey the fixture safety rules ([08-testing-and-evaluation.md](08-testing-and-evaluation.md) §8.2): fictional C2 domains only, no real secrets, README warning for malicious ones.
3. Hand-annotate ground-truth lines; add the expected verdict/risk band to the eval run sheet and `expected_verdicts.json`.

### Add a new context-aware canary intent

1. Add the intent keyword match + canary generator in `sandbox/context_honeypot.py` / `poisoned_well/canary_gen.py` (marker must embed `SKS-<8hex>` so correlation works unchanged).
2. Extend the `contextAwareCanary` enum in the verdict contract (backward-compatible addition) and the DB CHECK constraint via migration.
3. Add a fixture whose `declared_intent` triggers it; verify the UI context banner shows the intent → canary mapping.

## 10.8 Debugging Tips

| Symptom | First moves |
|:---|:---|
| Semantic stage empty/odd JSON | Check Ollama up (`GET /health`); inspect the anchored prompt (logged at debug); retry once is automatic — parse failure ⇒ `semantic-unavailable` finding |
| No canary events | Confirm sandbox enabled, inotify mounted, skill actually reads a seeded path; check `canary_events` table for `canary_seeded` rows |
| Sinkhole misses DNS | Fallback per plan: hosts-file override + `resolv.conf` pinning inside the container |
| Evasion fixture passes | Masquerade not applied? Verify `/dev/null:/.dockerenv:ro` mount and `LD_PRELOAD` env in the container spec |
| UI shows stale verdicts | Query cache keys: engine/model version bump invalidates; `skill-sentry cache stats` |
| Demo jeopardy | `--demo-mode` is always the answer (Chaos Run doctrine) |

## 10.9 Risks & Mitigations (plan §13)

| Risk | Likelihood | Mitigation |
|:---|:---|:---|
| Local E4B too slow on venue laptops | Medium | Q4 quantize; downscale images; cloud fallback wired from M1; pre-cache model night before |
| Sandbox DNS interception flaky | Medium | Test sinkhole early in M1; fallback = hosts-file override + `resolv.conf` pinning |
| Gemma vision misses subtle payload | Medium | Fixture payload tuned to be catchable (4 px → 6 px if needed); rehearse with exact model |
| Demo Wi-Fi dies | High | Everything runs offline; `--demo-mode` canned responses; backup video recorded during M4 |
| Scope creep into "full security product" | High | Hard rule: sandbox stays simple. No syscall tracing, no real signing before Phase 2 |
| Frontend/backend contract drift | Medium | Verdict JSON schema frozen at M0; mock server for Dev 3 until API ready |
| Poisoned Well false-trigger on benign skill | Low | Benign fixtures never touch canary paths; correlation requires marker-in-outbound-traffic |
| LLM hallucination (false positive) | Medium | Deterministic AST Anchors provide hard ground-truth; LLM cannot contradict them |
| Sandbox evasion by malware | Medium | Masquerade layer hides Docker artifacts; probing triggers auto-fail |
| Docker daemon crash during demo | Medium | Chaos Run (M4) tests this; UI shows graceful error state |

## 10.10 Roadmap

| Phase | Window | Highlights |
|:---|:---|:---|
| **0 — Core Build (M0–M4)** | milestone-based | Full pipeline, 7+1 fixtures, dashboard, Chaos Run, rehearsed demo |
| **1 — Stabilization (M5)** | after M4 | Pytest suite (parser, typosquat, fusion weights, cache); fixture regression; CI; `pip install skill-sentry`; published Docker image; `scan --watch`; `skill-sentry init`; model auto-download helper; CLI progress bars; 20-skill eval corpus + precision/recall; docs deep-dives |
| **2 — Production** | after M5 | MCP runtime proxy; signed verdicts (sigstore/cosign); community IOC feed; OpenTelemetry; Postgres team server; MCP server manifest scanning |

## 10.11 Compliance Checklist (judges will verify)

- ☐ Public GitHub repo + MIT LICENSE
- ☐ Gemma 4 load-bearing: **"Powered by Gemma 4 · open weights"** in UI header + README
- ☐ SkillSentry ships its own spec-compliant `SKILL.md` (name, description 1–1024 chars with trigger keywords, bundled scripts)
- ☐ Original harness called out in README: *"The sandbox runner, canary filesystem, DNS sinkhole, context-aware honeypot system, sandbox evasion detector, and Poisoned Well correlation engine are original code"*
- ☐ README order: 30-sec GIF → threat model → architecture diagram → how-to-run → eval table
- ☐ Backup demo video (unlisted YouTube) in submission
- ☐ Honest prior-art citations: Snyk ToxicSkills audit, Pipelock, AIR Security, MCP prompt-injection research
- ☐ Supply Chain Threat Model diagram included in README

---

*See also: [CHANGELOG.md](CHANGELOG.md).*
