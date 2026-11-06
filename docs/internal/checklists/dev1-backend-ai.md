# Dev 1 · Backend + AI Integration — Work Checklists

> **Owner:** Dev 1 (project initiator) · **Scope:** sandbox for skill testing, Poisoned Well deception, evasion detection, model plumbing, verdict fusion + **report generation**, API server/orchestrator.
>
> **Personal sequence (decision D4):** contracts/mock (small, unblocks Dev 3) → **sandbox first** → deception → model plumbing → **report generation** → server E2E.
>
> Spec homes: [02-architecture](../../developer/architecture.md) · [03-database](../../developer/database.md) · [04-security](../../developer/security.md) · [05-api-reference](../../reference/api.md)

---

## CL-D1-0 · Onboarding & Environment

*Depends on: — (start immediately)*

- [ ] Read [01-overview](../../user/overview.md), [02-architecture](../../developer/architecture.md) (pipeline + scoring), [04-security](../../developer/security.md) (§4.4–4.6 — you own the trust boundary), [11-team](../11-team-and-workload.md)
- [ ] Environment per [10-developer-guide §10.1](../../developer/getting-started.md): Python 3.11+ venv, Docker daemon, Node 20 (for testing against Dev 3's UI)
- [ ] `ollama pull gemma4:e4b-it-qat`; run one text + one image inference; **record baseline latency** (risk: E4B too slow — mitigation decision needed by end of M1)
- [ ] Create repo scaffold branches: `feat/contracts`, `feat/sandbox`, `feat/models`
- [ ] Wire CI badge + `pyproject.toml` skeleton so Dev 2/Dev 3 can `pip install -e .` from day one

**Done means:** repo installable in dev mode; model latency numbers written into [08-testing §8.4](../../developer/testing.md) notes.

---

## CL-D1-1 · Contracts, Mock Server & Scaffold (M0 · W1.0)

*Depends on: CL-D1-0 · **Blocks: Dev 3's entire workflow, Dev 2's StageResult shape***

- [ ] `skillsentry/core/contracts.py` — single source of truth: stage identifiers (`cache, spec, typosquat, deterministicAnchor, semantic, vision, sandbox, poisonedWell, evasion, verdict`), WS event names, severity enums, verdict enums ([05-api §5.4–5.5](../../reference/api.md))
- [ ] Pydantic models for **Verdict JSON Contract v1** — exact field names/types from [05-api §5.5](../../reference/api.md); export JSON Schema for Dev 3's type generation
- [ ] Pydantic model for `StageResult` (I3): `{stage, findings[], signals{normalized 0–100}, telemetry?}` — agreed with Dev 2 before they build stages
- [ ] `server/demo_mode.py`: serves every endpoint of [05-api §5.2](../../reference/api.md) from canned JSON (7-fixture store); WS replay with realistic timing + ≤ 2 s heartbeat; `DEMO DATA` flag in `GET /meta`
- [ ] WS message schema `{stage, skill, event, ts, detail?}` + event catalog minimum set ([05-api §5.3](../../reference/api.md))
- [ ] CI skeleton per [08-testing §8.8](../../developer/testing.md): lint (ruff), unit, **contract tests against mock server**
- [ ] Announce freeze: tag `contract-v1`, post in team channel — additions-only from here (rule I1)
- [ ] Hand off to Dev 3: mock URL + example fetch/WS snippet; verify their shell renders your canned triage rows

**Done means:** M0 exit gate — Dev 3 building against mock; Dev 2 coding to `StageResult`; contract tests green in CI.

---

## CL-D1-2 · Sandbox Core (M1 · W1.1) — *your first big block*

*Depends on: CL-D1-1 (contracts) · Blocks: CL-D1-4, Dev 2's E2E confidence*

- [ ] `sandbox/runner.py` — Docker SDK lifecycle per [04-security §4.5](../../developer/security.md) reference invocation: `python:3.11-slim`, non-root (`65534`), `no-new-privileges`, `cap-drop ALL`, `--read-only` + tmpfs `/tmp`, skill mounted **read-only**
- [ ] Resource enforcement: 512 MB RAM, 1 CPU, `--pids-limit 128`, **60 s watchdog kill** (thread + container stop + remove)
- [ ] Guaranteed teardown: try/finally + signal handlers + startup cleanup of stale `label=skillsentry` containers/networks
- [ ] Sinkhole-only Docker network: **no NAT to internet**; verify with in-container `curl 1.1.1.1` → must fail (automated test)
- [ ] `sandbox/masquerade.py`: `-v /dev/null:/.dockerenv:ro`, `LD_PRELOAD=/opt/masquerade.so` shim, and shim-based `/proc/{1,self}/cgroup` + `mountinfo` redirection (Docker 29 rejects `/proc` bind mounts)
- [ ] Masquerade verification test: inside container, `/.dockerenv` empty, `/proc/1/cgroup` shows faked content, `docker`/`container` strings absent from `/proc/self/mountinfo`
- [ ] `sandbox/canary_fs.py`: seed `~/.aws/credentials`, `~/.ssh/id_rsa` (fake PEM w/ marker comment), `~/.env`, `~/.config/gh/hosts.yml` — realistic modes (600/644), unique marker `SKS-<8hex>` per scan via `secrets.token_hex(4)`
- [ ] `sandbox/context_honeypot.py`: `declared_intent` (from Dev 2's I3 field) → canary set mapping per [02-arch §2.3](../../developer/architecture.md) table (AWS/GitHub/Slack/SSH/Generic); env-var injection (`SLACK_BOT_TOKEN` etc.); agree keyword normalization with Dev 2
- [ ] `sandbox/monitor.py`: watchdog/inotify on canary paths + probe paths; event records `{ts, path, process, event_type}` staged for `canary_events` table
- [ ] Sandbox emits `StageResult` (stage=`sandbox`) + raw telemetry stream to orchestrator bus
- [ ] Unit + integration tests: limits enforced; teardown on timeout/kill/crash; inotify fires on read; **benign fixture executes with zero canary/probe events** (M1 exit gate)

**Done means:** `skillsentry scan fixtures/benign/pdf-summarizer` runs sandboxed, clean, torn down; masquerade verified by test; sandbox telemetry flowing as `StageResult`.

---

## CL-D1-3 · Model Plumbing — interface I2 (M1 · W1.2)

*Depends on: CL-D1-0 (latency baseline) · **Blocks: Dev 2 semantic (W2.3) and vision (W2.4) against real model** — ship `MockGemma` FIRST*

- [ ] Define I2 protocol (typed): `generate_json(system, user, schema, retries=1) -> dict` · `analyze_image(path, prompt) -> {ocr, bboxes[], findings[]}` · `.model_version` property (for cache invalidation)
- [ ] `MockGemma` implementing I2 with canned, schema-valid responses (deceptive + benign variants) — **merge before real client** so Dev 2 is never blocked
- [ ] `models/gemma_local.py`: Ollama client (`localhost:11434`), JSON-mode/schema enforcement, timeout + 1 retry, image input base64, 1024 px downscale helper (shared with Dev 2's vision)
- [ ] `models/gemma_cloud.py`: Gemini API fallback; `GEMINI_API_KEY` from env only — never logged, never in reports/DB
- [ ] Backend selector `auto|local|cloud|demo` + health probe feeding `GET /health` and the UI's Local ☁/API badge
- [ ] Fail-safe wiring: model unavailable ⇒ `semantic-unavailable` / `vision-unavailable` note findings — **never a silent pass** ([05-api §5.8](../../reference/api.md))
- [ ] Prompt-injection hygiene per [04-security §4.8](../../developer/security.md): content fenced as data; parse failure ⇒ retry once ⇒ unavailable finding
- [ ] Tests: I2 contract tests run against MockGemma (CI) and real Ollama (nightly/local marker)

**Done means:** Dev 2's `analyzer.py` and `vision_scanner.py` run green against MockGemma in CI and against real Gemma locally; backend switch visible in `/meta`.

---

## CL-D1-4 · Deception: Sinkhole, Poisoned Well, Evasion (M2 · W1.3 + W1.6)

*Depends on: CL-D1-2 (sandbox), CL-D1-3 (health plumbing) · Blocks: CL-D1-5 overrides, Dev 3's IOC view data*

- [ ] `sandbox/dns_sinkhole.py`: in-container resolver on :53 logging every query `{ts, qname, client}`; `resolv.conf` pinned; fallback = hosts-file override (plan risk mitigation); DB writes → `sandbox_net_logs`
- [ ] `sandbox/fake_http.py`: responder logging method/URL/headers/body(base64); returns `200 {"status":"ok","data":"<secondary_canary>"}`; rate-limited; **inert content only** ([04-security §4.4](../../developer/security.md))
- [ ] `poisoned_well/canary_gen.py`: intent-matched fake secret generators (AWS `AKIA…SKS-`, GitHub `ghp_SKS…`, Slack `xoxb-SKS-…-fake`, SSH PEM comment) + secondary canary generator
- [ ] `poisoned_well/exfil_tracker.py`: correlation engine per [02-arch §2.3](../../developer/architecture.md) rules — Event A (canary read) + Event B (DNS/HTTP) within `correlation_window_s`; marker match: raw / base64 / hex / subdomain-label reassembly; confirmed ⇒ override signal `{verdict: MALICIOUS, confidence: 1.0}`
- [ ] `poisoned_well/attacker_profile.py`: profile builder `{targetedAssets, exfilChannel, c2Indicators[], encoding, declaredIntent, actualBehavior, contextAwareCanary}`; writes `iocs` (confirmed flag) + `attacker_profiles` tables; STIX bundle writer *(swing task — may move to Dev 2, [11-team §11.8](../11-team-and-workload.md))*
- [ ] `evasion/detector.py`: classify probe events (`/.dockerenv`, `/proc/1/cgroup`, `df -h`, `/proc/bus/input`, mountinfo greps) ⇒ override signal; masquerade failure ⇒ engine error, **never auto-pass**
- [ ] DB: DDL + write paths for `canary_events`, `sandbox_net_logs`, `iocs`, `attacker_profiles`, `active_defense` ([03-database §3.4/§3.6](../../developer/database.md))
- [ ] Fixture `cloud-sync-pro` (DNS-tunnel sketch, [08-testing §8.2](../../developer/testing.md)) — verify: PW correlation confirms **10/10 runs**, C2 domain captured, encoding detected `base64`
- [ ] Fixture `slack-notif-mal` (evasion + HTTP exfil) — verify: probe detected ⇒ auto-MALICIOUS **10/10**; context canary = SLACK when intent says Slack
- [ ] Safety self-review against [04-security §4.4](../../developer/security.md): no outbound to real infra, canaries fake-by-construction, deception log complete & user-visible, opt-out config works

**Done means:** both malicious fixtures deterministically trigger their overrides; `activeDefense` block populated exactly per contract; telemetry queryable for Dev 3's timeline/graph.

---

## CL-D1-5 · Verdict Fusion & Report Generation (M3 · W1.4) — *your second big block*

*Depends on: CL-D1-4 (override signals), Dev 2's StageResults (I3) + cache store (CL-D2-4) · Blocks: M3 exit, Dev 3 exports*

- [ ] `verdict/fusion.py`: weights from config (anchors 0.15 · semantic 0.20 · vision 0.20 · sandbox 0.25), weight-normalized sum + typosquat +15, clamp 100; tier thresholds (<30 / 30–70 / >70); **overrides** (PW correlation, evasion) ⇒ MALICIOUS, `riskScore ≥ 95`, `confidence 1.0` ([02-arch §2.4](../../developer/architecture.md))
- [ ] Signal ingestion: consume every stage's `StageResult.signals`; missing stage ⇒ documented degradation finding, renormalize weights over present stages
- [ ] `verdict/sarif_report.py`: SARIF 2.1.0 — `ruleId skillsentry/<stage>/<type>`, severity→level mapping, `physicalLocation` file+line, `run.properties.verdict/riskScore/confidence/cached` + `activeDefense` extension ([05-api §5.6](../../reference/api.md)); validate against official SARIF schema in CI
- [ ] Markdown renderer (human triage report) + STIX bundle emitted to `~/.skillsentry/reports/<scan_id>/` *(Markdown/STIX = swing tasks if behind)*
- [ ] Cache integration: Stage 0 lookup `(content_hash, engine_version, model_version)` via Dev 2's store; on miss, upsert cache + findings + active_defense **in one transaction**; `scans` row always written (incl. `cached-hit`) ([03-database §3.5–3.6](../../developer/database.md))
- [ ] Orchestrator E2E in `cli.py`: stages 0→6 in order, WS/progress events emitted per stage, crash ⇒ `status=failed` (never phantom cache entry)
- [ ] Fail-safe audit: enumerate every error path; assert none yields SAFE; degraded modes (`sandbox-unavailable`, `semantic-unavailable`, `vision-skipped`) produce note findings
- [ ] CLI surface: exit codes 0/1/2/3/4, flags `--fail-on --sarif-out --format --no-cache --demo-mode --backend --timeout --watch(stub) -q` ([07-cli](../../reference/cli.md))
- [ ] Tests: fusion math (weights, bonus, clamps, tiers, overrides) property-based; SARIF validates; verdict JSON matches contract v1 byte-schema; **eval sheet green** with Dev 2's harness

**Done means:** full fixture corpus produces expected verdicts/risk bands ([08-testing §8.4](../../developer/testing.md)); cached re-scan < 2 s measured; SARIF opens cleanly in GitHub Code Scanning (local upload test).

---

## CL-D1-6 · API Server & Live Streaming (M2 start → M3 finish · W1.5)

*Depends on: CL-D1-1 (routes skeleton in demo_mode) · Blocks: Dev 3 switching off mock (CL-D3-4/6)*

- [ ] `server/app.py` + `routes.py`: real implementations of `POST /scan` (202 + scan_id), `GET /scan/{id}`, `GET /scan/{id}/verdicts`, `GET /skills/{id}`, `GET /skills/{id}/export`, `GET /cache/stats`, `DELETE /cache`, `GET /health`, `GET /meta` ([05-api §5.2](../../reference/api.md))
- [ ] `WS /scan/{id}/stream` on the real pipeline bus: event catalog minimum set, ≤ 2 s heartbeat during LLM calls, `cancel` op ⇒ container teardown, reconnect-friendly (replay from DB on late join)
- [ ] Error model codes per [05-api §5.8](../../reference/api.md) (400/404/409/422/500/503); 409 on duplicate in-flight hash
- [ ] Concurrency: scan queue, per-skill quotas, one sandbox at a time by default (config `max_parallel`)
- [ ] **Schema-parity contract tests:** identical assertions run against `demo_mode` and the real server (they can never drift)
- [ ] `skillsentry serve` (mounts Dev 3's built UI) + `skillsentry self-audit` (scans own `skill/SKILL.md`)
- [ ] Swap Dev 2's fixture-derived canned payloads into `demo_mode` (I4) so demo data == real data shapes

**Done means:** Dev 3 flips base URL from mock → real with **zero UI code changes**; parity tests green.

---

## CL-D1-7 · Hardening, Chaos & Demo (M4)

*Depends on: M3 exit · All-hands, Dev 1 leads*

- [ ] Run **Chaos Run ×2** ([08-testing §8.6](../../developer/testing.md)): net unplugged, Docker killed mid-scan, corrupted fixture, `--demo-mode` — fix every non-graceful failure found
- [ ] Timeout/teardown fuzzing: kill engine mid-sandbox 10×; assert no orphan containers/networks/tmpdirs
- [ ] Performance validation: uncached < 90 s, cached < 2 s, WS heartbeat ≤ 2 s under load; record numbers for README eval table (hand to Dev 2)
- [ ] Security self-review: walk [04-security §4.5–4.6](../../developer/security.md) tables line by line; tick production checklist items that landed ([09-deployment §9.6](../../operations/deployment.md))
- [ ] Lead rehearsal ×3 of demo script ([08-testing §8.7](../../developer/testing.md)) — money shots: steps 5 (PW timeline) & 6 (evasion)
- [ ] Backup demo video support (Dev 3 records; you operate the engine)

**Done means:** M4 exit gate — Chaos Runs clean, demo runs 3× back-to-back without a hiccup.

---

## CL-D1-8 · Stabilization & Packaging (M5 / Phase 1)

*Depends on: M4 · Swing tasks may reassign — check [11-team §11.8](../11-team-and-workload.md)*

- [ ] `pip install skillsentry` packaging (entry points, pinned lockfile, minimal deps audit)
- [ ] Published Docker image (pinned manifest, CI-built) + `docker run` docs pass
- [ ] `skillsentry scan --watch` (watchdog-driven re-scan on skill dir changes)
- [ ] `skillsentry init` + model auto-download helper + CLI progress bars (DX)
- [ ] Signed-verdict spike: sigstore keyless signing of SARIF, `cosign verify-blob` recipe ([09-deployment §9.6](../../operations/deployment.md))
- [ ] Structured JSON logging + OpenTelemetry hooks; metrics per [09-deployment §9.7](../../operations/deployment.md)
- [ ] MCP runtime proxy design doc → implementation start (Phase 2, [09-deployment §9.5](../../operations/deployment.md))

**Done means:** a stranger can `pip install`, `init`, and scan a skill with zero tribal knowledge.

---

## Ongoing Responsibilities (all milestones)

- [ ] Guardian of **I1** (contracts): review any PR touching `contracts.py`, verdict schema, WS events
- [ ] Cross-cutting sign-off (with Dev 2 + Dev 3) on schema/weight/stage-list changes
- [ ] Model latency watch: re-benchmark on Ollama/model updates; update `model_version` handling
- [ ] Sandbox security regressions: re-run escape/teardown tests on every Docker base-image bump
- [ ] Daily standup: report against **milestone exit criteria**, flag swing-task triggers early
