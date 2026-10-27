# Changelog

All notable changes to **SkillSentry** are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

---

## [Unreleased]

### Added
- **Dev 1 M0 backend**: frozen Verdict v1 Pydantic contracts with generated `schemas/verdict.v1.json` + `schemas/api.v1.json`, deterministic `MockGemma`, SARIF 2.1.0 / Markdown / STIX 2.1 writers, and a 7-skill demo server covering REST, WebSocket replay, cache, batch scans, tab payloads, and error envelopes. Adds `skillsentry serve`, `skillsentry init`, and `skillsentry scan --demo-mode`; GitHub Actions lint/schema/demo-smoke gates. Live analysis still fails honestly with `503 engine_not_ready` until CL-D1-2…5 land.
- **Dev 1 sandbox/deception bundle**: Docker runner with an internal no-NAT network, non-root read-only container, 512 MB / 1 CPU / 128 pids / 60 s limits, canary seeding via tar, exec watchdog with timeout teardown, and fail-closed masquerade verification. Adds the `LD_PRELOAD` shim source + multi-stage sandbox image, canary-filesystem builder, context honeypot, tolerant monitor parser, loopback DNS sinkhole, inert HTTP responder with secondary canary, Poisoned Well correlation (raw/base64/hex/split DNS labels), attacker profile + IOC export, and evasion probe detection. Covered by mocked Docker lifecycle tests, real-loopback DNS/HTTP tests, and a real Docker Desktop 29.9.2 full-fixture pass with `MockGemma` (`cloud-sync-pro` 95, `slack-notif-mal` 100); real-model/vision E2E remains pending.
- **Dev 1 model + fusion source**: `GemmaLocal` (Ollama JSON-schema mode, image base64, health/digest probe) and opt-in `GemmaCloud` (Gemini, key in a request header only) implement I2 with retry-after-malformed-JSON and explicit `ModelUnavailable` failures; the `auto/local/cloud/demo` selector fails closed when no real backend is reachable. Adds the weighted fusion engine with missing-signal renormalisation, typosquat bonus, tier boundaries, stage-degradation notes, and hard overrides. No live Ollama/Gemini integration was possible in this environment.
- **CLI stdio hardening**: `skillsentry` reconfigures redirected stdout/stderr to UTF-8 with replacement, so emoji banners no longer crash `serve` on legacy Windows code pages before uvicorn binds. Verified with a real `skillsentry serve --demo-mode` smoke on loopback (`GET /meta`, `/health`, `/scans`, and `/skills/{id}` returned 200).
- **Team & workload assignment** (`docs/11-team-and-workload.md`): revised 3-developer split — Dev 1 (Backend + AI Integration: sandbox, Poisoned Well, models, verdict/reports, server), Dev 2 (Backend — Skill Analysis: parser, anchors, semantic, vision, cache), Dev 3 (Frontend only) — with work packages, milestone plan M0–M5, stage RACI, interface contracts I1–I5, and swing-task rebalancing. Supersedes the original plan §8 division; docs 02/08/10, CONTRIBUTING, and README updated for consistency.
- **Task-level work checklists** (`docs/checklists/`): 27 checklists (CL-D1-0…8, CL-D2-0…8, CL-D3-0…8) elaborating every work package into concrete tasks with dependencies, spec references, and "Done means" acceptance criteria; index includes milestone → checklist matrix and cross-developer dependency map.

### Fixed
- **Docker 29 sandbox execution**: removed `/proc` bind mounts and serve sanitised cgroup/mountinfo views through the shim; added `stat64`, `fstatat`, `statx`, and versioned glibc stat interception so `/.dockerenv` stays hidden from shell and coreutils probes; seed `/tmp/skillsentry` via exec on the tmpfs; use an anonymous canary-home volume; serialize all runners process-wide; and reset a RUNNING scan row when a post-history `ScanError` occurs. Full Docker fixture acceptance now passes with `MockGemma`.

### Planned — Phase 1: Stabilization
- Pytest suite (parser, typosquat, fusion weights, cache) + fixture-regression gate (`tests/expected_verdicts.json`)
- CI via GitHub Actions (unit/contract on runners; integration + E2E on self-hosted with Ollama)
- `pip install skillsentry` packaging + published Docker image
- `skillsentry scan --watch` mode
- `skillsentry init` (config file), model auto-download helper, CLI progress bars
- Evaluation corpus grown to 20 skills; published precision/recall table
- Docs: architecture deep-dive, threat-model doc, honest prior-art section

### Planned — Phase 2: Production (weeks 3–6)
- **MCP runtime proxy**: permission enforcement, resource limits, behavioral-drift detection
- Signed verdicts (sigstore keyless signing; `cosign verify-blob`)
- Community IOC blocklist feed (signed JSON, opt-in, false-positive dispute process)
- Structured JSON logging + OpenTelemetry hooks
- Postgres team-server backend behind the repository interface
- MCP server manifest scanning support
- Versioned verdict schema with migration path; signed release tags

## [2.0.0] — 2026-10 (MLH Hacktoberfest Hack Day)

### Added
- **8-stage inspection pipeline**: cache → spec/typosquat → deterministic anchor + semantic → multimodal vision → context-aware sandbox → Poisoned Well → evasion detection → verdict fusion
- **☠️ Poisoned Well active defense**: intent-matched fake credentials (marker `SKS-<8hex>`), DNS sinkhole + fake HTTP 200 responder with secondary canary, exfil correlation engine (raw/base64/hex/subdomain-label matching), attacker profile + STIX 2.1 IOC export
- **Context-aware honeypots**: canary seeding driven by the skill's `declared_intent` (AWS / GitHub / Slack / SSH / generic fallback sets)
- **Sandbox evasion detection**: probes for `/.dockerenv`, `/proc/1/cgroup`, disk checks, VM artifacts ⇒ auto-`MALICIOUS` (`confidence: 1.0`)
- **Masquerade layer**: `LD_PRELOAD` hooks, `/dev/null` bind over `/.dockerenv`, tmpfs-shadowed `/proc/1/cgroup`
- **Deterministic anchoring**: AST/regex pre-scan injected as ground truth into Gemma prompts (LLM may not contradict anchors)
- **Incremental scanning**: SHA-256 directory hash → SQLite cache; cached re-scan < 2 s; invalidation bound to engine + model versions
- **Multimodal vision scan**: Gemma 4 vision OCR for white-on-white / stego-style image payloads; SVG scanned as text and rendered; 1024 px downscale; bounding boxes
- **Verdict engine**: weighted fusion (anchors 0.15 · semantic 0.20 · vision 0.20 · sandbox 0.25 · typosquat +15) → risk 0–100 → SAFE/SUSPICIOUS/MALICIOUS tiers with hard-evidence overrides
- **Reports**: SARIF 2.1.0 JSON (with `activeDefense` extension) · Markdown · STIX 2.1
- **Triage Dashboard UI**: scan queue, live WebSocket console, triage table (verdict pills, risk gauges, ⚡ cache indicator), skill detail with six evidence tabs — Static Findings, **Gemma's Eye View** (contrast + bbox overlay), Sandbox Trace, Poisoned Well IOC timeline + React Flow graph, SARIF export, Threat Model Context
- **FastAPI + WebSocket server** with frozen **Verdict JSON Contract v1**; `--demo-mode` canned-response server for offline demos and parallel frontend development
- **Gemma dual backend**: Ollama local (Gemma 4 E4B, Q4 — 100% local by default) with opt-in Gemini API fallback
- **CLI**: `skillsentry scan` (incl. `--no-cache`, `--demo-mode`, `--fail-on`, `--sarif-out`), CI exit-code contract
- **Fixture corpus**: 4 benign (`pdf-summarizer`, `git-helper`, `image-resizer`, `weather-fetch`) + 3 malicious (`cloud-sync-pro` DNS-tunnel credential thief, `invoice-helper` image-payload injection, `slack-notif-mal` evasion + Slack-token theft) + stretch typosquat (`g1t-translate`)
- **SkillSentry's own Agent Skill** (`skillsentry/skill/SKILL.md` + `scripts/audit.sh`) — spec-compliant self-packaging
- Chaos Run doctrine (offline / Docker-down / corrupted-fixture / demo-mode drills) and rehearsed 3-minute demo script
- Documentation suite: overview, architecture, database, security, API reference, UI/UX, CLI, testing & evaluation, deployment & production, developer guide

### Security
- Sandbox hardening: `no-new-privileges`, cap-drop, non-root user, 512 MB / 1 CPU / 60 s limits, sinkhole-only egress (hard guarantee nothing escapes), ephemeral filesystem with guaranteed teardown
- Poisoned Well ethics rules: purely defensive deception — no contact with attacker infrastructure, fake-by-construction credentials, inert responses, user-visible deception log, opt-out config
- Fail-safe rule: no error path may produce a `SAFE` verdict; degraded scans carry explicit `*-unavailable` findings

## [1.x] — Initial concept (pre-v2.0)

- Text-only pre-install scanning concept (regex/LLM), single-stage verdict — superseded by the v2.0 multimodal + sandbox + active-defense architecture.

---

*Powered by Gemma 4 · open weights.*
