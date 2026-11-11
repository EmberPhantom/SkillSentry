# Changelog

All notable changes to **SkillSentry** are documented in this file.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/); versioning follows [SemVer](https://semver.org/).

---

## Policy

- Every change a user or operator can notice gets an entry under `[Unreleased]`, in the same pull request.
- Entries are grouped as Added, Changed, Deprecated, Removed, Fixed, or Security.
- A release moves the `[Unreleased]` entries under a new version heading with its date, and then `[Unreleased]` is empty again.
- Old entries keep the names they had at the time. Do not rewrite history.

## [Unreleased]

### Fixed
- The unused `watchdog` dependency is removed.
- The STIX bundle identity names the running version instead of a fixed `SkillSentry 2.0`.

## [2.1.0] — 2026-11-07

First final release of the 2.1 line. The changes are the ones listed under 2.1.0rc2 and 2.1.0rc1 below; this version has no further code changes.

## [2.1.0rc2] — 2026-11-06

### Added
- Type checking: mypy runs in CI and `scripts/check.sh`, using the pydantic plugin. Seven modules are on a documented lenient list in `pyproject.toml`.
- Coverage gate: the unit and contract tests must cover at least 86% of `skill_sentry_cli` (measured 88%).
- Server image healthcheck on `/meta`, using only the Python standard library.
- Release images are signed keyless with cosign, and both images carry a BuildKit SBOM and max provenance.
- A CycloneDX 1.6 SBOM of the installed wheel is attached to each GitHub release and listed in `SHA256SUMS`.
- Dashboard build job in CI (Node 24).
- Non-blocking Python 3.14 CI job. Python 3.14 is not supported yet.
- Community files: Code of Conduct, support guide, issue and pull request templates, CODEOWNERS, Dependabot, pre-commit, and `.editorconfig`.
- `docs/20-governance.md`: roles, decisions, release authority, support policy, and a maintainer settings checklist.
- Documentation gate that blocks capitalised model names in public documents.

### Changed
- Every GitHub Actions workflow action is pinned to a commit SHA.
- Base images in the server Dockerfile are pinned by digest.
- Node 24 is used for the dashboard build, the release build, and the server image.
- Public prose says "the local model" instead of naming the model. Configuration defaults and the frozen contract field names are unchanged.
- The local API's lack of authentication is documented in the security limitations and the user guide.
- Internal planning documents moved to `docs/internal/` with an archive note.

### Fixed
- SARIF `helpUri` and `informationUri` point at the repository, not an organisation that does not own it.
- The WebSocket `stream` protocol matches its implementations. Its return type is an async generator.
- The `Finding` keyword is spelled `finding_type` in Python code. The wire name is still `type`.
- The CLI reference no longer lists `--watch`, a Docker tag that does not exist, or per-stage output the CLI never prints.
- `audit.sh` no longer lists exit code 4, which the CLI does not return.
- The second `2.0.0` heading is renamed to `2.0.0-hackathon`, so version headings are unique.

## [2.1.0rc1] — 2026-11-02

### Added
- `install.ps1`: a native Windows installer (no administrator rights, checksum-verified, PATH set, `-DryRun`, `-NoSetup`, `-Uninstall`).
- `install.sh`: `--version`, `--dry-run`, and a PATH line for your shell.
- `scan --report-dir DIR` (one Markdown report per skill plus `summary.md`) and `scan --recursive`.
- Every text scan ends with where the report is and the command that writes it.
- `INVALID SKILL` status for a malformed SKILL.md. It is shown as a package problem, not as malware. The stored verdict and the CI gate are unchanged.
- A platform line in `doctor` (WSL, native Windows, and macOS advice; a warning for skills on a Windows drive under WSL).
- Windows and macOS CI jobs (non-blocking until they are stable).

### Changed
- A folder scan prints the banner once, and the summary lists the INVALID count only when it is non-zero.

## [2.0.0] — first public release

### Renamed
- **The package, module and command are now `skill-sentry-cli`, `skill_sentry_cli` and `skill-sentry-cli`.** The name `skillsentry` on PyPI belongs to an unrelated project that installs the same module and command, so this project cannot publish under those names. `skill-sentry` was also rejected by PyPI as too similar to an existing project. **Breaking:** update imports from `skillsentry` to `skill_sentry_cli`, and the command from `skillsentry` to `skill-sentry-cli`. Your data is unchanged: `skillsentry.toml`, `~/.skillsentry`, `SKILLSENTRY_*` variables, the sandbox image name and the bundled skill name all keep their names.

### Added
- `skill-sentry setup`: guided first-time setup. It checks the same things as `doctor`, writes the default configuration if you agree, offers to install the sandbox image (a published copy when this release has one) and to download the model, and never installs Docker or Ollama itself. Every download or build waits for a yes; `--yes` accepts all prompts.
- `install.sh`: installs from a published release after checking the wheel against `SHA256SUMS`. Uses pipx when available, otherwise a private virtual environment under your home folder. No sudo. `--uninstall` keeps your data.
- Registry account manual (`docs/18-registry-accounts.md`): PyPI and TestPyPI accounts, two-factor authentication, trusted publishing, recovery.
- Release workflow and runbook (`.github/workflows/release.yml`, `docs/17-release-process.md`): tag-driven, trusted publishing to TestPyPI for release candidates and to PyPI behind a reviewer approval, multi-architecture sandbox and server images, build provenance.
- `scripts/check_wheel.py`: fails the build if the wheel is missing the dashboard, the sandbox sources, the rules, the known-name list, the bundled skill, or the command.

### Fixed
- `doctor` reported Docker as unreachable even when it was reachable, because its cleanup ran after every check. Each check now closes its client after its last use.

### Added
- **User guide** (`docs/16-user-guide.md`): install from a checkout, check readiness, first scans, reading verdicts and UNSCANNED reasons, folder scans, reports and stored scans, dashboard, CI use, configuration, and troubleshooting with real messages. Its commands and flags are checked against `--help` by `tests/unit/test_user_guide.py`.
- **Web dashboard** (`ui/`, React 18 and TypeScript): triage table with verdict filter, search and sort; new-scan form with a live console over the scan WebSocket; skill detail with overview, static findings, vision evidence, sandbox trace, Poisoned Well and export tabs; cache stats and clear. It ships inside the wheel and is served at `/` by `skillsentry serve`.
- **CLI:** `cache stats|list|clear`, `export <scan_id>` (re-renders a stored report), and `sandbox build` (builds the sandbox image from the packaged sources).
- **`skillsentry doctor`** checks what a full scan needs: the model pulled into the local server, a writable database and the built dashboard are required; Docker and the sandbox image are optional.
- **Sandbox execution plan** (INT-4): the baseline checks are always present, anchor-derived checks only add to them, and the engine refuses to run a plan that fails validation.
- **Acceptance tooling:** `scripts/acceptance.sh` runs the local gates and the release build; with `--e2e` it also scans the core fixtures and a folder of real skills.
- **Dockerfile** for the server image (multi-stage: dashboard build, then a non-root Python runtime). The Docker socket is not mounted by default.
- **Release script** `scripts/build_release.sh` and local check `scripts/check.sh` (lint, tests, schema drift, demo smoke) while CI is blocked.
- **Dev 1 M0 backend**: frozen Verdict v1 Pydantic contracts with generated `schemas/verdict.v1.json` + `schemas/api.v1.json`, deterministic `MockGemma`, SARIF 2.1.0 / Markdown / STIX 2.1 writers, and a 7-skill demo server covering REST, WebSocket replay, cache, batch scans, tab payloads, and error envelopes. Adds `skillsentry serve`, `skillsentry init`, and `skillsentry scan --demo-mode`; GitHub Actions lint/schema/demo-smoke gates. Live analysis still fails honestly with `503 engine_not_ready` until CL-D1-2…5 land.
- **Dev 1 sandbox/deception bundle**: Docker runner with an internal no-NAT network, non-root read-only container, 512 MB / 1 CPU / 128 pids / 60 s limits, canary seeding via tar, exec watchdog with timeout teardown, and fail-closed masquerade verification. Adds the `LD_PRELOAD` shim source + multi-stage sandbox image, canary-filesystem builder, context honeypot, tolerant monitor parser, loopback DNS sinkhole, inert HTTP responder with secondary canary, Poisoned Well correlation (raw/base64/hex/split DNS labels), attacker profile + IOC export, and evasion probe detection. Covered by mocked Docker lifecycle tests, real-loopback DNS/HTTP tests, and a real Docker Desktop 29.9.2 full-fixture pass with `MockGemma` (`cloud-sync-pro` 95, `slack-notif-mal` 100); real-model/vision E2E remains pending.
- **Dev 1 model + fusion source**: `GemmaLocal` (Ollama JSON-schema mode, image base64, health/digest probe) and opt-in `GemmaCloud` (Gemini, key in a request header only) implement I2 with retry-after-malformed-JSON and explicit `ModelUnavailable` failures; the `auto/local/cloud/demo` selector fails closed when no real backend is reachable. Adds the weighted fusion engine with missing-signal renormalisation, typosquat bonus, tier boundaries, stage-degradation notes, and hard overrides. No live Ollama/Gemini integration was possible in this environment.
- **CLI stdio hardening**: `skillsentry` reconfigures redirected stdout/stderr to UTF-8 with replacement, so emoji banners no longer crash `serve` on legacy Windows code pages before uvicorn binds. Verified with a real `skillsentry serve --demo-mode` smoke on loopback (`GET /meta`, `/health`, `/scans`, and `/skills/{id}` returned 200).
- **Team & workload assignment** (`docs/11-team-and-workload.md`): revised 3-developer split — Dev 1 (Backend + AI Integration: sandbox, Poisoned Well, models, verdict/reports, server), Dev 2 (Backend — Skill Analysis: parser, anchors, semantic, vision, cache), Dev 3 (Frontend only) — with work packages, milestone plan M0–M5, stage RACI, interface contracts I1–I5, and swing-task rebalancing. Supersedes the original plan §8 division; docs 02/08/10, CONTRIBUTING, and README updated for consistency.
- **Task-level work checklists** (`docs/checklists/`): 27 checklists (CL-D1-0…8, CL-D2-0…8, CL-D3-0…8) elaborating every work package into concrete tasks with dependencies, spec references, and "Done means" acceptance criteria; index includes milestone → checklist matrix and cross-developer dependency map.
- **v1 test coverage**: the documented CLI surface is checked against `--help` and the exit codes (`tests/unit/test_cli_surface.py`); outages fail closed and stay contained to their scan (`tests/unit/test_chaos.py`); SARIF output validates against the official 2.1.0 schema, vendored under `tests/fixtures/sarif/` (`tests/unit/test_sarif_schema.py`).
- **Ported from feature/developer-2** (chauhanaman41): fusion monotonicity and floor tests; ten-run static determinism; a packaged typosquat list of 67 names (`skillsentry/data/known_skills_v1.json`, loaded with `importlib.resources`); docs hygiene gates; credential service bindings (a credential is judged against the vendor it belongs to); live Ollama tests that require a real generation.
- **Credential service bindings**: declared and bound is informational; undeclared but bound is MEDIUM; an unbound destination and DNS exfiltration stay CRITICAL. Plain HTTP, disabled verification and a custom proxy never count as a binding.

### Changed
- **UNSCANNED status.** When a stage is degraded, the CLI and folder summary show `UNSCANNED` with the verdict and the reason, instead of presenting the SUSPICIOUS score as a normal result. The JSON verdict contract is unchanged, and exit codes still follow the verdict.
- **`--backend demo` is refused** for `scan` and `self-audit` unless `SKILLSENTRY_DEV=1` is set. Use `--demo-mode` for the canned store.
- The report and CLI badge no longer name a model.
- Local model client: configurable context size, prediction cap, seed and keep-alive. Health requires the configured model to be pulled, so a server without it no longer answers with another model. Cache identity uses `name@digest`.
- Legacy semantic analysis splits skills into line-aligned chunks within a call budget. Anything not analysed is reported as a coverage gap and sets the stage to degraded.
- Raster images sent to the model are capped at three per scan, downscaled to 768 px. The rest are reported as partial coverage.
- `--fail-on` defaults to `suspicious` for `scan` and `self-audit`.
- The default model is `gemma4:e4b-it-qat`, the build that was pulled and verified.
- The Laya decision backend is opt-in (`decision.backend = "legacy"` by default) until its calibration gates pass.
- The version is read from `skillsentry/core/version.py`.
- Documentation: `docs/07` matches `--help` (fail-on default, `init`, `serve`, `self-audit`, cache and export flags, environment variables). `docs/02`, `04` and `08` now state the 768 px vision cap, the three-image budget, the fail-closed model path and the cloud backend name.

### Fixed
- `cache list` shows the scan ID, skill, status and verdict; `cache stats` reports the database file size and the hit rate (it printed the hit rate as the size).
- A missing config file named by `SKILLSENTRY_CONFIG` is an error (exit 2), not a silent fallback to defaults; the CLI never shows a traceback for a bad config.
- An unreachable model server is named in the UNSCANNED reason.
- **Model evidence alone cannot make a verdict MALICIOUS.** A MALICIOUS tier needs a malicious override, or a non-model finding or signal of HIGH or above. Otherwise the verdict is capped at SUSPICIOUS and a NOTE says so. Model findings can still raise a verdict to SUSPICIOUS.
- **Model citations are verified.** A quote the model cites must appear in the skill; the reported line is the one that contains it. Unverifiable quotes are dropped and counted in a NOTE.
- **Ordinary network code is not a reverse shell.** A plain socket is MEDIUM. CRITICAL is reserved for reverse-shell primitives (`/dev/tcp`, `pty.spawn`, `os.dup2`). The DNS rule matches only commands, not the word "host" in prose.
- **Cache identity includes generation options** (context size and prediction limit). Changing them no longer serves a cached result.
- **CLI writes report an unwritable path** as an operational error (exit 3) instead of a traceback.
- **Unknown API paths return a JSON 404**, not the dashboard page.
- **Model probe** distinguishes an unreachable server from a missing model; `doctor` says which.
- **Model errors keep their own message** (HTTP status, truncated, empty, transport). Only malformed output is called "no schema-valid JSON".
- **Sandbox timeout message** states the configured limit and the elapsed time.
- **Docker clients are closed** (runner, engine, doctor, sandbox build, health probe).
- **Dashboard dev-server dependencies** upgraded (Vite 8); the audit reports no vulnerabilities.
- **Lower dependency bounds** raised to versions that install and pass the suite: typer 0.16, PyYAML 6.0.1.
- Python 3.13 added to the classifiers and the CI matrix; the suite passes on 3.11, 3.12, and 3.13.
- Sandbox base image pinned by digest; Pillow pinned.
- The test suite is portable to an installed package: source-checkout gates skip cleanly when run outside a checkout.

- **Stable verdicts.** The prompt fence nonce is derived from the excerpt, so an identical skill produces an identical model prompt. Model replies are bounded (at most 8 patterns, short evidence), so a reply no longer fails by running past the token cap depending on the run.
- **No silent skips.** A text file that is oversize, over the text budget, or unreadable is reported as a HIGH "text file not analysed" finding, which degrades the spec stage. Extensionless scripts at the root are read.
- **Symlinks and bad encodings are findings.** A symlink is hashed as a link and reported (HIGH), and the rest of the skill is still scanned. A non-UTF-8 `SKILL.md` is reported (HIGH) and analysed with replacement characters.
- **PowerShell download-and-run** (`Invoke-WebRequest | Invoke-Expression`, `iex (…DownloadString…)`) is detected as a HIGH `shell-exec` anchor.
- **Health** reports Ollama as `ok` when the configured model is pulled, using the same readiness check as the model layer.
- **Tests are isolated** from the user's cache and scan history: the test database is a temporary file.

- Cache identity now includes a fingerprint of the credential rules file, so editing the rules cannot serve cached verdicts from before the edit.
- Fusion applies the strongest malicious override floor, so an evasion probe reports 100 even when a Poisoned Well override is listed first.
- Parser: YAML aliases and nesting deeper than 10 levels are refused before expansion. Reserved device names and alternate data stream notation are reported and the file stays in analysis.
- Typosquat: a case-only variant of a known name, and Cyrillic or Greek homographs, are flagged.
- SVG: UTF-16 documents are decoded and scanned, the whole document is scanned rather than the first 20,000 characters, and external `<use>`, `data:` URIs, DTD entities, remote stylesheets and hidden text are detected.
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

## [2.0.0-hackathon] — 2026-10 (MLH Hacktoberfest Hack Day)

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
