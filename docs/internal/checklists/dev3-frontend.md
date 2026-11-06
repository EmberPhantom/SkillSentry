# Dev 3 · Frontend — Work Checklists

> **Owner:** Dev 3 · **Scope:** the complete React dashboard (`ui/`) + demo assets (README GIF, backup video). **Frontend only** — no backend code, no fixtures.
>
> **Golden rule:** build against Dev 1's **mock server** (`demo_mode`) from day one; the switch to the real API is a base-URL change only. The Verdict Contract v1 is frozen — if a field seems missing, request a backward-compatible addition, never fork the schema.
>
> Spec homes: [06-ui-ux](../../developer/ui-design.md) (binding) · [05-api-reference](../../reference/api.md) · [11-team](../11-team-and-workload.md)

---

## CL-D3-0 · Onboarding & Environment

*Depends on: — (start immediately; mock server from CL-D1-1 within ~a day)*

- [ ] Read [06-ui-ux](../../developer/ui-design.md) fully (design language, wireframes, UX rules — they are binding), [05-api §5.2–5.5](../../reference/api.md) (endpoints + frozen verdict contract), [11-team §Dev 3](../11-team-and-workload.md)
- [ ] Node 20+, npm; clone repo; `cd ui`
- [ ] Run Dev 1's mock server (`python -m skillsentry.server.demo_mode --port 8000`) and fetch `GET /meta`, `POST /scan`, one WS stream by hand — know your data before you render it
- [ ] Collect the canned verdict fixtures (all 7 store skills incl. `cloud-sync-pro` PW block, `invoice-helper` vision bbox) into `ui/src/mocks/` for offline storybook-style dev

**Done means:** you can recite the verdict contract's top-level fields and where each detail tab's data comes from.

---

## CL-D3-1 · App Shell & Design System (M0 · W3.1)

*Depends on: CL-D1-1 (mock + frozen contract) · Blocks: every later UI checklist*

- [ ] Scaffold: Vite + React 18 + TypeScript (`strict: true`) + Tailwind + shadcn/ui; ESLint + Prettier; Vitest + React Testing Library; CI job in the repo pipeline
- [ ] Design tokens per [06-ui-ux §6.1](../../developer/ui-design.md): `zinc-950` bg / `zinc-900` panels / `zinc-800` borders; verdict colors emerald/amber/red; cyan live accent; Inter + JetBrains Mono (self-hosted or system fallback — preview sandbox has no network); scan-line keyframes + `prefers-reduced-motion` guard
- [ ] `verdict.ts` single source of truth: TS types generated from Dev 1's exported JSON Schema (or hand-written + contract test comparing to mock responses)
- [ ] API client layer: typed fetchers for every endpoint ([05-api §5.2](../../reference/api.md)) + WS wrapper with auto-reconnect; **base-URL env switch** mock ↔ real
- [ ] `<Header>`: brand, **"Powered by Gemma 4 · open weights" badge visible on every screen** (compliance — [06-ui-ux §6.1](../../developer/ui-design.md)), backend mode indicator (Local ☁ / API) from `GET /meta`, settings entry, `DEMO DATA` chip when `demoMode: true`
- [ ] Routing skeleton: 4 screens (Scan Queue / Live Console / Triage Table / Skill Detail w/ 6 tabs) with loading + error boundaries
- [ ] Health banner component reading `GET /health` (Ollama/Docker down ⇒ degraded-mode banner with `--demo-mode` hint — UX rule 4)

**Done means:** shell renders canned triage rows from the mock; badge + demo chip visible; contract test green in CI.

---

## CL-D3-2 · Scan Queue + Triage Table (M1 · W3.2)

*Depends on: CL-D3-1 · Blocks: demo story (this is the hero screen)*

- [ ] `<ScanQueue>` (Screen 1): `+ Scan folder` (path input → `POST /scan` → navigate to console), queue list with statuses, health banner placement
- [ ] `<TriageTable>` (Screen 3) exactly per wireframe ([06-ui-ux §6.3](../../developer/ui-design.md)): columns SKILL / VERDICT / RISK / KEY FINDING / ACTIONS; summary header ("7 skills · 4 safe · 3 blocked")
- [ ] `<VerdictPill>`: icon + text + color together (never color alone — a11y); tooltip: confidence + override reason ("Poisoned Well correlation, confidence 1.0")
- [ ] `<RiskGauge>`: Recharts radial 0–100, tier-colored
- [ ] `<CacheIndicator>`: ⚡ + "< 2 s (cached)" when `cached: true` (UX rule 5)
- [ ] Key-finding column: highest-severity finding message with stage emoji (☠️ / 👁 / 🔒)
- [ ] Actions per UX rule 8: SAFE → `Install`; SUSPICIOUS → `Install anyway…` behind confirm dialog enumerating findings; MALICIOUS → `Report` only (no install path)
- [ ] Filters (verdict / stage / cached) + sort (risk ↓ default, name, duration) + Export buttons (`SARIF` / `Markdown` → export endpoints)
- [ ] States: empty (illustration + CTA), loading (skeleton rows), error (retry); 100-row table scrolls/paginates smoothly
- [ ] Keyboard: arrow-key row navigation, enter → detail, visible focus rings

**Done means:** mock 7-skill store renders pixel-faithful to the wireframe; all filters/sorts work; install gating verified by tests.

---

## CL-D3-3 · Skill Detail Shell + Static Findings (M1–M2 · W3.3)

*Depends on: CL-D3-2 · Blocks: evidence-one-click rule (UX rule 1)*

- [ ] `<SkillDetail>` (Screen 4): `GET /skills/{id}`; 6-tab layout (Static Findings / 👁 Vision / Sandbox Trace / ☠️ Poisoned Well / SARIF Export / Threat Model Context); tabs degrade to dropdown < 768 px
- [ ] `<StaticFindings>`: code viewer (monospace, line numbers) with **red highlights at cited lines**; AST-anchor section visually separated from LLM judgment ([06-ui-ux §6.3](../../developer/ui-design.md)); severity chips
- [ ] Citation links: every `file:line` in every finding is clickable → opens highlighted snippet (UX rule 3)
- [ ] Finding list → code pane master/detail interaction; "no naked verdicts" test: MALICIOUS skill always surfaces ≥ 1 evidence item within one click
- [ ] `<ThreatModelContext>` tab: static explainer (actor → registry → gate diagram, inline SVG — no network assets) + doc links

**Done means:** for all 3 malicious mock skills, a judge can reach hard evidence in ≤ 1 click from the triage row.

---

## CL-D3-4 · Live Scan Console (M2 · W3.4)

*Depends on: CL-D3-1 (WS wrapper); real events when CL-D1-6 lands — build on mock replay first · Blocks: demo step 2 ("motion during slow LLM calls")*

- [ ] `<LiveConsole>` (Screen 2): terminal-style stream (JetBrains Mono), grouped by stage with headers, color-coded severities, auto-scroll + pause-on-hover
- [ ] WS lifecycle: connect on scan start, render `{stage, skill, event, ts, detail}` catalog ([05-api §5.3](../../reference/api.md)); heartbeat-loss detection (> 5 s silence ⇒ "waiting on model…" hint, not an error); auto-reconnect + late-join replay
- [ ] Per-stage progress rendering incl. **unknown stages generically** (forward-compat)
- [ ] `override` events get the money-shot treatment: full-width pulse row (☠️ "CANARY MARKER DECODED → CONFIRMED" / 🔒 "SANDBOX EVASION DETECTED"), `aria-live="assertive"`
- [ ] Cancel button (`{"op":"cancel"}`) with confirm; cancelled state
- [ ] Error events: inline, with degraded-mode explanation + next-step hint (never a blank screen)
- [ ] `completed` event → auto-navigate (or link) to triage/detail with the fresh verdict

**Done means:** scanning the mock store shows continuous motion start-to-finish; killing the WS server mid-scan shows a graceful reconnect/retry state.

---

## CL-D3-5 · Sandbox Trace + Vision Evidence (M2 · W3.5)

*Depends on: CL-D3-3; data shapes agreed with Dev 1 (telemetry) + Dev 2 (bbox fields) · Blocks: demo steps 4 & 6*

- [ ] `<SandboxTrace>`: filterable timeline (FS reads / DNS / HTTP / process / probe) from sandbox telemetry; filter chips + text search; monotonic T+x.x s timestamps
- [ ] Evasion alert banner (🔒) pinned top when probes present; probe rows highlighted
- [ ] Resource sparkline (time/mem) if telemetry provides it — optional, degrade gracefully
- [ ] `<VisionEvidence>` per wireframe ([06-ui-ux §6.3](../../developer/ui-design.md)): image pane + three view modes — `Normal` / `Contrast` (client-side CSS filters or canvas boost revealing white-on-white) / **`Gemma's Eye`** (contrast + bbox overlay + OCR-region heatmap)
- [ ] OCR transcript panel: JetBrains Mono, injected instruction highlighted, position note ("white-on-white, 4px font, bottom-right"), confidence badge
- [ ] bbox rendering contract with Dev 2: `{bbox:[x,y,w,h]}` normalized to displayed image size; multiple boxes supported
- [ ] Images embedded from API/data-URI (preview sandbox has no network — component tests use inline fixtures)

**Done means:** `invoice-helper` mock: toggling Normal → Gemma's Eye visibly reveals the payload with box; `slack-notif-mal` trace shows the probe row + evasion banner.

---

## CL-D3-6 · Poisoned Well IOC View + Exports (M3 · W3.6)

*Depends on: CL-D3-4 (live rows), CL-D3-5 (data plumbing); `activeDefense` block (I5 reports from Dev 1) · Blocks: demo step 5 — the showstopper*

- [ ] `<PoisonedWell>` attack timeline per wireframe: T+0.0s execution → masquerade → 🚨 canary READ → fake served (marker) → DNS/HTTP → 🔍 CONFIRMED; rows animate in live via WS during scan; confirmed row pulses red once
- [ ] IOC graph (React Flow): nodes `[script] → [canary file] → [marker] → [channel] → (C2)`; labeled edges `reads / fake / exfil`; node click → raw log evidence panel (mono); auto-layout, zoom/pan
- [ ] Context banner: "Intent: Slack integration ⇒ seeded SLACK_BOT_TOKEN" (declared intent vs. `contextAwareCanary`) — proves context-awareness to judges
- [ ] Verdict footer: `MALICIOUS · confidence 1.0 (hard evidence)` + `[Export STIX IOC]` button → `GET /skills/{id}/export?format=stix`
- [ ] `<ReportExport>` tab: rendered SARIF tree (rule → result → location) + raw JSON toggle; download buttons SARIF / Markdown / STIX (STIX disabled with tooltip when `activeDefense.triggered === false`)
- [ ] Empty state: benign skill → "No active-defense events — nothing touched the honeypots ✓"

**Done means:** `cloud-sync-pro` mock renders the full wireframe incl. working STIX download; graph nodes match `c2Indicators` from the contract.

---

## CL-D3-7 · States, Accessibility, Demo Mode, Settings (M3–M4 · W3.7)

*Depends on: all screens exist · Blocks: M4 exit (judges poke at states; a11y is a documented rule set)*

- [ ] Systematic empty/loading/error pass on **every** screen + tab (UX rule 4); error states always offer a next action (retry / demo-mode / docs link)
- [ ] A11y per [06-ui-ux §6.6](../../developer/ui-design.md): contrast ≥ 4.5:1 audit; color-independent verdicts; full keyboard flows; focus rings; dialog focus traps; `aria-live` polite (console/timeline) + assertive (overrides); `prefers-reduced-motion` kills scan-lines/pulses
- [ ] Responsive: KEY FINDING collapses < 1024 px; tabs → dropdown < 768 px; no horizontal scroll breakage
- [ ] Demo-mode UX: `DEMO DATA` chip always visible in demo; canned WS replay timing feels live; entire demo path works with backend fully down
- [ ] Settings screen: backend toggle (Local ☁ / API) wired to config endpoint or read-only display + docs link; cache stats (`GET /cache/stats`) with entries/hit-rate; `Clear cache` (confirm) → `DELETE /cache`
- [ ] Perf: 100-row triage + long console streams stay smooth (virtualize if needed); bundle sanity check

**Done means:** a11y checklist in [06-ui-ux §6.6](../../developer/ui-design.md) ticked item-by-item; killing Docker + Ollama still yields a complete, honest demo-mode walkthrough.

---

## CL-D3-8 · Demo Assets & Rehearsal (M4 · W3.8)

*Depends on: M3 exit (real E2E data) · Blocks: submission compliance*

- [ ] README GIF: capture the 8-step demo script ([08-testing §8.7](../../developer/testing.md)) — 30 s hero cut (scan all → triage → Gemma's Eye → PW timeline → ⚡ cached) + full-length version; save to `docs/assets/demo.gif` (the README's only placeholder file)
- [ ] Backup demo video: full 3-min script, screen + voiceover optional, uploaded unlisted YouTube, link into submission/README (compliance item)
- [ ] Rehearsals ×3 with Dev 1 operating: time each segment; fix any UI stall/dead-end found; run one rehearsal in `--demo-mode` end-to-end
- [ ] Judge-poke prep: click every button on every screen with empty/mocked data — zero dead ends, zero console errors
- [ ] Final polish: favicon, title tags, tab icons; header badge legibility on projector (test at low brightness/high glare settings)

**Done means:** GIF committed; video link recorded; demo ran 3× back-to-back with zero manual recovery.

---

## Post-M4 · Polish & Phase 1 (M5)

- [ ] Team-server read-only dashboard views ([09-deployment §9.4](../../operations/deployment.md)): triage queue over Postgres-backed API, confirmed-IOC leaderboard
- [ ] Component library pass: storybook-style catalog of pills/gauges/timeline rows for reuse
- [ ] Swing candidates (if reassigned, [11-team §11.8](../11-team-and-workload.md)): known-skill-names dictionary curation (data entry) · demo-mode canned payload authoring from recorded API responses

---

## Ongoing Responsibilities (all milestones)

- [ ] Guardian of the **frozen contract** on the client side: `verdict.ts` types + contract tests must match Dev 1's schema export in CI — drift fails the build
- [ ] UX rules enforcement ([06-ui-ux §6.5](../../developer/ui-design.md)): reject (in review) any screen state that violates "no naked verdicts", "evidence in one click", or "cache is visible"
- [ ] Gemma badge presence on every new screen (compliance, non-negotiable)
- [ ] Mock-first discipline: no UI PR may require the real backend while mock parity exists
