# 5 · API Reference

> The FastAPI server exposes REST endpoints for scans and skills, a WebSocket stream for live scan progress, and export endpoints for SARIF / Markdown / STIX. The **Verdict JSON Contract v1** (§5.5) is frozen at milestone M0 and does not change — the frontend builds against it via a mock server until the real API lands.

---

## 5.1 Conventions

| Item | Value |
|:---|:---|
| Base URL (local) | `http://127.0.0.1:8000` |
| Content type | `application/json` (UTF-8) |
| Timestamps | ISO-8601 UTC with milliseconds (`2026-10-21T09:31:07.412Z`) |
| IDs | `scan_id` / `skill_id`: UUID v4 strings |
| Auth | None in local mode (loopback bind only). Team-server mode: bearer token — **Spec (proposed)** |
| Demo mode | `--demo-mode` serves canned responses with identical schemas (no Docker/model required) |
| Versioning | Verdict contract `v1`; breaking changes ⇒ `v2` + migration path (never mutate `v1`) |

## 5.2 REST Endpoints

### `POST /scan` — start a scan

```jsonc
// Request
{
  "path": "/abs/path/to/skill-folder",   // required; directory containing SKILL.md
  "options": {                            // all optional
    "no_cache": false,
    "backend": "auto",                    // "auto" | "local" | "cloud" | "demo"
    "sandbox": true,                      // false ⇒ static stages only (flagged in findings)
    "poisoned_well": true,
    "timeout_s": 60
  }
}
// Response 202
{ "scan_id": "3f9c…", "status": "queued", "stream": "/scan/3f9c…/stream" }
```

Errors: `400` path missing/not a directory · `404` no `SKILL.md` found · `409` identical content hash already scanning · `422` body schema violation.

### `GET /scan/{scan_id}` — scan status

```jsonc
{
  "scan_id": "3f9c…",
  "status": "running",            // queued | running | completed | failed | cached-hit
  "stage": "sandbox",             // current pipeline stage (see §5.4)
  "skill": "cloud-sync-pro",
  "startedAt": "…", "elapsedMs": 41233,
  "error": null                   // populated when status = failed
}
```

### `GET /scan/{scan_id}/verdicts` — verdict list (backs the Triage Table)

```jsonc
{
  "scan_id": "3f9c…",
  "verdicts": [ /* array of Verdict Contract v1 objects, §5.5 */ ]
}
```

For a single-skill scan the array has one element; a folder-of-skills scan yields one verdict per skill (used by "Scan All" on the store view).

### `GET /skills/{skill_id}` — full detail (backs Skill Detail screen)

Returns the verdict object **plus** tab payloads: `staticFindings` (with code snippets), `visionEvidence` (image refs, OCR text, bboxes, view modes), `sandboxTrace` (ordered `canary_events` + `sandbox_net_logs`), `poisonedWell` (timeline + IOC graph nodes/edges + `activeDefense` block), `reportLinks`.

### `GET /skills/{skill_id}/export?format=sarif|markdown|stix`

Streams the report file (generated on demand, cached under `~/.skillsentry/reports/<scan_id>/`). `Content-Disposition: attachment`. STIX export requires an `activeDefense.triggered = true` scan (otherwise `409 no-iocs`).

### Cache & meta endpoints

| Endpoint | Purpose |
|:---|:---|
| `GET /cache/stats` | `{entries, hitRate, dbSizeBytes, engineVersion, modelVersion}` |
| `DELETE /cache?older_than=90d` | Prune cache rows (cascades to history per config) |
| `GET /health` | Liveness + dependency check: `{ollama: "ok"\|"down", docker: "ok"\|"down", db: "ok"}` — the UI's degraded-mode banner reads this |
| `GET /meta` | `{version, backendActive, gemmaBadge: "Fully local analysis · open weights", demoMode: bool}` |

## 5.3 WebSocket — `WS /scan/{id}/stream`

Live, terminal-style event stream (backs the Live Scan Console). Server → client messages:

```jsonc
{
  "stage": "poisoned_well",       // cache | spec | anchor | semantic | vision |
                                  // sandbox | poisoned_well | evasion | verdict
  "skill": "cloud-sync-pro",
  "event": "finding",             // started | progress | finding | override |
                                  // completed | error | cached
  "ts": "2026-10-21T09:31:07.412Z",
  "detail": { /* event-specific payload, may be null */ }
}
```

**Event catalog (minimum set the UI must handle):**

| Stage | Events worth streaming |
|:---|:---|
| `cache` | `cached` (⚡ instant verdict — stream closes) |
| `spec` | `progress` (frontmatter parsed), `finding` (typosquat!) |
| `anchor` | `finding` per AST/regex anchor (`{file, line, code}`) |
| `semantic` | `started`, `progress` ("Gemma analyzing…"), `completed` with `declared_intent` |
| `vision` | `progress` per image, `finding` with bbox + OCR snippet |
| `sandbox` | `started` (container up), `finding` (canary read / probe), `progress` (telemetry) |
| `poisoned_well` | `override` — "canary marker decoded → CONFIRMED" (the demo money-shot) |
| `evasion` | `override` — "sandbox evasion detected" |
| `verdict` | `completed` with the full Verdict object |
| any | `error` with `{stage, message, degraded: bool}` |

Client → server: `{"op":"ping"}` keepalive; `{"op":"cancel"}` aborts the scan (container teardown guaranteed).

**Demo rule:** stage events stream even during slow LLM calls (heartbeat `progress` every ≤ 2 s) so the console always has motion.

## 5.4 Pipeline Stage Identifiers

Canonical stage names (used by WS events, `findings.stage`, and DB CHECK constraints):

`cache` · `spec` · `typosquat` · `deterministicAnchor` · `semantic` · `vision` · `sandbox` · `poisonedWell` · `evasion` · `verdict`

## 5.5 Verdict JSON Contract v1 (FROZEN)

This is the single schema shared by the verdict engine, the triage table, the cache, and the mock server. **Frozen at M0 — additions must be backward-compatible (new optional fields only).**

```jsonc
{
  "skill": "cloud-sync-pro",
  "verdict": "MALICIOUS",            // SAFE | SUSPICIOUS | MALICIOUS
  "riskScore": 97,                   // 0–100 integer
  "confidence": 1.0,                 // 0.0–1.0
  "cached": false,                   // true ⇒ served from Stage 0 (<2s)
  "scanDurationMs": 87432,
  "findings": [
    {
      "stage": "deterministicAnchor", // §5.4 identifiers
      "severity": "high",             // low | medium | high | critical | note
      "message": "nslookup command detected — potential DNS tunneling",
      "evidence": { "file": "scripts/sync.sh", "line": 7 }
    },
    {
      "stage": "sandbox",
      "severity": "critical",
      "message": "Read canary file ~/.aws/credentials",
      "evidence": { "file": "scripts/sync.sh", "line": 14 }
    },
    {
      "stage": "poisonedWell",
      "severity": "critical",
      "message": "Canary marker exfiltrated via DNS",
      "evidence": { "c2": "evil-collector.net", "marker": "SKS-7f3a9c21" }
    }
  ],
  "activeDefense": {                  // present iff Poisoned Well ran
    "triggered": true,
    "targetedAssets": ["~/.aws/credentials"],
    "exfilChannel": "DNS_TUNNELING",  // DNS_TUNNELING | HTTP_POST | RAW_SOCKET | null
    "canaryMarker": "SKS-7f3a9c21",
    "secondaryCanary": "SKS-9d1e4b77",
    "c2Indicators": ["evil-collector.net"],
    "encoding": "base64",
    "sandboxEvasionDetected": false,
    "declaredIntent": "Cloud file synchronization",
    "contextAwareCanary": "AWS"       // AWS | GITHUB | SLACK | SSH | GENERIC
  }
}
```

**Field notes:**

| Field | Guarantees |
|:---|:---|
| `verdict` / `riskScore` | Tier boundaries: SAFE < 30 ≤ SUSPICIOUS ≤ 70 < MALICIOUS; overrides force MALICIOUS with `confidence: 1.0` |
| `findings[].evidence.file/line` | Line-accurate citation target ≥ 80%; every MALICIOUS verdict has ≥ 1 finding with `file` + `line` ("no naked verdicts") |
| `cached` | Drives the ⚡ indicator in the UI |
| `activeDefense` | Mirrors the SARIF extension (§5.6); `triggered: false` keeps the block present with nulls for schema stability |

## 5.6 SARIF 2.1.0 Mapping + `activeDefense` Extension

- Each `findings[]` entry ⇒ one SARIF `result` with `ruleId = skillsentry/<stage>/<type>`, `level` mapped from severity (`critical/high → error`, `medium → warning`, `low/note → note`), and `locations[].physicalLocation` = `{artifactLocation.uri, region.startLine}`.
- The verdict itself ⇒ `run.properties.verdict` / `.riskScore` / `.confidence` / `.cached`.
- Poisoned Well enrichment ⇒ `run.properties.activeDefense`:

```json
{
  "activeDefense": {
    "triggered": true,
    "targetedAssets": ["SLACK_BOT_TOKEN", "~/.aws/credentials"],
    "exfilChannel": "DNS_TUNNELING",
    "canaryMarker": "SKS-7f3a9c21",
    "secondaryCanary": "SKS-9d1e4b77",
    "c2Indicators": ["evil-collector.net", "185.220.101.42"],
    "encoding": "base64",
    "sandboxEvasionDetected": false,
    "declaredIntent": "Slack notification integration",
    "actualBehavior": "Credential theft + DNS exfiltration",
    "iocExport": "stix-bundle.json"
  }
}
```

GitHub Action uploads this SARIF to Code Scanning (`upload-sarif: true`).

## 5.7 STIX 2.1 Export Mapping

| SkillSentry IOC | STIX object |
|:---|:---|
| C2 domain (`evil-collector.net`) | `indicator` · `pattern: [domain-name:value = '…']` · labels `["malicious-activity"]` |
| C2 IP | `indicator` · `[ipv4-addr:value = '…']` |
| Exfil URL | `indicator` · `[url:value = '…']` |
| The skill package itself | `malware` object (name = skill name, sample refs by SHA-256) |
| Correlation ("skill exfils to C2") | `relationship` · `exfiltrates-to` / `indicates` |

Bundle metadata: `created_by_identity = "SkillSentry 2.0"`, `confidence` from canary correlation (confirmed ⇒ 100). File: `reports/<scan_id>/stix-bundle.json`.

## 5.8 Error Model

```jsonc
{ "error": { "code": "sandbox_unavailable", "message": "Docker daemon not reachable",
             "stage": "sandbox", "degraded": true, "scan_id": "3f9c…" } }
```

| HTTP | `code` | Meaning / UI behavior |
|:--|:---|:---|
| 400 | `invalid_path` | Path missing, not a directory, or escapes allowed roots |
| 404 | `unknown_scan` / `no_skill_manifest` | Bad ID / no `SKILL.md` |
| 409 | `scan_in_progress` / `no_iocs` | Duplicate concurrent scan / STIX export without triggered defense |
| 422 | `schema_violation` | Request body fails Pydantic validation |
| 500 | `internal` | Unhandled; scan row marked `failed`, never silently `SAFE` |
| 503 | `model_unavailable` | Ollama down **and** cloud fallback disabled ⇒ UI offers `--demo-mode`; verdict may be produced from deterministic stages only, flagged `semantic-unavailable` |

**Fail-safe rule:** no error path may produce a `SAFE` verdict. Degraded scans complete with the stages that *did* run and carry explicit `note`-severity findings about what was skipped.

## 5.9 Mock-Server Contract (parallel frontend development)

Dev 3 ships a mock Ollama endpoint + canned Verdict JSON fixtures so Dev 1 never blocks on the real API:

- `python -m skill_sentry_cli.server.demo_mode --port 8000` serves every endpoint above from recorded fixture responses (the 7-fixture store, pre-baked Poisoned Well timeline, `invoice-helper` vision payload with bbox).
- Canned data is **schema-identical** to production — the frontend switches by base URL only.
- WS streams replay recorded events with realistic timing (including the heartbeat rule).

---

*Next: [06-ui-ux.md](06-ui-ux.md) — design language, screens, and interaction specs.*
