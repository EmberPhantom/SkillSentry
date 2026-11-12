# 5 · API reference

The HTTP and WebSocket API that `skill-sentry-cli serve` exposes. The dashboard uses it, and so can your own tools. Section numbers are kept stable, because the code refers to them.

## 5.1 Conventions

| Item | Value |
|:---|:---|
| Base URL | `http://127.0.0.1:8000` (the default for `serve`) |
| Content type | `application/json` (UTF-8) |
| Response field names | camelCase, for example `scanId` and `riskScore` |
| Request field names | snake_case, for example `no_cache` and `timeout_s` |
| Timestamps | ISO-8601, UTC |
| Identifiers | UUIDs, for scans and skills |
| Authentication | **None.** The server is meant for loopback use only. Keep the default `--host 127.0.0.1`. See the [security model](../developer/security.md) §4.11. |
| Host check | Requests whose `Host` is not loopback or the bind address get `400 untrusted_host`, on every endpoint. An `Origin` header on a WebSocket handshake, or on a `POST`, `PUT`, `PATCH` or `DELETE`, must be the server's own origin (same scheme, host and port as `Host`) or a dev origin such as `http://localhost:5173`. Otherwise the request is refused with `400 untrusted_host` (WebSocket: closed with 1008). A `null` origin is refused. Requests without an `Origin` header (curl, the CLI) and `GET` requests are not affected. Add names with `SKILLSENTRY_ALLOWED_HOSTS`. |
| Contract version | Reported as `contractVersion` by `GET /meta`. The verdict contract is `v1`. Changes are additive. |
| Demo mode | `serve --demo-mode` serves canned data with the same schemas. No Docker or model is needed. |

## 5.2 REST endpoints

| Method and path | Purpose | Success | Errors |
|:---|:---|:---|:---|
| `POST /scan` | Start a scan | `202` | `400` `untrusted_host`, `403` `path_not_allowed`, `404` no `SKILL.md`, `409` `scan_in_progress`, `422` `missing_path`, `invalid_skill`, or `folder_of_skills` |
| `GET /scans` | List scans, newest first | `200` | |
| `GET /scan/{scan_id}` | Status of one scan | `200` | `404` unknown scan |
| `GET /scan/{scan_id}/verdicts` | Verdicts of one scan | `200` | `404` unknown scan, `409` still running, `500` failed |
| `GET /skills/{skill_id}` | Full detail for a skill | `200` | `404` unknown skill |
| `GET /skills/{skill_id}/export?format=` | Report for a skill | `200` (file) | `404` unknown skill, `409` STIX requested without indicators |
| `GET /cache/stats` | Cache statistics | `200` | |
| `DELETE /cache?older_than=` | Remove cached verdicts | `200` | `422` invalid duration |
| `GET /health` | Dependency health | `200` | |
| `GET /meta` | Server metadata | `200` | |
| `WS /scan/{scan_id}/stream` | Live events for one scan | (§5.3) | |

### `POST /scan`: start a scan

Request:

```json
{
  "path": "/absolute/path/to/skill-folder",
  "options": {
    "no_cache": false,
    "backend": "auto",
    "sandbox": true,
    "poisoned_well": true,
    "timeout_s": 60
  }
}
```

- `path` is the skill folder. It must contain `SKILL.md`. A missing or empty path gives `422 missing_path`. A path that does not exist gives `404 no_skill_manifest`. A path that is not a directory gives `422 invalid_skill`.
- `options` is optional. `backend` is `auto`, `local`, `cloud`, or `demo`. Set `sandbox` to `false` to skip the sandbox; the verdict then relies on the static stages only.
- A folder whose child folders are skills gives `422 folder_of_skills`, and the message names them. Scan each one with its own request.
- If the operator set `[server] allowed_scan_roots` (or `SKILLSENTRY_ALLOWED_SCAN_ROOTS`), the path must resolve inside one of those folders. Symlinks are followed, so `..` and a link that points outside are refused. Otherwise the request gets `403 path_not_allowed`. The check runs before the existence check, so a refused path gets the same answer whether or not it exists, and the message does not repeat the path. With no roots set, any folder is allowed, as before.
- A second scan of the same folder while one is running gives `409 scan_in_progress`. The `scanId` of the running scan is in the error body.

Response, status `202`:

```json
{
  "scanId": "3f9c2a1e-0000-4000-8000-000000000001",
  "status": "queued",
  "stream": "/scan/3f9c2a1e-0000-4000-8000-000000000001/stream"
}
```

### `GET /scans`: list scans

Newest first. Query parameters: `limit` (1 to 1000, default 100), `offset` (default 0), and `status` (optional; one of the values listed under `GET /scan/{scan_id}`). The list reads the scan history database. A scan appears once its history row is written, which happens when the scan starts; a request that is accepted but not yet started does not appear. A running scan is listed with status `running`.

Response: `{"scans": [...]}`. Each entry is a summary with `scanId`, `skillId`, `skill`, `verdict`, `riskScore`, `cached`, `status`, `startedAt`, `durationMs`, and `keyFinding`. `verdict` and `riskScore` are empty while the scan runs. Use `GET /scan/{scan_id}` for the live status of one scan, and `GET /scan/{scan_id}/verdicts` for the full verdicts.

### `GET /scan/{scan_id}`: status

```json
{
  "scanId": "3f9c2a1e-0000-4000-8000-000000000001",
  "status": "running",
  "stage": "sandbox",
  "skill": "cloud-sync-pro",
  "startedAt": "2026-10-21T09:31:07.412Z",
  "elapsedMs": 41233,
  "error": null
}
```

`status` is one of `queued`, `running`, `completed`, `failed`, or `cached-hit`. `stage` is the current stage (§5.4). `error` is set when `status` is `failed`.

### `GET /scan/{scan_id}/verdicts`: verdicts

```json
{
  "scanId": "3f9c2a1e-0000-4000-8000-000000000001",
  "verdicts": [ { "...": "one verdict object per skill, §5.5" } ]
}
```

A single-skill scan returns one verdict. A folder scan returns one per skill.

### `GET /skills/{skill_id}`: detail

Returns the verdict object (`verdict`) together with the data for each dashboard tab:

| Field | Contents |
|:---|:---|
| `verdict` | The verdict object (§5.5). Required. |
| `staticFindings` | Findings from code analysis, with the source lines. |
| `visionEvidence` | Images checked, with text found and bounding boxes. |
| `sandboxTrace` | Canary reads and network events seen during the sandbox run. |
| `poisonedWell` | Decoy credential activity and the indicators it produced. |
| `reportLinks` | Links to the report in each format. |

### `GET /skills/{skill_id}/export?format=sarif|markdown|stix`

Returns the report as a file attachment, rendered from the stored result when you ask for it. Nothing is written to disk on the server. `format` is required.

- `sarif`: SARIF 2.1.0 (§5.6).
- `markdown`: a human-readable report.
- `stix`: a STIX 2.1 bundle (§5.7). It needs at least one indicator, otherwise the response is `409 no_iocs`.

### `GET /cache/stats`

```json
{
  "entries": 42,
  "hitRate": 0.37,
  "dbSizeBytes": 1048576,
  "engineVersion": "2.1.0+ab12cd34",
  "modelVersion": "example-model@sha256:…"
}
```

### `DELETE /cache?older_than=`

`older_than` is a number and a unit, for example `7d` or `12h`. Units are `s`, `m`, `h`, `d`, and `w`. Without it, all entries are removed. The response reports `deleted` and `retained`.

### `GET /health`

```json
{ "ollama": "ok", "docker": "down", "db": "ok", "demoMode": false }
```

Each dependency is `ok` or `down`. The dashboard uses this to show that some stages are unavailable. A `down` status does not mean a scan will succeed.

### `GET /meta`

```json
{
  "version": "2.1.0",
  "backendActive": "local",
  "gemmaBadge": "Fully local analysis · open weights",
  "demoMode": false,
  "contractVersion": "1"
}
```

`gemmaBadge` is the name of the field. Its value follows the active analysis backend, and it is the same text the CLI banner prints for that backend:

- `local` and `mock`/`demo`: `Fully local analysis · open weights`.
- Cloud (Gemini API): `Cloud analysis · code excerpts sent to the Gemini API`. Code excerpts leave the machine.
- `auto` before a model is selected, or no backend available: `Analysis backend unknown`.

The field name does not say which model is in use. Use `backendActive` for the backend identity.

## 5.3 WebSocket: `WS /scan/{scan_id}/stream`

The server sends events as the scan runs. Each message has this shape:

```json
{
  "stage": "sandbox",
  "skill": "cloud-sync-pro",
  "event": "progress",
  "ts": "2026-10-21T09:31:07.412Z",
  "detail": {}
}
```

**Events:** `started`, `progress`, `finding`, `override`, `completed`, `error`, and `cached`.

- `cached`: the verdict came from the cache. No stages run.
- `override`: a hard-evidence rule decided the result, such as a decoy credential in outbound traffic or a sandbox-detection probe.
- `completed`: the scan finished. The final verdict is available from `GET /scan/{scan_id}/verdicts`.
- `error`: a stage or the scan failed. `detail` holds `code`, `message`, and `degraded`.
- `progress` with `detail.heartbeat` set to `true`: sent every 20 seconds while a long step runs, so a client can tell the scan is still alive.

**Client messages.** The only client message the server acts on is `{"op": "cancel"}`, which stops the scan. The scan is recorded as failed at once, and the server sends an `error` event whose `detail.code` is `cancelled`. Closing the socket does not stop the scan.

Payloads other than `error` and the heartbeat are stage-specific. Treat them as informational, and rely on the verdict for results.

## 5.4 Pipeline stage identifiers

These exact strings appear in events, in `stage` fields, and in findings:

`cache` · `spec` · `typosquat` · `deterministicAnchor` · `semantic` · `vision` · `sandbox` · `poisonedWell` · `evasion` · `verdict`

## 5.5 Verdict JSON contract v1 (frozen)

The verdict object is the one shape shared by the engine, the API, the cache, and the reports. The JSON Schema is generated from the code and committed in `schemas/verdict.v1.json`. CI fails if the two drift apart.

```json
{
  "scanId": "3f9c2a1e-0000-4000-8000-000000000001",
  "skillId": "8b1d4e62-0000-4000-8000-000000000002",
  "skill": "cloud-sync-pro",
  "verdict": "MALICIOUS",
  "riskScore": 97,
  "confidence": 1.0,
  "cached": false,
  "scanDurationMs": 87432,
  "findings": [
    {
      "stage": "deterministicAnchor",
      "severity": "high",
      "message": "Reads the AWS credentials file",
      "evidence": { "file": "scripts/sync.sh", "line": 4 }
    }
  ],
  "activeDefense": {
    "triggered": true,
    "targetedAssets": ["~/.aws/credentials"],
    "exfilChannel": "DNS_TUNNELING",
    "canaryMarker": "SKS-7f3a9c21",
    "c2Indicators": ["evil-collector.net"],
    "encoding": "base64",
    "sandboxEvasionDetected": false,
    "declaredIntent": "Cloud file synchronization",
    "contextAwareCanary": "AWS"
  }
}
```

| Field | Notes |
|:---|:---|
| `verdict` | `SAFE` below 30, `SUSPICIOUS` from 30 to 70, `MALICIOUS` above 70. An override sets `MALICIOUS` with `confidence` 1.0. |
| `riskScore` | An integer from 0 to 100. |
| `confidence` | From 0.0 to 1.0. |
| `findings[].severity` | `low`, `medium`, `high`, `critical`, or `note`. |
| `findings[].evidence` | The file and line of the evidence, where there is one. A Poisoned Well finding can instead cite the destination and marker. |
| `findings[].type` | Optional. Used in the SARIF rule ID. |
| `activeDefense` | Optional. Present when Poisoned Well ran. Readers must accept it as absent or null. `triggered` is `false` when no decoy was seen. |

**Compatibility.** Changes to this contract are additive: new optional fields only. A breaking change needs a new contract version and a migration path.

## 5.6 SARIF 2.1.0 mapping

- Each finding becomes one SARIF `result`. Its `ruleId` is `skillsentry/<stage>/<type>`.
- Severity maps to SARIF level: `critical` and `high` become `error`, `medium` becomes `warning`, and `low` and `note` become `note`.
- The verdict's `verdict`, `riskScore`, `confidence`, and `cached` appear under the run's properties.
- The Poisoned Well block appears under the run's `activeDefense` property.

Upload to GitHub code scanning with the usual `github/codeql-action/upload-sarif` action. SkillSentry does not upload anything itself; a GitHub Action for this is planned.

## 5.7 STIX 2.1 mapping

The STIX bundle is built from the Poisoned Well indicators of one scan. It is available only when that scan has indicators.

| Indicator | STIX object |
|:---|:---|
| C2 domain | `indicator` with a `domain-name` pattern |
| C2 IP address | `indicator` with an `ipv4-addr` pattern |
| Exfiltration URL | `indicator` with a `url` pattern |
| The skill | `malware`, named after the skill |
| Link between skill and indicator | `relationship` of type `indicates` |

The bundle's identity is `SkillSentry <version>`, the running release. Indicators have a confidence of `100` when the decoy was seen, and `50` otherwise.

## 5.8 Error model

Errors that SkillSentry raises use one envelope:

```json
{
  "error": {
    "code": "unknown_scan",
    "message": "unknown scan: 3f9c2a1e-0000-4000-8000-000000000001",
    "stage": null,
    "degraded": false,
    "scan_id": null
  }
}
```

| Status | Codes | When |
|:---|:---|:---|
| `404` | `unknown_scan` | No scan or skill with that ID. |
| `403` | `path_not_allowed` | The server has `allowed_scan_roots` set and the path does not resolve inside one of them. The same answer is given whether or not the path exists. |
| `404` | `no_skill_manifest` | The path does not exist, or has no `SKILL.md`. |
| `409` | `scan_in_progress` | The folder is already being scanned, or the scan has not finished. |
| `409` | `no_iocs` | STIX export for a scan with no indicators. |
| `422` | `missing_path` | No path was given to `POST /scan`. |
| `422` | `invalid_skill` | The path is not a directory. |
| `422` | `invalid_duration` | `older_than` could not be read. |
| `500` | `scan_failed` | The scan failed. |
| `500` | `internal_error` | An unexpected error. The scan is marked failed, never `SAFE`. |

Requests that fail schema validation (wrong types, a missing body) get FastAPI's standard validation response with status `422`. That response is not in the envelope above.

**Fail-safe rule.** No error path may produce a `SAFE` verdict. A degraded scan completes with the stages that did run, and it carries a finding that says what was skipped.

## 5.9 Demo mode

`skill-sentry-cli serve --demo-mode --port 8000` serves every endpoint in §5.2 from canned data for seven demo skills. The responses use the same schemas as live output, so a client needs only a different base URL to switch between them. The WebSocket stream replays recorded events.

Demo mode is for trying the dashboard and building clients. It does not analyse anything.

---

*Next: [dashboard design](../developer/ui-design.md).*
