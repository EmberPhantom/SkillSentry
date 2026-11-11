# 2 · Architecture

> System context, the 8-stage inspection pipeline, risk scoring, data flow, module map, tech stack, and integration contracts for **SkillSentry v2.0**.

---

## 2.1 Architectural Principles

| Principle | Consequence in the design |
|:---|:---|
| **Pre-install gate first** | All analysis happens *before* a skill touches the agent runtime. Runtime enforcement through an MCP proxy is planned, not implemented (section 2.10). |
| **Deterministic anchoring** | Static AST/regex facts are computed first and injected into every LLM prompt as ground truth; the LLM may elaborate but may not contradict them. |
| **Hard evidence overrides soft judgment** | Poisoned Well correlation and sandbox-evasion probes force `MALICIOUS` (`confidence: 1.0`) regardless of the fused score. |
| **Everything local** | Ollama (local model, Q4) + Docker + SQLite on one machine; cloud (Gemini API) is an explicit opt-in fallback. |
| **Contract-first** | The Verdict JSON schema is versioned (v1), and changes are additive. See [API reference](../reference/api.md). |
| **Fail-safe demo** | Every external dependency (network, Docker, model) has a degraded path: cloud fallback, `--demo-mode`, graceful UI error states. |

## 2.2 System Context

```mermaid
flowchart LR
    subgraph Threat_Actors["🏴‍☠️ Threat Actors"]
        A1["Compromised Dev Account"]
        A2["Typosquatter"]
        A3["Supply Chain Poisoner<br/>(benign → malicious update)"]
    end

    subgraph Registry["📦 Public Registry (ClawHub)"]
        R1["Malicious Skill Package"]
    end

    subgraph Local_Env["💻 Developer Local Environment"]
        L1["Agent IDE / CLI"] --> L2["SkillSentry<br/>Pre-Install Gate"]
        L2 -->|"✅ CLEAN"| L3["Agent Runtime"]
        L2 -->|"🚫 MALICIOUS"| L4["Block & Map C2"]
        L3 --> L5["MCP Tool Execution"]
        L5 --> L6["Local Filesystem / APIs"]
    end

    A1 --> R1
    A2 --> R1
    A3 --> R1
    R1 -->|"1. Download"| L1
    L1 -->|"2. Audit"| L2
```

SkillSentry sits between the registry/IDE and the agent runtime. Nothing installs without passing the gate; a `MALICIOUS` verdict blocks installation *and* produces an attacker profile (IOCs, exfil channel, C2).

## 2.3 The 8-Stage Inspection Pipeline

```mermaid
flowchart TD
    A["📦 Skill Package<br/>(SKILL.md + scripts/ + assets/)"] --> B

    subgraph S0["STAGE 0 · Incremental Cache"]
        B["SHA-256 Hash Check<br/>Hit? → Return cached SARIF (<2s)"]
    end
    B -->|"Cache Miss"| C

    subgraph S1["STAGE 1 · Spec Validation + Typosquat"]
        C["Parse frontmatter · name ·<br/>description 1–1024 chars · trigger keywords ·<br/>Levenshtein distance ≤ 2"]
    end
    C --> D

    subgraph S2["STAGE 2 · Deterministic Anchor + Semantic"]
        D["AST/Regex pre-scan → hard 'anchors'<br/>fed to the local model for text analysis"]
    end
    D --> E

    subgraph S3["STAGE 3 · Multimodal Scan — local vision model"]
        E["Bundled images → OCR hidden text ·<br/>white-on-white · stego instructions ·<br/>SVG: text + rendered scan"]
    end
    E --> F

    subgraph S4["STAGE 4 · Context-Aware Behavioral Sandbox"]
        F["Docker run: Masquerade · canary FS<br/>seeded per declared_intent · DNS sinkhole ·<br/>fake HTTP · 60s / 512MB / 1 CPU"]
    end
    F --> G

    subgraph S5["STAGE 4.5 · ☠️ POISONED WELL"]
        G["Canary read? → serve FAKE intent-matched<br/>secrets → fake HTTP 200 → track exfil → C2"]
    end
    G --> H

    subgraph S6["STAGE 5 · Sandbox Evasion Detection"]
        H["Probed /.dockerenv, /proc/1/cgroup,<br/>disk, VM artifacts? → auto-MALICIOUS"]
    end
    H --> I

    subgraph S7["STAGE 6 · Verdict Engine"]
        I["Fuse signals → risk 0–100 →<br/>SAFE/SUSPICIOUS/MALICIOUS →<br/>SARIF 2.1.0 + citations → cache to SQLite"]
    end
    I --> J["🖥️ Triage Dashboard"]
    I --> K["✅ Install / 🚫 Block"]
    I --> L["🛡️ Runtime guard hooks (MCP)"]
```

### Stage specifications

| Stage | Name | What it does | Key implementation | Failure/degraded mode |
|:--|:---|:---|:---|:---|
| **0** | Incremental Cache | SHA-256 hash of the skill directory; on hit, return the cached SARIF verdict instantly (< 2 s) | `hashlib` + SQLite (`scan_cache` table) | Hash mismatch on engine/model version ⇒ re-scan |
| **1** | Spec Validation + Typosquat | Enforce frontmatter rules (name; description 1–1024 chars with trigger keywords); Levenshtein distance ≤ 2 vs. known-skill names ⇒ typosquat flag (+15 risk bonus) | `python-frontmatter` + regex | Malformed package ⇒ `SUSPICIOUS` finding, pipeline continues |
| **2** | Deterministic Anchor + Semantic | AST/regex pre-scan (`eval()`, `subprocess…shell=True`, `os.system()`, `base64.b64decode()`, credential paths, network calls…) → anchors injected as ground truth into the the local model structured-JSON analysis | Python `ast` + regex → prompt template (§5.3 of plan) | Model unavailable ⇒ semantic stage degraded (fail closed; never SAFE from a missing model). Cloud is used only when opted in |
| **3** | Multimodal Vision Scan | Enumerate bundled images; local vision model OCR for hidden text (white-on-white, 4–6 px, stego-style); SVG scanned **as text and rendered**; at most 3 raster images per scan, each downscaled to 768 px (images beyond the budget ⇒ partial coverage, degraded); bounding boxes extracted for *Eye View* | Vision scanner pipeline | No images ⇒ stage skipped (logged as `no-assets`) |
| **4** | Context-Aware Behavioral Sandbox | Execute the skill in Docker (`skillsentry-sandbox:local`) with: masquerade layer, canary FS seeded from `declared_intent`, DNS sinkhole, fake HTTP responder; limits: 60 s timeout, 512 MB RAM, 1 CPU; egress restricted to the sinkhole network | Docker SDK; `LD_PRELOAD`; watchdog/inotify | Docker down ⇒ UI error state; verdict from static stages only, flagged `sandbox-unavailable` |
| **4.5** | ☠️ Poisoned Well | On canary-path read: serve intent-matched fake credentials (marker `SKS-<8hex>`); log all DNS queries + HTTP bodies; correlate marker (raw/base64/hex/subdomain labels); fake HTTP responds `200 OK` + secondary canary to keep multi-stage malware talking; build attacker profile | Canary gen + sinkhole correlation engine | No canary read ⇒ stage inert (no deception events) |
| **5** | Sandbox Evasion Detection | inotify on sensitive paths; detect probes for `/.dockerenv`, `/proc/1/cgroup`, disk checks (`df -h`), VM artifacts (`/proc/bus/input`); any probe ⇒ auto-`MALICIOUS`, `confidence: 1.0` | Masquerade hides artifacts so probes are observable and malware doesn't go dormant | Masquerade failure ⇒ treat as engine error, do **not** auto-pass |
| **6** | Verdict Engine | Weighted fusion of all signals → risk score 0–100 → verdict tier → SARIF 2.1.0 JSON + Markdown + STIX → persist to SQLite cache | Weights in §2.4 | Any stage error is a finding, never a silent pass |

### Stage 2 detail — Semantic prompt contract

The analyzer prompt (frozen template) is:

```text
SYSTEM: You are SkillSentry, a security auditor for AI Agent Skills.
Analyze the following skill package. Output STRICT JSON only.

DETERMINISTIC ANCHORS (ground truth — do NOT contradict these):
{AST_ANCHOR_FINDINGS}

JSON SCHEMA:
{
  "declared_intent": "what the description CLAIMS the skill does",
  "actual_capabilities": ["what the scripts/instructions ACTUALLY do"],
  "is_deceptive": boolean,
  "suspicious_patterns": [
    {"type": "exfil|injection|obfuscation|typosquat|evasion",
     "evidence": "exact quote", "file": "path", "line": N,
     "severity": "low|medium|high|critical"}
  ],
  "confidence": 0.0-1.0
}

Focus on contradictions between declared intent and actual behavior.
Use the deterministic anchors as confirmed facts.
```

The deterministic anchor scanner (`ast_anchor.py`) matches at minimum:

`eval(` · `subprocess.call(…shell=True)` · `os.system(` · `base64.b64decode(` · `exec(` · `__import__(` · `open(…credentials…)` · `open(…id_rsa…)` · `nslookup|dig|host` · `curl|wget|requests.post`

Each anchor carries `{file, line, pattern, description, code}` — this is what powers line-accurate citations.

### Stage 4/4.5 detail — Deception sequence

```mermaid
sequenceDiagram
    participant SK as Malicious Skill (in sandbox)
    participant CFS as Context Honeypot FS
    participant PW as Poisoned Well Engine
    participant DNS as DNS Sinkhole
    participant HTTP as Fake HTTP Responder

    Note over CFS: Intent detected: "Slack Integration"<br/>Seeding: SLACK_BOT_TOKEN, SLACK_WEBHOOK<br/>+ generic: ~/.aws/credentials, ~/.ssh/id_rsa

    SK->>CFS: read $SLACK_BOT_TOKEN
    CFS->>PW: 🚨 inotify: canary READ
    PW->>SK: serve fake token (xoxb-SKS-8b2c-fake)
    SK->>SK: encode token (base64)

    alt DNS exfiltration
        SK->>DNS: query c2.evil-collector.net
        DNS->>PW: log query + payload
        PW->>PW: 🔍 decode → MATCH marker "SKS-8b2c"
    else HTTP exfiltration
        SK->>HTTP: POST http://evil-c2.com/collect
        HTTP->>PW: log request body
        PW->>PW: 🔍 decode → MATCH marker "SKS-8b2c"
        PW->>HTTP: respond 200 OK + secondary canary
        Note over HTTP: The sinkhole does not intercept TLS; HTTPS traffic is not decoded
    end

    PW->>PW: Build Attacker Profile (targeted asset,<br/>channel, C2, encoding)
```

**Correlation rules:** Event A = inotify on a canary path (timestamp + path + process). Event B = any DNS query or HTTP request body logged by the sinkhole. If B occurs within N seconds of A **and** B's payload contains the marker (raw, base64, hex, or as subdomain labels), the correlation is *confirmed* ⇒ auto-`MALICIOUS`, `confidence: 1.0`.

**Context-aware canary set:**

| Declared intent | Canary seeded | Marker format |
|:---|:---|:---|
| AWS / Cloud | `~/.aws/credentials`, `AWS_SECRET_ACCESS_KEY` | `AKIA…SKS-<8hex>` |
| GitHub | `~/.config/gh/hosts.yml`, `GITHUB_TOKEN` | `ghp_SKS<8hex>` |
| Slack | `SLACK_BOT_TOKEN`, `SLACK_WEBHOOK_URL` | `xoxb-SKS-<8hex>` |
| SSH / DevOps | `~/.ssh/id_rsa`, `~/.ssh/config` | PEM comment `SKS-<8hex>` |
| Generic / unknown | All of the above + `~/.env`, `~/Documents/passwords.kdbx.txt` | Mixed markers |

## 2.4 Risk Scoring Model

```mermaid
flowchart LR
    subgraph Signals["Signal Sources"]
        S1sig["Static rules + AST Anchors — w 0.15"]
        S2sig["LLM semantic (anchored) — w 0.20"]
        S3sig["Vision findings — w 0.20"]
        S4sig["Sandbox telemetry — w 0.25"]
        S7sig["Typosquat — +15 bonus"]
        S5sig["Poisoned Well trigger — OVERRIDE"]
        S6sig["Sandbox Evasion Probe — OVERRIDE"]
    end
    S1sig --> FUSE["Weighted fusion"]
    S2sig --> FUSE
    S3sig --> FUSE
    S4sig --> FUSE
    S7sig --> FUSE
    S5sig -->|"confidence = 1.0"| OVERRIDE["Auto-MALICIOUS"]
    S6sig -->|"confidence = 1.0"| OVERRIDE
    FUSE --> SCORE["Risk score 0–100"]
    SCORE --> T1["✅ SAFE < 30"]
    SCORE --> T2["⚠️ SUSPICIOUS 30–70"]
    SCORE --> T3["🚫 MALICIOUS > 70"]
    OVERRIDE --> T3
```

**Fusion rule (implementation formula):** each signal source emits a normalized sub-score `sᵢ ∈ [0,100]`; the fused score is the weight-normalized sum plus the typosquat bonus, clamped to 100, then raised by explicit evidence floors:

```text
riskScore = min(100, round( Σ(wᵢ·sᵢ) / Σ(wᵢ) ) + typosquatBonus)
weights:  anchors 0.15 · semantic 0.20 · vision 0.20 · sandbox 0.25
bonus:    typosquat detected ⇒ +15 (and a 30/SUSPICIOUS evidence floor)
floors:   CRITICAL finding ⇒ ≥ 95 · HIGH ⇒ ≥ 70 · MEDIUM ⇒ ≥ 30
override: Poisoned Well correlation ⇒ MALICIOUS, riskScore ≥ 95
          evasion probe             ⇒ MALICIOUS, riskScore = 100
          both override confidence = 1.0
tiers:    SAFE < 30 ≤ SUSPICIOUS ≤ 70 < MALICIOUS
```

The evidence floors are **not weights**: a single critical deterministic or vision finding cannot be averaged below `MALICIOUS` by several clean-looking model scores. `FusionResult.evidence_floor` records the applied floor for auditing. A degraded stage still forces `SUSPICIOUS` at minimum and can never leave a scan `SAFE`.

**Design principle:** *LLM judgment + hard deterministic evidence = credible, not vibes.* Weights live in one config module so they are tunable and testable (see fixture-regression tests in [08-testing-and-evaluation.md](testing.md)).

## 2.5 Data Flow

```mermaid
flowchart TD
    subgraph Input
        PKG["Skill Package (directory)"]
    end
    subgraph Processing["SkillSentry Engine"]
        HASH["SHA-256 Hash"] --> CACHE_CHECK{"In SQLite?"}
        CACHE_CHECK -->|Yes| CACHED["Return cached verdict"]
        CACHE_CHECK -->|No| PARSE["Parse SKILL.md + scripts + assets"]
        PARSE --> AST["AST/Regex Anchor Scan"]
        AST --> LLM["Local model semantic analysis"]
        PARSE --> IMG["Image Extractor"]
        IMG --> VISION["local vision model OCR + Payload Detect"]
        PARSE --> SANDBOX["Docker Sandbox + Context Honeypots"]
        SANDBOX --> MONITOR["inotify + DNS Sinkhole + Fake HTTP"]
        MONITOR --> PW["☠️ Poisoned Well Correlation Engine"]
        LLM --> FUSION["Verdict Fusion"]
        VISION --> FUSION
        PW --> FUSION
        AST --> FUSION
    end
    subgraph Output
        FUSION --> SARIF["SARIF 2.1.0 JSON"]
        FUSION --> VERDICT["Verdict"]
        SARIF --> DASH["Triage Dashboard"]
        VERDICT --> DASH
        SARIF --> EXPORT["Export: SARIF / STIX / Markdown"]
    end
    PKG --> HASH
```

## 2.6 Module Map (Repository Structure)

```text
skill_sentry_cli/
 ├── LICENSE                          # MIT
 ├── README.md                        # GIF → problem → arch → run → eval
 ├── SECURITY.md
 ├── pyproject.toml
 ├── skill_sentry_cli/
 │   ├── cli.py                       # `skill-sentry-cli scan ./skill-folder`
 │   ├── core/
 │   │   ├── cache/
 │   │   │   ├── sqlite_store.py      # SHA-256 hash → cached verdict
 │   │   │   └── hash_utils.py        # Directory hashing
 │   │   ├── parser/
 │   │   │   ├── skill_parser.py      # SKILL.md + frontmatter parser
 │   │   │   └── typosquat.py         # Levenshtein vs known-skill names
 │   │   ├── semantic/
 │   │   │   ├── ast_anchor.py        # Deterministic regex/AST pre-scan
 │   │   │   ├── analyzer.py          # local model text analysis orchestrator
 │   │   │   └── prompts.py           # Structured-output prompt templates
 │   │   ├── vision/
 │   │   │   ├── image_extractor.py   # Find images in skill bundle
 │   │   │   └── vision_scanner.py    # local model vision OCR + payload detect
 │   │   ├── sandbox/
 │   │   │   ├── runner.py            # Docker lifecycle + Masquerade
 │   │   │   ├── masquerade.py        # Hide Docker artifacts
 │   │   │   ├── context_honeypot.py  # Intent-aware canary seeding
 │   │   │   ├── canary_fs.py         # Honeypot file seeding
 │   │   │   ├── dns_sinkhole.py      # Fake resolver + query logger
 │   │   │   ├── fake_http.py         # Fake HTTP 200 OK responder
 │   │   │   └── monitor.py           # inotify + env-var read tracker
 │   │   ├── poisoned_well/
 │   │   │   ├── canary_gen.py        # Dynamic fake secrets (intent-aware)
 │   │   │   ├── exfil_tracker.py     # Match canary markers in traffic
 │   │   │   └── attacker_profile.py  # C2 IOC builder + STIX export
 │   │   ├── evasion/
 │   │   │   └── detector.py          # Sandbox probe detection
 │   │   ├── verdict/
 │   │   │   ├── fusion.py            # Weighted signal fusion → score
 │   │   │   └── sarif_report.py      # SARIF 2.1.0 JSON + markdown
 │   │   └── models/
 │   │       ├── gemma_local.py       # Ollama client
 │   │       └── gemma_cloud.py       # Gemini API client (fallback)
 │   ├── server/
 │   │   ├── app.py                   # FastAPI + WebSocket scan stream
 │   │   ├── routes.py
 │   │   └── demo_mode.py             # --demo-mode canned responses
 │   └── skill/                       # SkillSentry's OWN Agent Skill
 │       ├── SKILL.md
 │       └── scripts/audit.sh
 ├── ui/                              # React app (see 06-ui-ux.md)
 ├── fixtures/
 │   ├── benign/                      # 4 skills
 │   └── malicious/                   # 2 skills + typosquat + evasion
 └── tests/
```

**Module areas** are listed in [CONTRIBUTING.md](../../CONTRIBUTING.md).

## 2.7 Technology Stack & Rationale

| Layer | Choice | Rationale |
|:---|:---|:---|
| Core language | **Python 3.11+** | Docker SDK, inotify/watchdog, SARIF, FastAPI ecosystem |
| Local model | **a local model via Ollama (Q4)** | Laptop-feasible; latency tested night before; images downscaled if slow |
| Cloud fallback | **Gemini API** | Opt-in only; off by default |
| Caching | **SQLite + `hashlib` (SHA-256)** | Instant < 2 s scans for unchanged skills |
| Sandbox | **Docker** (`skillsentry-sandbox:local` base) | Portable, demonstrable, simple |
| Evasion defense | **`LD_PRELOAD` hooks / fake `/proc`** | Hides Docker artifacts from probing malware |
| DNS interception | **Sinkhole resolver** in-container (all DNS → local logger on :53) | Catches exfil-by-DNS; no iptables complexity |
| HTTP interception | **Fake HTTP responder** | Returns 200 OK; catches direct-IP exfil. TLS is not intercepted. |
| Egress control | Docker `--network` restricted to sinkhole only | **Hard guarantee nothing escapes** |
| API server | **FastAPI + WebSocket** | Live scan streaming for a reactive UI |
| Frontend | **React 18 + Vite + TypeScript** | Small, dependency-light dashboard |
| Report format | **SARIF 2.1.0-style JSON + Markdown + STIX** | Instant credibility with technical audiences |
| Packaging | `pipx` / `pip install skill-sentry-cli`, the install script, and the server image | GitHub Action is planned, not available |

### Model backends

```mermaid
flowchart LR
    AN["Analyzer / Vision Scanner"] --> SEL{"Backend selector"}
    SEL -->|"default"| OL["Ollama · local model (Q4)<br/>localhost:11434 · 100% local"]
    SEL -->|"opt-in / local down"| GC["Gemini API<br/>(gemma_cloud.py)"]
    SEL -->|"demo / both down"| DM["demo_mode.py<br/>canned responses"]
```

Selection order: **local → cloud (if enabled) → demo-mode (if requested)**. The active backend is recorded with every cached verdict so cache entries are invalidated when the model changes (see [03-database.md](database.md)).

## 2.8 Performance Budget

| Operation | Target |
|:---|:---|
| Cached re-scan (Stage 0 hit) | **< 2 s** end-to-end |
| Full uncached scan, local E4B Q4 | **< 90 s** per skill |
| Sandbox execution window | 60 s hard timeout (512 MB RAM, 1 CPU) |
| Vision preprocessing | Downscale to 768 px before inference; at most 3 images per scan |
| WebSocket stage events | Streamed per stage so the UI shows motion even during slow LLM calls |

## 2.9 Integration contracts

| Contract | Producer | Consumer | Format |
|:---|:---|:---|:---|
| `POST /scan` → `scan_id` | Dashboard, CLI | Server | JSON |
| `WS /scan/{id}/stream` | Server | Dashboard live console | `{stage, skill, event, ts}` |
| Verdict object | Verdict engine | Dashboard, reports, API | **JSON schema v1** ([API reference](../reference/api.md)) |
| SARIF report | Verdict engine | Code-scanning tools | SARIF 2.1.0 |
| Model client | Analysis stages | Local model server (or cloud, if enabled) | Structured JSON responses |
| Demo store | Demo mode | Dashboard and API tests | Schema-identical canned responses |

**Rule:** the verdict schema is versioned, and changes are additive only. Contract tests run against both the live API and the demo server, so the two cannot drift.

## 2.10 Planned: MCP runtime interception

> **Not implemented.** This section describes a proposal.

Pre-install auditing catches static threats; runtime interception catches **dynamic privilege escalation** ("you were approved to read files, but you just tried to open a network socket ⇒ **Blocked**").

```mermaid
flowchart LR
    Agent["🤖 AI Agent"] -->|"Tool Call"| MCP["SkillSentry MCP Proxy"]
    MCP -->|"Intercept & Verify"| Policy["Runtime Policy Engine"]
    Policy -->|"✅ Allowed"| Sandbox["Sandboxed Execution"]
    Policy -->|"🚫 Blocked"| Agent
    Sandbox -->|"Result"| Agent

    subgraph Runtime_Guards
        RG1["Permission check: file read vs network"]
        RG2["Resource limits: CPU, memory, time"]
        RG3["Behavioral drift: declared vs actual"]
    end
    Policy --> RG1
    Policy --> RG2
    Policy --> RG3
```

The MCP proxy reuses the pre-install verdict as the *baseline policy* for a skill (declared intent, allowed capabilities) and enforces drift detection at tool-call time. Deployment details: [09-deployment-and-production.md](../operations/deployment.md) §Phase 2.

---

*Next: [03-database.md](database.md) — persistence, caching, and IOC storage.*
