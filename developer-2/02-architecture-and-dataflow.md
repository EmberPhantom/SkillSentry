# 02 · Module Architecture & Data Flow

> **Subsystem:** Backend — Skill Analysis  
> **Author:** Developer 2 (Backend Engineer & Security Architect)  
> **Source-of-Truth References:** [docs/02-architecture.md](file:///d:/Skillsentry/SkillSentry/docs/02-architecture.md) · [docs/03-database.md](file:///d:/Skillsentry/SkillSentry/docs/03-database.md) · [docs/04-security.md](file:///d:/Skillsentry/SkillSentry/docs/04-security.md)

---

## 1. System Context & Pipeline Placement

The SkillSentry pipeline is an 8-stage pre-installation analysis engine. Users initiate scans directly from Windows PowerShell using documented CLI commands (`skillsentry scan <path>` or `python -m skillsentry.cli scan <path>`). Developer 2's components are responsible for entry input normalization, safe parsing, deterministic AST anchoring, multimodal vision scanning, caching layers (Stages 0, 1, 2, and 3), and generating **Dynamic Sandbox Action Instructions** (`SandboxActionInstruction`, Interface INT-4) along with normalized intent keywords (`declared_intent`) to drive Developer 1's Stage 4 Docker sandbox.

### 1.1 The 10-Step Windows PowerShell User Workflow
The end-to-end user experience on Windows systems progresses through ten coordinated operational steps:

1. **User Opens PowerShell**: The user opens Windows PowerShell (5.1 or 7.x Core) in a supported terminal (Windows Terminal, VS Code, or ConHost) with Python 3.11+ virtual environment active.
2. **User Invokes Scan**: The user runs the documented command interface:
   ```powershell
   skillsentry scan "C:\path\to\skill" --format text
   ```
3. **Target Specification**: The user specifies a target: a single skill folder, a parent directory of skills, or a relative/absolute/UNC path (including paths with spaces and quotes).
4. **Input Validation & Ingestion**: SkillSentry normalizes backslashes to POSIX slashes, verifies directory containment, validates frontmatter, and checks for reserved Windows DOS device names (`CON`, `PRN`, `AUX`, `NUL`).
5. **Static Analysis & Ingestion Pipeline**: Developer 2 executes Stage 0 (directory hash check) and Stage 1 (spec validation, package inventory, typosquatting analysis).
6. **Model Inference & Embedding Workflow**: On cache miss, Stage 2 executes deterministic AST/regex scanning (<100ms), followed by Gemma 4 semantic intent analysis and embedding generation/reuse; Stage 3 executes image contrast pre-filtering (<50ms) and vision OCR.
7. **Dynamic Sandbox Scheduling & Execution**: Developer 2 emits structured `SandboxActionInstruction` objects. Developer 1's orchestrator schedules and runs the isolated checks within the Stage 4 Docker sandbox container (canaries, DNS sinkhole, fake HTTP responder).
8. **Evidence Correlation & Verdict Fusion**: Developer 1's Stage 6 fusion engine correlates AST anchors, semantic findings, vision payloads, and sandbox canary/sinkhole telemetry into an integrated risk score (0–100) and SARIF 2.1.0 document.
9. **Assessment & Artifact Delivery**: The user receives a color-coded terminal assessment, detailed line-numbered findings, sandbox execution telemetry, and links to exported artifacts (e.g. SARIF report).
10. **Inspection, Remediation & Reproducibility**: The user reviews the findings, understands failures or degraded states, inspects C2 indicators, and can reproduce the scan deterministically (sub-2s cached response on identical input).

```mermaid
flowchart TD
    PS_USER["💻 User in Windows PowerShell<br/><code>skillsentry scan C:\path\to\skill</code>"] --> NORM["<b>Path Normalizer & Ingestion</b><br/>Windows path sanitization (C:\, backslashes, encoding)"]
    NORM --> PKG["📦 Untrusted Skill Package<br/>(SKILL.md + scripts/ + assets/)"]
    PKG --> S0

    subgraph D2_SCOPE_1["Developer 2 Analysis Scope: Front-End Stages"]
        S0["<b>Stage 0: Incremental Cache</b><br/>hash_utils.py + sqlite_store.py<br/>SHA-256 Dir Hash Check (<2s)"]
        S1["<b>Stage 1: Spec Validation & Typosquat</b><br/>skill_parser.py + typosquat.py<br/>Frontmatter checks + Levenshtein ≤ 2"]
        S2["<b>Stage 2: Deterministic Anchors & Semantic</b><br/>ast_anchor.py + analyzer.py + sandbox_instructions.py<br/>AST/Regex (<100ms) → Gemma 4 Text → Sbx Instructions"]
        S3["<b>Stage 3: Multimodal Vision Scan</b><br/>image_extractor.py + vision_scanner.py<br/>Contrast filter + Gemma Vision OCR + BBoxes"]
    end

    subgraph D1_SCOPE["Developer 1 Scope: Dynamic Sandbox & Verdict Stages"]
        S4["<b>Stage 4: Context-Aware Sandbox</b><br/>Docker Runner + Masquerade + Canary FS<br/>Executes SandboxActionInstructions (INT-4)"]
        S45["<b>Stage 4.5: ☠️ Poisoned Well</b><br/>Fake Creds + DNS/HTTP Sinkhole + Exfil Track"]
        S5["<b>Stage 5: Sandbox Evasion</b><br/>inotify on /.dockerenv, /proc/1/cgroup"]
        S6["<b>Stage 6: Verdict Engine</b><br/>Weighted Fusion + SARIF 2.1.0 Report"]
    end

    S0 -->|"Cache Hit (<2s)"| S6
    S0 -->|"Cache Miss"| S1
    S1 --> S2
    S2 --> S3
    S3 --> S4
    S4 --> S45
    S45 --> S5
    S5 --> S6

    S2 -.->|"Normalized declared_intent<br/>(aws, slack, github, ssh...)"| S4
    S2 -.->|"Dynamic Sandbox Instructions (INT-4)<br/>(trigger scripts, canary watch, dns sinkhole)"| S4
    S2 -.->|"Deterministic Anchors<br/>(Hard Ground Truth)"| S6
    S3 -.->|"Bounding Boxes & OCR<br/>for Gemma's Eye View"| UI["🖥️ Dev 3 UI Dashboard"]
    S6 -->|"SARIF Report + Console Output"| PS_USER
```

---

## 2. Subsystem Component Architecture

Developer 2's subsystem is organized into four core functional domains within `skillsentry/core/`:

```
skillsentry/core/
├── cache/                     # Content Hashing & SQLite Persistence
│   ├── hash_utils.py          # Deterministic directory SHA-256 hasher
│   └── sqlite_store.py        # SQLite repository (scan_cache & schema_meta, <2s budget)
├── parser/                    # Ingestion, Validation & Typosquatting
│   ├── skill_parser.py        # YAML frontmatter, path normalizer & inventory
│   └── typosquat.py           # Levenshtein distance & homoglyph analysis
├── semantic/                  # Code Anchoring & LLM Analysis
│   ├── ast_anchor.py          # Deterministic AST & regex scanner (<100ms)
│   ├── sandbox_instructions.py# Dynamic SandboxActionInstruction generator (INT-4)
│   ├── prompts.py             # Frozen structured prompt contracts
│   └── analyzer.py            # Gemma text analysis coordinator via I2
└── vision/                    # Multimodal Asset Analysis
    ├── image_extractor.py     # Image enumeration, downscaling & contrast filter
    └── vision_scanner.py      # Gemma Vision OCR & bounding-box extractor via I2
```

### 2.1 Detailed Component Interaction Diagram

```mermaid
graph TD
    subgraph Input_Layer["1. Input & Ingestion Layer (Windows PowerShell)"]
        PS["PowerShell CLI: skillsentry scan &lt;path&gt;"] --> NORM["Path Normalizer<br/>(C:\, backslashes, encoding)"]
        NORM --> HU["hash_utils.py<br/>(Canonical SHA-256)"]
        NORM --> SP["skill_parser.py<br/>(Safe Traversal & Frontmatter)"]
    end

    subgraph Cache_Layer["2. Caching Layer (Stage 0)"]
        HU -->|"content_hash"| SS["sqlite_store.py<br/>(scan_cache)"]
        SS -->|"Hit?"| RET["Return Cached SARIF & Verdict<br/>(&lt; 2 s)"]
    end

    subgraph Spec_Layer["3. Spec & Typosquat (Stage 1)"]
        SP -->|"Metadata & Files"| TQ["typosquat.py<br/>(Levenshtein ≤ 2 vs Dict)"]
        SP -->|"Parsed Package"| INV["Package Inventory<br/>(Scripts, Assets, Sizes)"]
    end

    subgraph Static_Layer["4. Deterministic Anchoring & Pre-Filter (Stage 2)"]
        INV -->|"Python Files"| AST["ast_anchor.py<br/>(Python AST Walk &lt;100ms)"]
        INV -->|"Shell / JS Files"| RGX["ast_anchor.py<br/>(Regex Line Scan &lt;100ms)"]
        AST & RGX -->|"Hard Facts"| ANCH["Anchor Findings List<br/>{file, line, pattern, code}"]
        ANCH --> SBX_GEN["sandbox_instructions.py<br/>(Derive Sandbox Action Checks)"]
    end

    subgraph Semantic_Layer["5. Semantic Analysis (Stage 2)"]
        ANCH -->|"Ground Truth"| PRM["prompts.py<br/>(Structured Prompt Template)"]
        INV -->|"Fenced Code"| PRM
        PRM -->|"Prompt Text"| ANZ["analyzer.py<br/>(I2 Client Caller)"]
        ANZ -->|"JSON Retry / Validate"| SEM_RES["Semantic Analysis Result<br/>(Intent, Contradictions, Keywords)"]
    end

    subgraph Vision_Layer["6. Multimodal Vision (Stage 3)"]
        INV -->|"Image Files"| EXT["image_extractor.py<br/>(Enumerate + Downscale 1024px)"]
        EXT -->|"Contrast Pre-Filter"| PRE_FLT["Luminance / White-on-White Check"]
        EXT -->|"Processed Images"| VIS["vision_scanner.py<br/>(I2 analyze_image)"]
        VIS -->|"BBox & OCR"| VIS_RES["Vision Findings & BBoxes<br/>(Gemma's Eye View Data)"]
        VIS_RES --> SBX_GEN
    end

    subgraph Downstream_Handoff["7. Integration & Sandbox Handoff"]
        SEM_RES -.->|"intent_keywords[]"| D1_HONE["Dev 1 Context Honeypot Seeder"]
        SBX_GEN -.->|"SandboxActionInstructions (INT-4)<br/>(Check Categories, Policies, Scripts)"| D1_SBX["Dev 1 Docker Sandbox Runner (Stage 4)"]
        TQ & ANCH & SEM_RES & VIS_RES -->|"StageResult Dataclasses (I3)"| D1_FUSE["Dev 1 Pipeline Fusion Engine"]
        VIS_RES -.->|"BBoxes & View Modes (INT-3)"| D3_UI["Dev 3 Vision Evidence View"]
    end
```

---

## 3. Data Flow & Execution Sequence

The operational lifecycle of a fresh, uncached skill package proceeding through Developer 2’s stages and downstream sandbox handoff is detailed in the sequence diagram below:

```mermaid
sequenceDiagram
    autonumber
    actor USER as 💻 User in Windows PowerShell
    participant CLI as Dev 1 CLI (`cli.py`)
    participant ORCH as Dev 1 Pipeline Orchestrator
    participant CH as cache/hash_utils
    participant CS as cache/sqlite_store
    participant PS as parser/skill_parser
    participant TQ as parser/typosquat
    participant AA as semantic/ast_anchor
    participant SBX_GEN as semantic/sandbox_instructions
    participant SA as semantic/analyzer
    participant VS as vision/vision_scanner
    participant I2 as Dev 1 Model Client (I2)
    participant SBX as Dev 1 Docker Sandbox (Stage 4)
    participant FUS as Dev 1 Fusion Engine

    USER->>CLI: skillsentry scan C:\Skills\custom-skill --format text
    CLI->>ORCH: initiate_scan(target_path, options)
    
    %% STAGE 0: CACHE
    ORCH->>CH: compute_directory_hash(skill_path)
    CH-->>ORCH: return content_hash (64 hex)
    
    ORCH->>CS: get_cached(content_hash, engine_v, model_v)
    alt Cache Hit (< 2 s)
        CS-->>ORCH: return (verdict_json, sarif_json)
        ORCH-->>CLI: emit cached verdict & SARIF
        CLI-->>USER: Render terminal assessment (<2s)
    else Cache Miss
        CS-->>ORCH: return None
        
        %% STAGE 1: SPEC & TYPOSQUAT
        ORCH->>PS: parse_package(skill_path)
        PS-->>ORCH: StageResult(stage='spec', findings, inventory)
        
        ORCH->>TQ: check_typosquat(skill_name)
        TQ-->>ORCH: StageResult(stage='typosquat', findings, bonus=+15)
        
        %% STAGE 2: AST ANCHORS & FAST PRE-FILTER
        ORCH->>AA: scan_anchors(inventory.scripts)
        AA-->>ORCH: StageResult(stage='deterministicAnchor', findings, anchors_text)
        
        %% STAGE 2: DYNAMIC SANDBOX INSTRUCTION GENERATION
        ORCH->>SBX_GEN: generate_sandbox_instructions(findings, declared_intent)
        SBX_GEN-->>ORCH: list[SandboxActionInstruction] (INT-4)
        
        %% STAGE 2: SEMANTIC ANALYSIS (GEMMA 4)
        ORCH->>SA: analyze_semantics(inventory, anchors_text, I2)
        SA->>I2: generate_json(system_prompt, user_content, schema)
        I2-->>SA: raw_json_dict
        SA-->>ORCH: StageResult(stage='semantic', intent_keywords, findings)
        
        %% STAGE 3: MULTIMODAL VISION
        alt Package Contains Images/SVGs
            ORCH->>VS: scan_visual_assets(inventory.assets, I2)
            VS->>I2: analyze_image(image_path, prompt)
            I2-->>VS: {ocr, bboxes, findings}
            VS-->>ORCH: StageResult(stage='vision', bboxes, findings)
            ORCH->>SBX_GEN: append_vision_sandbox_instructions(vision_findings)
        else No Assets Present
            ORCH-->>ORCH: emit StageResult(stage='vision', note='no-assets')
        end
        
        %% STAGES 4, 4.5, 5: DOWNSTREAM SANDBOX EXECUTION (DEV 1)
        ORCH->>SBX: execute_sandbox(package, intent_keywords, SandboxActionInstructions)
        SBX-->>ORCH: SandboxTrace(canary_events, net_logs, evasion_flags)
        
        %% STAGE 6: VERDICT FUSION & SARIF
        ORCH->>FUS: fuse_all_results(StageResults, SandboxTrace)
        FUS-->>ORCH: FinalVerdict(verdict, riskScore, SARIF)
        
        %% PERSIST TO CACHE
        ORCH->>CS: put(content_hash, verdict_json, sarif_json, ...)
        
        %% RETURN TO POWERSHELL USER
        ORCH-->>CLI: Return verdict, SARIF, and evidence
        CLI-->>USER: Render formatted terminal assessment & exit code (0/1/2/3)
    end
```

---

## 4. Trust Boundaries & The 5-Phase Sandbox Execution Boundary

Developer 2’s code operates directly on the **untrusted host boundary**. Because SkillSentry is explicitly built to inspect hostile, malicious, and adversarial packages, Developer 2's components must enforce defensive boundaries:

```
[ UNTRUSTED ZONE ]
  Public Registries (ClawHub), Malicious ZIP Archives, Untrusted Folders
  - Hostile SKILL.md (Prompt Injection payloads, instructions to the scanner)
  - Malicious Scripts (Path traversal ../../, bash bombs, eval bombs)
  - Adversarial Images (White-on-white text, stego payloads, oversized SVGs)
        │
        ▼  [ STRICT BOUNDARY CHECKS ]
  1. Safe Directory Walker (Rejects symlinks escaping root, skips .git/__pycache__)
  2. Strict Frontmatter Parser (Max 1024 char desc, BOM/UTF-8 sanitation, depth caps)
  3. Fenced Prompt Data Wrapping (Code wrapped as inert data: --- BEGIN SKILL DATA ---)
  4. AST Anchor Ground-Truth Invariance (Model forbidden from overriding AST facts)
  5. Image Normalization (Downscale to 1024px, PIL decompression bomb protection)
  6. Windows Path Normalization (C:\, backslashes, long-path protection)
        │
        ▼
[ TRUSTED ZONE ]
  Structured `StageResult` Dataclasses, `SandboxActionInstruction` list, SQLite `scan_cache`
```

### 4.1 The 5-Phase Sandbox Execution Boundary

A core architectural principle of SkillSentry is that **Developer 2 detects and instructs, but NEVER executes untrusted code**. The execution lifecycle is partitioned across five distinct phases:

| Phase | Designation | Responsible Subsystem | Concrete Action |
|:---:|:---|:---:|:---|
| **Phase 1** | **Analysis Output** | **Dev 2 (Skill Analysis)** | AST anchors, semantic analysis, and vision OCR detect suspicious patterns. Developer 2 emits findings and packages them into formal `SandboxActionInstruction` objects (target script, reason, check category, normalized intent, suggested limits). |
| **Phase 2** | **Execution Request** | **Dev 1 (Orchestrator)** | The pipeline orchestrator validates scan options (e.g., checks `--no-sandbox` toggle), verifies host prerequisites (Docker daemon status), evaluates policy, and schedules container execution. |
| **Phase 3** | **Sandbox Enforcement** | **Dev 1 (Sandbox Core)** | Docker container runner enforces strict isolation: non-root user, dropped Linux capabilities, 60s hard timeout, 512MB RAM cap, 1 CPU limit, masquerade layer (`/.dockerenv`), and isolated sinkhole network. |
| **Phase 4** | **Sandbox Evidence Collection** | **Dev 1 (Deception/Evasion)** | Kernel `inotify` watches canary paths; DNS sinkhole and fake HTTP responder capture exfiltration traffic; evasion detector watches system probes. Raw telemetry (`canary_events`, `sandbox_net_logs`) is recorded. |
| **Phase 5** | **Evidence Correlation & Verdict** | **Dev 1 (Fusion Engine)** | Fusion engine correlates Phase 4 telemetry with Phase 1 deterministic findings (e.g., matching canary token `SKS-7f3a` to DNS query) and computes the final risk score and SARIF report. |

### 4.2 Boundary Enforcement Rules
1. **Never Execute on Host**: Developer 2's code **never executes** scripts or binaries under audit. All inspection is strictly static (AST parsing, regex line scans, token analysis, image downscaling, vision OCR). Actual execution is quarantined to Developer 1's Docker sandbox in Stage 4. Untrusted code is never run in the PowerShell CLI process.
2. **Never Trust File Paths**: Paths reported in package metadata must be sanitized against path-traversal attacks (`../`, absolute paths, Windows drive letters, symlink redirections).
3. **Never Allow Injection from Scanned Text to Flip Decisions**: Analysis prompts treat all skill text as untrusted data wrapped in delimiters. Model outputs are strictly validated against a hard JSON schema.
4. **Anchor Invariance**: If AST regex detects an `os.system` call or `nslookup`, the model’s claim that *"this skill does not use network or shell"* is automatically flagged as a contradiction and discarded in favor of the anchor.
5. **Fail-Safe Sandbox Handoff**: If sandbox execution is disabled (`--no-sandbox`) or unavailable (Docker down), the orchestrator must flag the verdict as `sandbox-unavailable` (degraded). Developer 2's deterministic code anchors and semantic findings are still preserved in the report.

### 4.3 Sandbox Safety Controls & Isolation Architecture
The execution handoff from Developer 2 to Developer 1 enforces strict defense-in-depth safety controls within the sandbox execution environment:

1. **Host Isolation**: Untrusted skill packages run inside an ephemeral Linux Docker container under a dedicated unprivileged user (`uid=10001, gid=10001`). All Linux capabilities are dropped (`--cap-drop=ALL`), and privileges cannot be escalated (`--security-opt=no-new-privileges`). Root filesystem is mounted read-only (`--read-only`), with ephemeral `tmpfs` mounts for `/tmp` and isolated home directories.
2. **Resource Boundaries & Hard Timeouts**: Container execution is hard-capped at **512 MB RAM**, **1.0 vCPU core**, and a maximum runtime of **60 seconds** (`timeout_s: 60`). If a process hangs, loops infinitely, or attempts fork bombs, the container is forcibly terminated (`SIGKILL`) and recorded as a timeout finding.
3. **Network Isolation & Controlled Simulation**: Public egress to the internet is strictly blocked. All outbound network traffic is routed through an isolated internal bridge to Developer 1's **DNS Sinkhole** (listening on UDP/TCP port 53) and **Fake HTTP Responder** (listening on TCP ports 80 and 443).
4. **Canary Credential Files & Monitoring**: Ephemeral canary files seeded based on Developer 2's `contextual_intent` (e.g., `~/.aws/credentials`, `~/.ssh/id_rsa`, Slack tokens) contain unique tracking markers (`SKS-<hex8>`). Linux kernel `inotify` watches monitor file read attempts in real time.
5. **DNS Sinkhole & Fake HTTP Exfiltration Tracking**: Inbound DNS queries are inspected for Base64 or Hex encoded labels matching canary markers. HTTP POST requests are logged with headers and request payloads to capture exfiltration attempts.
6. **Poisoned Well Correlation & Ephemeral Teardown**: When an exfiltration attempt is confirmed, the sinkhole responds with deceptive secondary payloads to profile the C2 infrastructure. Upon completion of each sandbox check, the container is destroyed, volumes unmounted, and all ephemeral artifacts unlinked.
7. **Failure & Blocked States**: If a package is flagged for host traversal during Stage 1 spec validation, Developer 2 emits `check_status="blocked"` with descriptive `status_notes`, preventing the container from ever mounting or executing the package.

---

## 5. Performance Optimization Architecture & Resource Bounding

To achieve fast, responsive scans without compromising detection thoroughness:

1. **Sub-2-Second Incremental Cache**: Content-addressable SHA-256 caching guarantees instant scan retrieval for unchanged skill packages across runs. SQLite WAL mode provides high concurrency and sub-50ms hash-to-verdict turnaround.
2. **Cheap Deterministic Pre-Filtering**: Fast deterministic checks (AST walk and regex scanning in $<100$ ms; image luminance contrast pre-filter in $<50$ ms) execute before initiating expensive Gemma 4 text and vision inference.
3. **Elimination of Redundant Operations**: File parsing and package inventory are executed once during Stage 1 and shared in-memory via `PackageManifest` across all downstream stages (AST scanning, semantic prompt fencing, asset extraction, and Docker volume mounts).
4. **Embedding Generation, Batching & Reuse**:
   - When generating semantic embeddings for threat clustering, queries are batched in a single model call rather than per-sentence requests.
   - Embeddings are indexed by individual file content hash in SQLite (`scan_cache`), allowing partial reuse when only documentation or non-executable assets are modified.
5. **Bounded Concurrency**: CPU-bound AST scans, image downscaling, and model client queries execute within strict thread/process pool limits (`min(4, os.cpu_count())`) to prevent resource contention on developer laptops.
6. **Persistent Model Connections**: Model client protocol (I2) leverages persistent HTTP keep-alive connections to local Ollama (`localhost:11434`), avoiding per-scan model initialization latency.
7. **Thoroughness Invariance & Fail-Safe Accounting**:
   - Optimizations eliminate duplicate work and execution overhead, but **never omit required detection stages or bypass sandbox checks**.
   - Timeouts and model unavailability are surfaced honestly as degraded findings (`degraded: true`), never as a clean `SAFE` verdict.
   - Fast scan profiles (e.g. `--no-sandbox`) are explicitly documented in the report, preventing unverified claims of clean execution.
