# 02 · Module Architecture & Data Flow

> **Subsystem:** Backend — Skill Analysis  
> **Author:** Developer 2 (Backend Engineer & Security Architect)  
> **Source-of-Truth References:** [docs/02-architecture.md](file:///d:/Skillsentry/SkillSentry/docs/02-architecture.md) · [docs/03-database.md](file:///d:/Skillsentry/SkillSentry/docs/03-database.md) · [docs/04-security.md](file:///d:/Skillsentry/SkillSentry/docs/04-security.md)

---

## 1. System Context & Pipeline Placement

The SkillSentry pipeline is an 8-stage pre-installation analysis engine. Developer 2's components are responsible for the entry, parsing, deterministic anchoring, multimodal scanning, and caching layers (Stages 0, 1, 2, and 3), while also supplying critical baseline data (`declared_intent`) to Developer 1's sandbox honeypots (Stage 4) and evidence records to Developer 3's UI.

```mermaid
flowchart TD
    PKG["📦 Untrusted Skill Package<br/>(SKILL.md + scripts/ + assets/)"] --> S0

    subgraph D2_SCOPE_1["Developer 2 Analysis Scope: Front-End Stages"]
        S0["<b>Stage 0: Incremental Cache</b><br/>hash_utils.py + sqlite_store.py<br/>SHA-256 Dir Hash Check"]
        S1["<b>Stage 1: Spec Validation & Typosquat</b><br/>skill_parser.py + typosquat.py<br/>Frontmatter checks + Levenshtein ≤ 2"]
        S2["<b>Stage 2: Deterministic Anchors & Semantic</b><br/>ast_anchor.py + analyzer.py + prompts.py<br/>Python AST + Regex → Anchors → Gemma 4"]
        S3["<b>Stage 3: Multimodal Vision Scan</b><br/>image_extractor.py + vision_scanner.py<br/>Contrast filter + Gemma Vision OCR + BBoxes"]
    end

    subgraph D1_SCOPE["Developer 1 Scope: Dynamic & Verdict Stages"]
        S4["<b>Stage 4: Context-Aware Sandbox</b><br/>Docker Runner + Masquerade + Canary FS"]
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
    S2 -.->|"Deterministic Anchors<br/>(Hard Ground Truth)"| S6
    S3 -.->|"Bounding Boxes & OCR<br/>for Gemma's Eye View"| UI["🖥️ Dev 3 UI Dashboard"]
```

---

## 2. Subsystem Component Architecture

Developer 2's subsystem is organized into four core functional domains within `skillsentry/core/`:

```
skillsentry/core/
├── cache/                     # Content Hashing & SQLite Persistence
│   ├── hash_utils.py          # Deterministic directory SHA-256 hasher
│   └── sqlite_store.py        # SQLite repository (scan_cache & schema_meta)
├── parser/                    # Ingestion, Validation & Typosquatting
│   ├── skill_parser.py        # YAML frontmatter & filesystem inventory
│   └── typosquat.py           # Levenshtein distance & homoglyph analysis
├── semantic/                  # Code Anchoring & LLM Analysis
│   ├── ast_anchor.py          # Deterministic AST & regex scanner
│   ├── prompts.py             # Frozen structured prompt contracts
│   └── analyzer.py            # Gemma text analysis coordinator via I2
└── vision/                    # Multimodal Asset Analysis
    ├── image_extractor.py     # Image enumeration, downscaling & contrast filter
    └── vision_scanner.py      # Gemma Vision OCR & bounding-box extractor via I2
```

### 2.1 Detailed Component Interaction Diagram

```mermaid
graph TD
    subgraph Input_Layer["1. Input & Ingestion Layer"]
        DIR["Target Directory"] --> HU["hash_utils.py<br/>(Canonical SHA-256)"]
        DIR --> SP["skill_parser.py<br/>(Safe Traversal & Frontmatter)"]
    end

    subgraph Cache_Layer["2. Caching Layer (Stage 0)"]
        HU -->|"content_hash"| SS["sqlite_store.py<br/>(scan_cache)"]
        SS -->|"Hit?"| RET["Return Cached SARIF<br/>(< 2 s)"]
    end

    subgraph Spec_Layer["3. Spec & Typosquat (Stage 1)"]
        SP -->|"Metadata & Files"| TQ["typosquat.py<br/>(Levenshtein ≤ 2 vs Dict)"]
        SP -->|"Parsed Package"| INV["Package Inventory<br/>(Scripts, Assets, Sizes)"]
    end

    subgraph Static_Layer["4. Deterministic Anchoring (Stage 2)"]
        INV -->|"Python Files"| AST["ast_anchor.py<br/>(Python AST Walk)"]
        INV -->|"Shell / JS Files"| RGX["ast_anchor.py<br/>(Regex Line Scan)"]
        AST & RGX -->|"Hard Facts"| ANCH["Anchor Findings List<br/>{file, line, pattern, code}"]
    end

    subgraph Semantic_Layer["5. Semantic Analysis (Stage 2)"]
        ANCH -->|"Ground Truth"| PRM["prompts.py<br/>(Structured Prompt Template)"]
        INV -->|"Fenced Code"| PRM
        PRM -->|"Prompt Text"| ANZ["analyzer.py<br/>(I2 Client Caller)"]
        ANZ -->|"JSON Retry / Validate"| SEM_RES["Semantic Analysis Result<br/>(Intent, Contradictions, Keywords)"]
    end

    subgraph Vision_Layer["6. Multimodal Vision (Stage 3)"]
        INV -->|"Image Files"| EXT["image_extractor.py<br/>(Enumerate + Downscale 1024px)"]
        EXT -->|"Contrast Filter"| PRE_FLT["Luminance / White-on-White Check"]
        EXT -->|"Processed Images"| VIS["vision_scanner.py<br/>(I2 analyze_image)"]
        VIS -->|"BBox & OCR"| VIS_RES["Vision Findings & BBoxes<br/>(Gemma's Eye View Data)"]
    end

    subgraph Downstream_Handoff["7. Integration & Handoff"]
        SEM_RES -.->|"intent_keywords[]"| D1_HONE["Dev 1 Context Honeypot Seeder"]
        TQ & ANCH & SEM_RES & VIS_RES -->|"StageResult Dataclasses (I3)"| D1_FUSE["Dev 1 Pipeline Fusion Engine"]
        VIS_RES -.->|"BBoxes & View Modes"| D3_UI["Dev 3 Vision Evidence View"]
    end
```

---

## 3. Data Flow & Execution Sequence

The operational lifecycle of a fresh, uncached skill package proceeding through Developer 2’s stages is detailed in the sequence diagram below:

```mermaid
sequenceDiagram
    autonumber
    actor ORCH as Dev 1 Orchestrator
    participant CH as cache/hash_utils
    participant CS as cache/sqlite_store
    participant PS as parser/skill_parser
    participant TQ as parser/typosquat
    participant AA as semantic/ast_anchor
    participant SA as semantic/analyzer
    participant VS as vision/vision_scanner
    participant I2 as Dev 1 Model Client (I2)
    participant FUS as Dev 1 Fusion Engine

    ORCH->>CH: compute_directory_hash(skill_path)
    CH-->>ORCH: return content_hash (64 hex)
    
    ORCH->>CS: get_cached(content_hash, engine_v, model_v)
    alt Cache Hit (< 2 s)
        CS-->>ORCH: return (verdict_json, sarif_json)
        ORCH-->>ORCH: emit StageResult(stage='cache', cached=True)
    else Cache Miss
        CS-->>ORCH: return None
        
        %% STAGE 1: SPEC & TYPOSQUAT
        ORCH->>PS: parse_package(skill_path)
        PS-->>ORCH: StageResult(stage='spec', findings, inventory)
        
        ORCH->>TQ: check_typosquat(skill_name)
        TQ-->>ORCH: StageResult(stage='typosquat', findings, bonus=+15)
        
        %% STAGE 2: AST ANCHORS & SEMANTIC
        ORCH->>AA: scan_anchors(inventory.scripts)
        AA-->>ORCH: StageResult(stage='deterministicAnchor', findings, anchors_text)
        
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
        else No Assets Present
            ORCH-->>ORCH: emit StageResult(stage='vision', note='no-assets')
        end
        
        %% DOWNSTREAM HANDOFF
        ORCH->>ORCH: Pass intent_keywords to Stage 4 (Sandbox)
        ORCH->>FUS: Forward all StageResults (I3) to Fusion Engine
    end
```

---

## 4. Trust Boundaries & Security Enclaves

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
        │
        ▼
[ TRUSTED ZONE ]
  Structured `StageResult` Dataclasses, Normalized Signals, SQLite `scan_cache`
```

### 4.1 Boundary Enforcement Rules
1. **Never Execute**: Developer 2's code **never executes** scripts or binaries under audit. All inspection is strictly static (AST parsing, regex line scans, token analysis, image downscaling, vision OCR). Actual execution is quarantined to Developer 1's Docker sandbox in Stage 4.
2. **Never Trust File Paths**: Paths reported in package metadata must be sanitized against path-traversal attacks (`../`, absolute paths, symlink redirections).
3. **Never Allow Injection from Scanned Text to Flip Decisions**: Analysis prompts treat all skill text as untrusted data wrapped in delimiters. Model outputs are strictly validated against a hard JSON schema.
4. **Anchor Invariance**: If AST regex detects an `os.system` call or `nslookup`, the model’s claim that *"this skill does not use network or shell"* is automatically flagged as a contradiction and discarded in favor of the anchor.
