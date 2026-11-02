# 13 · Laya Integration Plan (Revised V1)

> **Status:** Proposed, awaiting execution approval.
> **Date:** 2026-10-28.
> **Baseline commit:** `7785026 fix(sandbox): make real Docker E2E pipeline pass`.
> **Scope:** Replace Gemma as the default text-semantic decision layer with an embedded, local Laya backend. Vision remains deferred.

---

## 13.1 Executive decision

Laya becomes SkillSentry's **first-class local semantic decision backend**.

Laya is not a general-purpose LLM. It answers only typed questions:

- `choice` — select one label from a fixed set;
- `noul` — probability that a yes/no statement is true;
- `score` — position on an ordered rubric.

The integration therefore changes the semantic stage from **free-form JSON generation** to **typed decisions over deterministic evidence candidates**.

### Non-negotiable rules

1. Deterministic anchors, sandbox evidence, and canary correlation remain authoritative.
2. Laya is advisory. It may increase suspicion; it must not decrease hard evidence.
3. Laya never runs inside the untrusted Docker sandbox.
4. Missing or failed Laya must never produce `SAFE`.
5. No mock/demo model may be used as proof of live behavior.
6. Vision is out of scope for this phase and must fail safe if required.

```text
final_risk = max(deterministic_risk, laya_escalation_risk)
```

---

## 13.2 Goals and non-goals

### Goals

- Embed Laya locally as the default semantic decision layer.
- Keep skill content on the machine.
- Preserve deterministic evidence, citations, and final verdict authority.
- Add a typed `DecisionClient` interface that can later support other decision backends.
- Keep the existing Docker sandbox and `SandboxActionInstruction` handoff.
- Calibrate Laya before enabling it by default.
- Keep the base install lightweight by making Laya an optional extra.
- Preserve all fail-safe and degraded-mode behavior.
- Keep reports deterministic; Laya may choose typed report metadata only.

### Non-goals

- Replacing Gemma/Gemini for vision or OCR.
- Generating report prose with Laya.
- Running Laya inside the sandbox.
- Letting Laya choose arbitrary shell commands or skip baseline checks.
- Making Laya the sole final verdict authority.
- Fine-tuning Laya in the first implementation pass; calibration comes first.
- Hosted/cloud Laya as the default mode.

---

## 13.3 Current baseline

At commit `7785026`:

- `ScanEngine` runs the live pipeline: cache → spec → typosquat → anchors → semantic → vision → sandbox → Poisoned Well → evasion → fusion.
- Semantic analysis uses `ModelClient.generate_json()` with a free-form `SEMANTIC_SCHEMA`.
- The same `ModelClient` is also used for vision, which couples text and vision model selection.
- `ScanEngine._sandbox_stage()` constructs a `SandboxRequest` directly from the package entrypoint and declared intent; it does not consume formal instructions.
- Fusion already refuses to emit `SAFE` when a stage is degraded.
- Current acceptance baseline: 240 tests pass; static fixtures 8/8; real Docker fixtures `cloud-sync-pro` 95 and `slack-notif-mal` 100.
- Real Ollama/Gemma and Gemini E2E remain unverified in this environment.

The existing Docker pipeline is working. This plan does not rewrite it.

---

## 13.4 Target architecture

```text
skillsentry scan
  |
  v
ScanEngine
  |
  +--> cache / spec / typosquat
  |
  +--> deterministic anchors
  |       |
  |       +--> evidence candidates (file, line, snippet, anchor type)
  |
  +--> Laya semantic decision layer (local, advisory)
  |       |
  |       +--> intent choice
  |       +--> capability nouls
  |       +--> deception choice
  |       +--> calibrated confidence
  |       +--> findings with code-supplied evidence
  |
  +--> SandboxExecutionPlan (INT-4)
  |       |
  |       +--> baseline checks always present
  |       +--> Laya intent/capabilities may add checks
  |       +--> declared entrypoint only
  |
  +--> Docker sandbox
  |       |
  |       +--> canaries / DNS sinkhole / HTTP responder / monitors
  |       +--> SandboxExecutionReport
  |
  +--> deterministic fusion (authoritative)
  |
  +--> deterministic report renderer
```

### Stage order

Keep the current stage order. Add Laya inside the existing semantic stage rather than creating a new pipeline stage.

```text
cache -> spec -> typosquat -> deterministicAnchor -> semantic(Laya)
      -> vision(deferred/legacy) -> sandbox(INT-4) -> poisonedWell
      -> evasion -> verdict
```

---

## 13.5 Model and deployment policy

### 13.5.1 Runtime mode

**V1:** in-process Python SDK, lazy-loaded through the optional `laya` package.

**Later:** optional HTTP mode through `laya-serve` for isolation or container deployment. Laya's server exposes a Jev-compatible `/v1/systemone` API.

The in-process mode is the default because it gives the simplest CLI experience. The HTTP mode is kept as a future deployment option, not a V1 requirement.

### 13.5.2 Checkpoints

| Checkpoint | Parameters | Context | Intended use |
|---|---:|---:|---|
| `laya` | 421M | 512 | English semantic decisions |
| `laya-multilingual` | 322M | 1,024 (up to 8,192) | Non-English and multilingual content |
| `laya-typed-decisions` | 421M | 1,024 | Only after SkillSentry-specific fine-tuning |

V1 policy:

- Use Laya's router to choose `laya` or `laya-multilingual`.
- Pin accepted checkpoints; do not silently accept arbitrary Hub IDs.
- Record the selected checkpoint in stage telemetry and the report.
- Do not treat `laya-typed-decisions` as a zero-shot win. Upstream reports that base checkpoints are near chance on its typed-decisions benchmark; the strong result comes from fine-tuning.
- Do not load all three checkpoints. Keep at most two resident, and one in memory-constrained deployments.
- Use `max_len` / `head_max_len` overrides only through reviewed configuration.

### 13.5.3 Question design rules

- Keep `choice` option sets small, preferably under 20.
- Use coarse-to-fine questions instead of one large label set.
- Avoid `score` for critical severity decisions; it is Laya's weakest primitive.
- Use a neutral two-option `choice` instead of `noul` where the English checkpoint shows label bias.
- Treat probabilities as calibrated only after SkillSentry-specific calibration.
- Never interpret high confidence as correctness.
- Batch related questions in one request where possible.
- Keep question IDs stable; they are part of the evidence contract.

---

## 13.6 Semantic decision contract

### 13.6.1 New interface

Add a separate decision interface. Do not force Laya into `ModelClient.generate_json()`.

```python
class DecisionClient(Protocol):
    backend: str
    model_version: str

    def decide(
        self,
        state: str | dict,
        questions: dict[str, DecisionQuestion],
    ) -> DecisionResult: ...

    def health(self) -> bool: ...
```

Suggested models:

```python
class DecisionQuestion(BaseModel):
    type: Literal["choice", "score", "noul"]
    instructions: str
    criteria: dict[str, str] | list[str] | None = None

class DecisionAnswer(BaseModel):
    choice: str | None = None
    score: float | None = None
    noul: float | None = None
    probabilities: dict[str, float] | list[float] | None = None
    confidence: float | None = None
    abstention: bool = False

class DecisionResult(BaseModel):
    answers: dict[str, DecisionAnswer]
    backend: str
    checkpoint: str
    routing: dict[str, Any] = {}
    usage: dict[str, Any] = {}
```

Implementation files:

```text
skillsentry/core/decisions/__init__.py
skillsentry/core/decisions/base.py       # protocol + models
skillsentry/core/decisions/laya.py       # LayaDecisionClient
skillsentry/core/decisions/mock.py       # tests only
skillsentry/core/decisions/questions.py  # fixed taxonomy/schema
skillsentry/core/decisions/calibration.py
skillsentry/core/decisions/mapping.py    # decisions -> findings/score
```

### 13.6.2 Fixed question set

Start with a small taxonomy.

#### Intent

`choice` over:

- `text_processing`
- `file_management`
- `network_access`
- `credential_access`
- `code_execution`
- `ui_automation`
- `data_export`
- `other`

#### Capabilities

One `noul` per capability:

| Question ID | Question |
|---|---|
| `cap_credentials` | Does the skill read, request, or transmit credential material? |
| `cap_env_secrets` | Does it inspect environment variables for secrets? |
| `cap_process` | Does it spawn processes or execute shell commands? |
| `cap_network` | Does it make outbound network requests? |
| `cap_upload` | Does it send data to a remote endpoint? |
| `cap_dns` | Does it perform DNS lookups or encode data in DNS? |
| `cap_filesystem` | Does it write or delete files outside its own package? |
| `cap_persistence` | Does it modify startup or persistence mechanisms? |
| `cap_obfuscation` | Does it decode or obfuscate content to hide behavior? |
| `cap_hidden_behavior` | Does it hide behavior from the user? |
| `cap_prompt_injection` | Does it contain instructions aimed at an auditing agent or model? |
| `cap_deception` | Does the implementation contradict its declared intent? |

#### Deception

`choice` over:

- `consistent`
- `unclear`
- `deceptive`

#### Evidence candidates

Deterministic code supplies candidate evidence. Laya does not generate file paths, line numbers, or evidence strings.

Candidate contract:

```python
class EvidenceCandidate(BaseModel):
    candidate_id: str
    file: str
    line: int
    code: str
    anchor_type: str
```

For top candidates, run a separate small `noul` adjudication. The finding keeps the code-supplied location and snippet.

### 13.6.3 State shape

Send a structured JSON state:

```json
{
  "declared_intent": "...",
  "package_name": "...",
  "anchors": [
    {
      "candidate_id": "anchor-1",
      "type": "credential-read",
      "file": "scripts/sync.py",
      "line": 42,
      "code": "..."
    }
  ],
  "snippets": [
    {
      "file": "scripts/sync.py",
      "line": 42,
      "text": "..."
    }
  ]
}
```

Rules:

- Treat all skill content as untrusted data.
- Delimit content clearly in the state.
- Cap candidates and characters before sending.
- Never let Laya output a new evidence location.
- Keep an instruction floor derived from deterministic anchors.

---

## 13.7 Semantic scoring and fusion

### 13.7.1 Semantic score

The semantic stage computes a deterministic score from Laya's calibrated decisions:

```text
semantic_score = max(
    instruction_floor,
    capability_risk,
    deception_risk
)
```

Rules:

- `instruction_floor` is derived from deterministic anchor findings, as it is today.
- Capability findings are created only above calibrated thresholds.
- Deception `deceptive` creates a high-severity finding; `unclear` creates a note or review flag.
- A Laya `benign` answer cannot lower `instruction_floor`.
- Laya's raw `score` primitive is not used as the final severity.
- `confidence` is used for routing/review, not as a replacement for evidence.

### 13.7.2 Fusion

Keep the existing fusion engine. Laya contributes through:

- semantic findings with real evidence; and
- the existing `semantic` signal.

Add a regression test that proves:

- a known-malicious anchor remains malicious when Laya says benign;
- a degraded Laya stage cannot produce `SAFE`;
- a hard override still wins;
- fusion output is deterministic for fixed inputs.

### 13.7.3 Low confidence

Low-confidence Laya answers:

- do not create `MALICIOUS` findings;
- may add a `semantic-low-confidence` note;
- may set `needs_human_review` in report metadata;
- do not make the scan `SAFE` if other required stages are degraded.

---

## 13.8 Sandbox and INT-4 integration

### 13.8.1 Laya's role

Laya may inform which checks are relevant:

- `intent` selects a canary context;
- capability signals add targeted monitors or canary assets.

Laya must not:

- generate arbitrary commands;
- remove baseline checks;
- replace the declared entrypoint;
- execute inside the sandbox;
- decide that a sandbox stage can be skipped.

### 13.8.2 Execution plan

Introduce the formal `SandboxExecutionPlan` contract:

```text
SandboxActionInstruction
  instruction_id
  category
  reason
  source (deterministicAnchor | laya | baseline)
  check
  timeout_s
  required
```

```text
SandboxExecutionPlan
  instructions[]
  baseline_instructions[]
  declared_entrypoint
  canary_context
  validation_status
```

Rules:

- Baseline checks are always present.
- Laya-derived checks are additive.
- Invalid or missing instructions mean no `SAFE`.
- Only the declared entrypoint is executed.
- Docker failure means no `SAFE`, no cache, and exit `3` unless malicious evidence forces exit `1`.
- The execution report records per-instruction coverage.

### 13.8.3 Runner integration

Extend `SandboxRequest` additively:

```python
execution_plan: SandboxExecutionPlan | None = None
```

Keep the existing `command` field for compatibility. The engine builds the plan before calling the runner. The runner validates the plan and refuses to run an undeclared fallback command.

---

## 13.9 Report strategy

Reports remain deterministic.

Laya may fill typed metadata:

- `primary_threat_category`
- `recommended_action`
- `review_priority`
- `needs_human_review`
- `report_template`

Code renders the prose from templates.

Reports must include:

- decision backend;
- checkpoint;
- calibration version;
- selected model routing;
- confidence/probabilities used;
- degraded-stage notes;
- which findings came from Laya versus deterministic evidence.

Do not include raw prompts or full untrusted skill content in reports.

Vision status must be explicit:

- `not_applicable` when no assets exist;
- `not_evaluated` when vision is deferred/unavailable;
- never silently treat deferred vision as clean.

---

## 13.10 Configuration and CLI

### 13.10.1 Configuration

Add a new section; keep `[model]` for the legacy/vision path.

```toml
[decision]
backend = "auto"                 # auto | laya | legacy | none
checkpoint = "auto"              # auto | english | multilingual | typed-decisions
device = "auto"                  # auto | cpu | cuda | mps
model_path = ""                  # offline checkpoint directory
timeout_s = 30
max_len = 1024
head_max_len = 256
calibration_path = ""
required = false                 # true: no fallback, fail closed if Laya is unavailable
```

Environment overrides:

```text
SKILLSENTRY_DECISION_BACKEND
SKILLSENTRY_LAYA_CHECKPOINT
SKILLSENTRY_LAYA_DEVICE
SKILLSENTRY_LAYA_MODEL_PATH
```

### 13.10.2 Selection semantics

- `auto`: prefer Laya if importable; otherwise use the legacy semantic model if configured; otherwise degrade.
- `laya`: require Laya; no silent fallback.
- `legacy`: use the existing Gemma semantic path for comparison only.
- `none`: deterministic-only semantic stage; degraded if semantic analysis is required.

`required = true` makes missing Laya a hard degraded condition even in `auto`.

### 13.10.3 CLI

Add decision-specific flags without breaking `--backend`:

```text
skillsentry scan <path> --decision-backend auto|laya|legacy|none
skillsentry scan <path> --laya-checkpoint auto|english|multilingual|typed-decisions
skillsentry scan <path> --laya-device auto|cpu|cuda|mps
skillsentry scan <path> --laya-timeout 30
skillsentry scan <path> --laya-model-path ./models/laya
skillsentry scan <path> --laya-required
```

Keep the existing `--backend` option for the legacy/vision model path. Deprecate it only after the split is stable.

### 13.10.4 Scan options

Add an optional additive field to `ScanOptions`:

```python
decision_backend: str | None = None
```

Do not change the existing `Backend` enum in a way that breaks API clients.

---

## 13.11 Packaging and model distribution

### Base install

Do not add PyTorch, Transformers, and model weights to the base install.

### Optional extra

```toml
[project.optional-dependencies]
laya = [
  "laya>=0.4.17,<0.5",
]
```

Verified against Laya 0.4.17 (2026-10-28). Laya itself declares `torch>=2.0.0`,
`transformers>=4.48.0`, `safetensors>=0.4.0`, `huggingface_hub>=0.20.0`, and
`numpy>=1.20.0`, so the extra does not need to repeat those pins. Do not pin
`transformers>=5`; the current package supports 4.48 and later.

### Installation

```text
pip install skillsentry
pip install "skillsentry[laya]"
```

### Offline distribution

- Provide `--laya-model-path` for pre-downloaded checkpoints.
- Verify checkpoint SHA-256 hashes.
- Document the Hugging Face cache location.
- Do not require network access during a scan.
- Do not use `trust_remote_code=True` unless a reviewed checkpoint requires it.

### CI

- Unit tests use `MockDecisionClient`.
- Live Laya E2E runs in a separate job with the real checkpoint.
- No mock-only scan may be presented as proof of live behavior.

---

## 13.12 Fail-safe behavior

| Condition | Required behavior |
|---|---|
| Laya not installed, `auto`, legacy available | Use legacy semantic backend; record backend |
| Laya not installed, `required=true` | Semantic stage degraded; no cache; no `SAFE`; exit `3` unless malicious evidence |
| Laya model download/load fails | Degraded; no cache; no `SAFE` |
| Laya timeout | Degraded; no cache; no `SAFE` |
| Laya returns malformed response | Degraded; no cache; no `SAFE` |
| Laya returns low confidence | Note/review flag; never `SAFE` solely from this |
| Laya says benign but anchors are malicious | Anchors win |
| Docker unavailable | Existing behavior: degraded sandbox, no `SAFE` |
| Vision required but deferred | `vision-not-evaluated`; no `SAFE` |
| Any stage error | A finding, never a silent pass |

Exit codes:

- `0` — scan completed and no fail threshold met.
- `1` — verdict at or above the configured fail threshold.
- `3` — operational/model/sandbox failure with no trustworthy verdict.
- `4` — usage error.

---

## 13.13 Security requirements

- Run Laya outside the sandbox.
- Keep skill content local; no cloud egress in the default path.
- Pin and hash model files.
- Pin Python dependencies.
- Cap model memory, input length, and runtime.
- Treat Laya output as untrusted advisory data.
- Preserve the deterministic instruction floor.
- Add adversarial tests for prompt-injection text that tries to suppress findings.
- Do not log full skill content or raw prompts by default.
- Do not allow Laya to lower an anchor or canary finding.
- Do not allow Laya to alter sandbox command construction.
- Validate every `SandboxExecutionPlan` before execution.

---

## 13.14 Implementation phases

### Phase L0 — Contract and decision freeze

**Deliverables**

- `DecisionClient`, `DecisionQuestion`, `DecisionAnswer`, `DecisionResult`.
- `EvidenceCandidate`.
- Capability/intent taxonomy.
- `SemanticDecisionSettings`.
- Cache identity fields for decision backend/checkpoint/calibration.
- Decision: Laya is an optional extra; `auto` is the default.

**Files**

- `skillsentry/core/decisions/base.py`
- `skillsentry/core/decisions/questions.py`
- `skillsentry/core/config.py`
- `skillsentry/core/contracts.py` (additive fields only)
- `tests/unit/test_decision_contract.py`

**Acceptance**

- Contract tests pass.
- Existing tests still pass.
- No existing public contract field is renamed or removed.

---

### Phase L1 — Laya adapter

**Deliverables**

- `LayaDecisionClient` with lazy import/load.
- Health check, timeout, response validation.
- Checkpoint pinning and routing metadata.
- Device selection.
- `MockDecisionClient`.
- Clear error mapping to `ModelUnavailable`/degraded.

**Files**

- `skillsentry/core/decisions/laya.py`
- `skillsentry/core/decisions/mock.py`
- `skillsentry/core/decisions/selector.py`
- `tests/unit/test_laya_client.py`
- `tests/unit/test_decision_selector.py`

**Acceptance**

- Unit tests use a fake HTTP/server or mocked SDK; no real checkpoint required.
- Missing package raises a typed unavailable error.
- Timeout and malformed responses fail closed.
- No model is loaded at import time.

---

### Phase L2 — Laya semantic analyzer

**Deliverables**

- `LayaSemanticAnalyzer` replacing the default Gemma semantic path.
- Deterministic evidence candidate extraction.
- Question builder and state builder.
- Decision-to-finding mapping.
- Instruction floor preserved.
- Chunking/selection for Laya context limits.
- Legacy Gemma semantic path behind `decision_backend = legacy`.

**Files**

- `skillsentry/core/semantic/laya_analyzer.py`
- `skillsentry/core/semantic/candidates.py`
- `skillsentry/core/semantic/analyzer.py` (legacy path retained)
- `skillsentry/core/decisions/mapping.py`
- `skillsentry/core/engine.py` (split model selection)
- `tests/unit/test_laya_semantic.py`
- `tests/unit/test_laya_semantic_failures.py`

**Acceptance**

- Laya produces findings with code-supplied file/line evidence.
- No finding has a model-invented location.
- Anchors remain in the prompt/state as ground truth.
- Laya `benign` cannot lower an anchor instruction floor.
- Long skills are filtered/chunked rather than silently truncated without a note.

---

### Phase L3 — Fusion, cache, and reports

**Deliverables**

- Decision metadata in stage telemetry.
- Cache key includes decision backend, checkpoint, calibration version.
- Degraded Laya disables cache.
- Report metadata from typed decisions.
- Markdown/JSON/SARIF reporting updates.
- Explicit vision status.

**Files**

- `skillsentry/core/cache/` (cache identity)
- `skillsentry/core/engine.py`
- `skillsentry/core/reports/`
- `skillsentry/core/contracts.py` (additive report fields if needed)
- `tests/unit/test_cache_identity.py`
- `tests/unit/test_reports_laya.py`

**Acceptance**

- Changing checkpoint/calibration invalidates cache.
- Degraded scans are never cached as clean.
- Reports show backend/checkpoint/calibration.
- No report contains raw prompts.

---

### Phase L4 — INT-4 sandbox handoff

**Deliverables**

- `SandboxActionInstruction`, `SandboxExecutionPlan`, `InstructionResult`, `SandboxExecutionReport`.
- Deterministic plan builder.
- Baseline instructions always included.
- Laya intent/capabilities may add instructions.
- Runner consumes and validates the plan.
- Per-instruction coverage in the report.

**Files**

- `skillsentry/core/sandbox/instructions.py`
- `skillsentry/core/sandbox/runner.py`
- `skillsentry/core/engine.py`
- `tests/unit/test_sandbox_instructions.py`
- `tests/unit/test_sandbox_plan_execution.py`

**Acceptance**

- Missing/invalid instructions cannot produce `SAFE`.
- Baseline checks are never removed by Laya.
- Undeclared entrypoints are refused.
- Docker failure remains degraded and uncached.

---

### Phase L5 — Calibration and evaluation

**Deliverables**

- Labelled SkillSentry decision corpus.
- Calibration file with version and checkpoint hash.
- Temperature scaling per question type/option count.
- Held-out evaluation report.
- Adversarial tests.
- Performance measurements.

**Files**

- `tests/eval/` or `tests/fixtures/decisions/`
- `scripts/calibrate_laya.py`
- `docs/08-testing-and-evaluation.md`
- `docs/internal/13-laya-integration-plan.md` (results appendix)

**Evaluation set**

- benign lookalikes;
- credential readers with legitimate intent;
- network calls with declared intent;
- prompt-injection skills targeting the classifier;
- evasion skills;
- multilingual skills;
- long skills with irrelevant text.

**Gates**

- No false negatives on the known-malicious fixture set.
- Benign fixtures remain below the `SAFE` boundary or are explicitly review-flagged.
- Calibration error is reported and acceptable for the chosen thresholds.
- Laya cannot lower a deterministic malicious verdict.
- Semantic stage latency and RSS stay within the agreed CI budget.

Exact numeric thresholds are set after the baseline evaluation; they are not assumed in advance.

---

### Phase L6 — Packaging, CLI, and documentation

**Deliverables**

- `skillsentry[laya]` extra.
- CLI flags and config schema.
- `skillsentry init` includes `[decision]`.
- Offline/model-hash documentation.
- Architecture, CLI, security, testing, and developer docs updated.
- Changelog entry.

**Files**

- `pyproject.toml`
- `skillsentry/cli.py`
- `skillsentry/core/config.py`
- `docs/02-architecture.md`
- `docs/04-security.md`
- `docs/05-api-reference.md`
- `docs/07-cli-reference.md`
- `docs/08-testing-and-evaluation.md`
- `docs/10-developer-guide.md`
- `docs/CHANGELOG.md`

**Acceptance**

- Base install still works without Laya.
- `pip install "skillsentry[laya]"` enables the local backend.
- `--decision-backend none` is deterministic-only and degraded, not clean.
- Documentation matches actual behavior.

---

## 13.15 Test plan

### Unit

- Decision contract validation.
- Laya response mapping.
- Checkpoint/routing metadata.
- Timeout/error/degraded behavior.
- Calibration loading and threshold application.
- Evidence candidate extraction.
- Finding mapping with citations.
- Cache identity changes.
- Config precedence and CLI validation.

### Integration

- `ScanEngine` with `MockDecisionClient`.
- `ScanEngine` with real Laya (optional marker).
- `ScanEngine` with Laya unavailable.
- `fuse()` with Laya-escalated and Laya-benign inputs.
- Sandbox plan validation.
- Report rendering with decision metadata.

### End-to-end

- Static fixtures: expected verdicts unchanged.
- Docker fixtures: `cloud-sync-pro` and `slack-notif-mal` still pass.
- Real Laya + real Docker on at least one benign and one malicious fixture.
- No mock-only E2E claim.

### Adversarial

- Skill text instructs the auditor to ignore findings.
- Skill text claims to be benign.
- Skill text contains fake evidence paths.
- Laya returns low confidence on a malicious anchor.
- Laya returns a malformed response.
- Laya times out.
- Model OOM/load failure.
- Option-order sensitivity check for critical choices.

### Performance

- Cold start and warm inference latency.
- Peak RSS.
- Semantic stage overhead relative to sandbox time.
- No model load during `--no-semantic` or deterministic-only scans.

---

## 13.16 Acceptance gates for V1

V1 is complete when all are true:

- [ ] Existing 240 tests pass.
- [ ] Static fixtures remain 8/8.
- [ ] Real Docker fixtures still produce expected scores.
- [ ] Real Laya E2E passes; mock-only proof is rejected.
- [ ] Laya missing/load failure/timeout produces degraded, no `SAFE`, no cache.
- [ ] Malicious deterministic evidence wins over a Laya benign answer.
- [ ] Adversarial prompt-injection test cannot suppress anchors.
- [ ] Reports include backend/checkpoint/calibration and vision status.
- [ ] Laya runs outside the sandbox.
- [ ] INT-4 plan validation prevents undeclared execution.
- [ ] Docs and CLI match implementation.

---

## 13.17 Risks and mitigations

| Risk | Mitigation |
|---|---|
| Laya zero-shot accuracy is weak | Calibrate first; fine-tune only if gates fail |
| `noul` label bias | Use neutral two-option `choice` for critical questions |
| Large choice sets degrade | Keep taxonomies small; hierarchical questions |
| Context limits (512/1,024, up to 8,192) | Filter and chunk; cap candidates |
| Overconfident probabilities | Temperature scaling per question type/option count |
| Adversarial skill text | Deterministic anchor floor; monotonic fusion |
| Heavy ML dependency | Optional extra; lazy import; no model at import time |
| Supply-chain risk | Pin package/checkpoint versions; verify hashes |
| Model unavailable | Degraded; no `SAFE`; no cache |
| Laya used inside sandbox | Architectural prohibition + test |
| Vision silently skipped | Explicit `vision-not-evaluated` degraded finding |
| Report hallucination | Deterministic templates; Laya only selects fields |

---

## 13.18 Open decisions and assumptions

These are the working assumptions for execution:

1. **Laya is an optional extra**, not a mandatory base dependency.
2. **`auto` prefers Laya** when installed, with legacy fallback only if explicitly available.
3. **Laya is advisory**; deterministic fusion remains authoritative.
4. **Vision is frozen** and deferred to a later workstream.
5. **Calibration comes before fine-tuning**; fine-tuning is a V1.5 fallback.
6. **In-process SDK is the V1 runtime**; HTTP `laya-serve` is a later deployment option.
7. **INT-4 remains in scope** and is not replaced by Laya.
8. **No model runs inside the sandbox.**

If any assumption is changed, update this document before implementation.

---

## 13.19 Definition of done

- [ ] `DecisionClient` contract is implemented and tested.
- [ ] Laya adapter works locally and fails closed.
- [ ] Semantic stage uses typed Laya decisions with deterministic evidence.
- [ ] Anchor floor and hard overrides are preserved.
- [ ] Decision/checkpoint/calibration metadata is recorded.
- [ ] Cache invalidation is correct.
- [ ] INT-4 plan is validated before execution.
- [ ] Reports are deterministic and include model metadata.
- [ ] Vision is explicitly deferred and fails safe.
- [ ] Real Laya + real Docker E2E passes.
- [ ] Docs, CLI, and config match behavior.
- [ ] No mock-only scan is accepted as proof.

---

## 13.20 References

- Laya upstream: <https://github.com/NandhaKishorM/laya>
- Laya model card: <https://huggingface.co/convaiinnovations/laya>
- Laya documentation: <https://nandhakishorm.github.io/laya/>
- Laya PyPI: <https://pypi.org/project/laya/>

> Note: `laya-ai.com` is a community/landing resource, not the canonical upstream project. Use the GitHub/Hugging Face/PyPI sources for integration decisions.

- TypeSafe Jev (future optional decision backend): <https://typesafe.ai/blog/introducing-system-one-models-and-jev>
- TypeSafe models: <https://docs.typesafe.ai/models>

---

## 13.20 Results appendix (L5)

**Status: calibration measured on real Laya (2026-10-29). Docker E2E not yet run.**

### Measured run (checkpoint `english`, CPU, token budget 512/128)
- Real-Laya integration tests: 4 of 4 pass in `.venv-laya`.
- Calibration (`scripts/calibrate_laya.py`) over 38 fitting cases (`g1t-translate` excluded as `review`):
  - Fitted temperature 2.248; capability threshold 0.639.
  - **Final fit:** 0 of 18 malicious missed; **12 of 20 benign flagged**.
  - **Held-out split** (10 cases, 4 malicious): **1 of 4 malicious missed**; 3 of 6 benign flagged.
  - Expected calibration error 0.326 (final), 0.330 (held-out). This is poorly calibrated.
- Laya warned that this checkpoint ships temperatures outside [0.5, 5]. Confidence values
  from the affected entries are uncalibrated, so the temperature fit is not fully trustworthy.

### Gate outcome against section 13 L5
- No false negatives on known malicious cases: **fails on held-out** (1 of 4), passes on the final fit only because the threshold was fitted to it.
- Benign cases below the SAFE boundary or review-flagged: **fails**; 60% of benign cases exceed the threshold.
- Calibration error acceptable: **fails** (0.33).

**Decision:** do not enable this calibration file by default. The capability threshold is not usable yet.
Next steps: more labelled data, per-capability thresholds, and a check of whether the English checkpoint's
capability answers track the labels at all (the held-out miss suggests not reliably).

### Real Laya + Docker sandbox E2E (2026-10-29)
Run with `calibration/e2e_real_laya.py` (laya venv, real checkpoint `english`, Docker 29.9.2, sandbox enabled, uncalibrated):

| Skill | Verdict | Risk | Expected (full sandbox) | Notes |
|---|---|---|---|---|
| cloud-sync-pro | MALICIOUS | 95 | MALICIOUS, >= 91, active defense, DNS_TUNNELING | pass |
| slack-notif-mal | MALICIOUS | 95 | MALICIOUS, >= 100, active defense, evasion | **fail on score**: active defense and evasion detected, risk 5 below expectation |
| git-helper | SAFE | 8 | SAFE | pass |

No stage was degraded. Real Laya answered every semantic question, and the sandbox ran for every skill.
The slack-notif-mal shortfall is a scoring gap in the fusion or evasion floor, not a missed detection. The
expectation was not changed to make the run pass.

### Operational notes
- Full-corpus runs need the token budget reduced (512/128); the default 1024/256 ran out of memory mid-corpus on this host.
- Memory on this host is still the limiting factor (page file 4 GB, WSL using about 1.1 GB).

### What is in place

- Labelled corpus: `tests/fixtures/decisions/labels.json` (schema v2) with 39 cases:
  20 benign, 18 malicious, and 1 `review` case that is reported but never fitted.
  Ten cases carry per-capability truths. The eight shipped fixtures carry labels only.
- Calibration module: `skillsentry/core/decisions/calibration.py`. It fits a
  temperature on `logit(p)` for the `noul` question type, then a capability
  threshold, and reports a deterministic held-out split (every fourth case).
- Runner: `scripts/calibrate_laya.py`. It aborts on any unscorable case and exits 1
  when the final fit still misses a malicious case.

### Blockers for a real run

1. **Laya weights do not load on this machine.** `laya` 0.4.17 is installed in
   `.venv-laya`, and the health probe passes. Loading the model fails with
   `OSError: The paging file is too small (os error 1455)`. The laya agent builds
   its encoder and loads roughly 0.8 GB of weights, and this host has 15.6 GB RAM,
   about 2.7 GB free, and an 8 GB page file. Raise the page file or free memory.
2. **Docker is not running.** The sandbox E2E needs the Docker Desktop engine.

### How to produce the results

```text
.venv-laya\Scripts\python -m pytest tests/unit/test_laya_real.py -q
.venv-laya\Scripts\python scripts\calibrate_laya.py --version <label> ^
    --out calibration.json --report calibration-report.json
```

Record in this appendix: the checkpoint and its hash, the held-out and final
false-negative and benign-flagged counts, the fitted temperature and threshold,
the expected calibration error, the semantic-stage latency and RSS, and the
Docker E2E verdicts for one benign and one malicious fixture.

### Gates (from §13 L5) to check against those numbers

- No false negatives on the known-malicious cases.
- Benign cases either sit below the SAFE boundary or are flagged for review.
- Laya cannot lower a deterministic malicious verdict (covered by fusion tests).
- Calibration error is reported and acceptable for the chosen threshold.
