# Mandatory Build and Merge Instructions (`readbeforemurger.md`)

> **Permanent Source of Truth for Repository Architecture, Branch Ownership, Build Coordination, and Safe Integration**  
> **Applies to:** `developer-1`, `developer-2`, `developer-3`, Integration Engineers, and Automated Coding Agents.  
> **Target Protected Branch:** `main`  
> **Document Status:** Active & Enforceable  

---

## 1. Document Purpose & Operational Mandate

This document serves as the permanent, authoritative architectural policy for coordinating work between independent development streams on the SkillSentry repository. Its primary purpose is to eliminate recurring merge collisions, prevent commit history rewriting, enforce developer ownership boundaries, and establish repeatable, zero-regression integration gates before any branch merges into `main`.

Every human developer and automated coding agent working on this repository **must read and adhere to this document** prior to initiating any branch synchronization, rebase, or merge operation.

---

## 2. Verified Repository State & Branch Topography

*(Inspection performed from repository root. Commit SHAs and branch relationships recorded below are verified repository facts as of October 2026.)*

### 2.1 Branch Topology & Ancestry Matrix

| Branch Name | Local Head Commit | Upstream Tracking | Ahead / Behind | Architectural Status |
| :--- | :--- | :--- | :--- | :--- |
| `main` | `1a474a6` | `origin/main` (`53b1598`) | Behind 12 | Protected integration target. Local reference is at initial baseline `1a474a6` (`project-doc-init`). |
| `feature/developer-2` | `cf1211e` | `origin/feature/developer-2` (`cdd2629`) | Ahead 1 | Active feature branch for Developer 2 containing core ports, AST anchors, and docs hygiene fixes. |
| `feature/developer-2-split`| `88dd9af` | *None (local)* | Direct child of `origin/main` | Clean 3-commit atomic branch split from `origin/main` (`53b1598`), avoiding SHA duplication. |
| `backup/dev2-cdd2629` | `cdd2629` | *None (local backup)* | - | Safety backup of monolithic commit `cdd2629`. |
| `backup/dev2-cf1211e` | `cf1211e` | *None (local backup)* | - | Safety backup of working tree recovery commit `cf1211e`. |
| `parked/dashboard-ui` | `406a06e` | *None (local parked)* | - | Parked frontend dashboard artifacts (`ui/`), quarantined from core Python packages. |
| `origin/main` | `53b1598` | Remote Head | Up-to-date | Upstream baseline containing Developer 1's merged PR #11 (`50384dd`). |

### 2.2 Merge-Base Analysis & History Divergence

Inspection of commit relationships reveals critical divergence facts:
1. **Merge Base of `feature/developer-2` and `origin/main`:**
   ```bash
   git merge-base origin/main feature/developer-2
   # Output: 1a474a6659779951ee176b6b772b260e0a51c96b
   ```
   The merge base is `1a474a6` (`project-doc-init`).
2. **Commit Count Comparison (`origin/main...feature/developer-2`):**
   - `origin/main` has **12 commits** ahead of the merge base (`8a3e76e` through `53b1598`), all authored by Developer 1 (`PranayChandra`).
   - `feature/developer-2` has **20 commits** ahead of the merge base.
   - **Root Cause of Divergence:** The 12 commits authored by Developer 1 on `origin/main` were previously replayed/rebased onto `feature/developer-2` under new commit SHAs (`d517ea4` through `d024e39`). This resulted in SHA rewriting and branch divergence.
3. **Clean Split Base (`feature/developer-2-split`):**
   ```bash
   git merge-base origin/main feature/developer-2-split
   # Output: 53b15988be0ee69374465df9d2c18ab9d40a2bb1 (origin/main)
   ```
   `feature/developer-2-split` is exactly 3 commits ahead and 0 commits behind `origin/main`. It contains cleanly partitioned commits:
   - `feb5c6d`: `dev2: corpus, ground-truth fixtures, and static determinism metrics`
   - `c889a79`: `dev2: credential flow analyzer and AST anchor detector`
   - `88dd9af`: `dev2: vision scanner, SVG parser, and directory integrity hasher`

### 2.3 Verified Facts vs. Unverified Assumptions

| Item | Classification | Verification Detail |
| :--- | :--- | :--- |
| **Evasion-Floor Fix in `fusion.py`** | **VERIFIED FACT** | Present on `origin/main` in commit `50384dd` (`override_floor = 100 if override.source == Stage.EVASION else 95` in `skillsentry/core/verdict/fusion.py`). |
| **Frontend UI Ownership** | **VERIFIED FACT** | Assigned exclusively to Developer 3 per `docs/checklists/dev3-frontend.md`. Developer 2 has no mandate to build or serve the web dashboard. |
| **Runtime Mock Isolation** | **VERIFIED FACT** | Verified by `tests/unit/test_no_mocks_in_runtime.py`. No mock libraries (`unittest.mock`, `pytest_mock`) are imported in production code paths. |
| **`slack-notif-mal` Score of 100** | **UNVERIFIED ASSUMPTION** | Assigned to Developer 1 in `docs/checklists/dev1-backend-ai.md`. The live run transcript in the sandbox harness is pending submission by Developer 1. |
| **Live Gemma 4 Inference Transcript** | **UNVERIFIED ASSUMPTION** | Unit tests in `tests/unit/test_gemma_clients.py` utilize `httpx.MockTransport`. A live execution transcript against an active Ollama instance remains unverified in this workspace. |

---

## 3. Developer Ownership & Subsystem Scopes

Strict boundaries prevent cross-developer collision and file contention.

```
SkillSentry Repository
├── skillsentry/
│   ├── core/
│   │   ├── sandbox/          <--- Developer 1 (Backend, AI Orchestration, Sandbox)
│   │   ├── evasion/          <--- Developer 1 (Evasion Analysis, Deception Floor)
│   │   ├── verdict/          <--- SHARED CONTRACT (Fusion Engine, Decision Logic)
│   │   ├── parser/           <--- Developer 2 (AST Anchors, Skill Normalization)
│   │   ├── static/           <--- Developer 2 (Typosquatting, Levenshtein, Homoglyphs)
│   │   ├── vision/           <--- Developer 2 (SVG Parsing, Steganography, QR)
│   │   └── corpus/           <--- Developer 2 (Directory Hashing, Benign Baseline)
│   └── cli/                  <--- Shared Entrypoint
├── developer-2/              <--- Developer 2 Isolated Subsystem Package
│   ├── skillsentry_dev2/
│   └── tests/
├── ui/                       <--- Developer 3 (Web Dashboard Frontend)
└── tests/
    ├── sandbox/              <--- Developer 1 Sandbox Tests
    ├── unit/                 <--- Shared & Subsystem Unit Tests
    └── fixtures/             <--- Shared Ground-Truth Evaluation Datasets
```

### 3.1 Developer 1 Ownership Scope

* **Primary Responsibilities:** AI orchestration, sandbox runtime harness, evasion detection, and deceptive prompt analysis.
* **Assigned Objective:** Bring `slack-notif-mal` to a score of 100 in the sandbox harness. Rebase onto the evasion-floor fix once it is pushed.
* **Operational Scope:**
  - `skillsentry/core/sandbox/`
  - `skillsentry/core/evasion/`
  - `skillsentry/core/deception/`
  - `skillsentry/core/models/` (model adapters, Ollama client integration)
  - `tests/sandbox/`
* **Mandatory Constraints for Developer 1:**
  1. Focus strictly on validating `slack-notif-mal` inside the sandbox harness.
  2. Ground the target score of 100 on the project's actual scoring engine: when `Stage.EVASION` triggers an override, the floor is enforced at 100 (`MALICIOUS`). Do not claim success without verifiable run logs.
  3. Wait until prerequisite fixes are confirmed on `origin/main` before rebasing.
  4. Never overwrite or rebase Developer 2's standalone feature branches.

### 3.2 Developer 2 Ownership Scope

* **Primary Responsibilities:** Skill analysis, AST anchors, typosquatting detection (Levenshtein + homoglyphs), vision scanning (SVG/image sanitization), directory integrity hashing, and benign corpus calibration.
* **Operational Scope:**
  - `developer-2/` (fully owned subsystem)
  - `skillsentry/core/parser/`
  - `skillsentry/core/static/`
  - `skillsentry/core/vision/`
  - `skillsentry/core/corpus/`
  - `fixtures/benign/`
  - `fixtures/malicious/` (assigned static attack fixtures: `invoice-helper`, `g1t-translate`, `svg-borne`, `dns-tunneler`, `sl4ck-bot`, `credential-multi`)
* **Explicit Non-Ownership:**
  - Developer 2 **does not own** `ui/` (Frontend dashboard built and served). Web dashboard UI is exclusively Developer 3's role.
  - Developer 2 **does not modify** sandbox isolation mechanics or backend Ollama process managers without prior review.

### 3.3 Main Branch Protection Policy

* `main` represents production-ready, verified code.
* Direct pushes to `main` are strictly forbidden.
* All integrations must arrive via pull requests that satisfy all mandatory gates defined in Section 6.
* Force-pushing (`git push -f` or `--force-with-lease`) to `main` or any shared remote branch is prohibited.

---

## 4. Analysis of Known Structural Merge Problems

The following five structural problems occurred during previous integration attempts. The associated rules are mandatory for all subsequent work.

### Problem A: Oversized Monolithic Commits

* **Incident:** Commit `cdd2629` grouped 58 files, 4,169 insertions, and 290 deletions into a single change. It combined core engine ports, Laya semantic layers, isolated `developer-2/` code, documentation, and frontend UI artifacts.
* **Consequence:** Code review was impossible to perform reliably. A failure in one domain blocked deployment of unaffected modules.
* **Mandatory Rule:**
  - Commit logically independent components into distinct, atomic commits.
  - Maintain the 4-part split pattern:
    1. Corpus, ground-truth fixtures, and baseline calibration.
    2. Credential flow analyzer and AST anchor detector.
    3. Vision scanner, SVG parser, and directory integrity hasher.
    4. Subsystem glue and CLI entrypoints.
  - Commits that bundle unrelated documentation, frontend artifacts, or external tools alongside core engine logic will be rejected at the Scope Gate.

### Problem B: Rewriting Existing Shared History

* **Incident:** A previous rebase replayed Developer 1's 12 upstream commits onto `feature/developer-2`, creating 12 duplicate commits with altered SHAs (`d517ea4`..`d024e39`). This resulted in a divergent commit graph (20 ahead, 12 behind `origin/main`).
* **Consequence:** Git merge-base was corrupted back to the initial repository commit (`1a474a6`), obscuring true file diffs and risking accidental reversion of upstream fixes.
* **Mandatory Rule:**
  - Never run `git rebase` on commits that have been pushed to a shared remote.
  - When synchronizing a feature branch with `origin/main`:
    - **Preferred Strategy:** Branch freshly from `origin/main` and cherry-pick or path-restore feature commits (as done in `feature/developer-2-split`).
    - **Alternative Strategy:** Merge `origin/main` into the feature branch with a standard non-fast-forward merge commit (`git merge origin/main --no-ff`).
  - Do not alter existing commit SHAs belonging to other developers.

### Problem C: Uncoordinated Edits to Integration-Sensitive Files

* **Incident:** Six core and test files at the integration boundary between Developer 1 and Developer 2 were modified directly:
  1. `skillsentry/core/decisions/__init__.py`
  2. `skillsentry/core/config.py`
  3. `tests/unit/test_laya_semantic.py`
  4. `tests/unit/test_cache_identity.py`
  5. `tests/unit/test_calibration.py`
  6. `tests/unit/test_calibration_fit.py`
* **Consequence:** Subtle interface mismatches, cache invalidation discrepancies, and altered test assertions.
* **Mandatory Rule:**
  - The 6 files above are designated as **Integration-Sensitive**.
  - Any PR modifying these files must undergo hunk-by-hunk review using the **File-Overlap Review Checklist** (Section 5.3).
  - Upstream defaults, public class signatures, and test fixtures must remain backwards-compatible.

### Problem D: Dependency Declaration and Import Safety

* **Incident:** `vision_scanner.py` imported `defusedxml` without verification. Although `defusedxml` was declared in `pyproject.toml`, unmanaged virtual environments lacked the installed package, triggering runtime `ModuleNotFoundError`.
* **Consequence:** Test failures in clean environments and masked execution paths.
* **Mandatory Rule:**
  - Every third-party import must be explicitly declared in both the root `pyproject.toml` and any subsystem configuration (`developer-2/pyproject.toml`).
  - Never wrap missing dependencies in silent `try/except ImportError: pass` blocks that mask missing packages.
  - If a dependency is optional, it must be guarded by an explicit feature flag and emit a descriptive diagnostic warning when invoked.

### Problem E: Missing Prerequisite Evasion-Floor Fix

* **Incident:** Branch `feature/developer-2` branched from a revision before Developer 1's evasion-floor fix (`50384dd`) was committed to `origin/main`. As a result, tests expecting evasion overrides to anchor at score 100 failed.
* **Consequence:** Developers attempted local workarounds in `fusion.py`, risking conflicting scoring implementations.
* **Mandatory Rule:**
  - Check the **Outstanding Fixes Register** (Section 8) before starting integration.
  - If a dependent fix exists on `origin/main`, verify that commit `50384dd` is an ancestor of your current branch (`git merge-base --is-ancestor 50384dd HEAD`).
  - Stop integration immediately if prerequisite commits are missing.

---

## 5. Mandatory Development Lifecycle

All developers must follow this five-stage workflow for every feature and merge request.

```
Stage 1: Pre-Dev Check
  ├── Read readbeforemurger.md
  ├── Verify clean working tree (`git status`)
  └── Confirm branch base at `origin/main`
           │
Stage 2: Isolated Development
  ├── Work within assigned scope
  ├── Keep commits atomic & focused
  └── Run local subsystem unit tests
           │
Stage 3: Pre-Commit Hygiene
  ├── Inspect staged diff (`git diff --cached`)
  ├── Check for secrets / stray files
  └── Verify dependency declarations in `pyproject.toml`
           │
Stage 4: Pre-Merge Verification
  ├── Verify merge-base with `origin/main`
  ├── Execute full test suite (Core + Subsystem)
  ├── Run regression gate & citation accuracy check
  └── Complete File-Overlap Checklist
           │
Stage 5: Post-Integration Audit
  ├── Inspect final tree diff against `origin/main`
  ├── Ensure zero unhandled regressions
  └── Document integrated commit SHAs
```

### 5.1 Stage 1 — Before Development

1. Review `readbeforemurger.md`.
2. Inspect `git status` to ensure working directory is clean.
3. Fetch the latest remote state: `git fetch origin`.
4. Ensure your feature branch originates from up-to-date `origin/main`:
   ```bash
   git checkout -b feature/<feature-name> origin/main
   ```
5. Confirm that all prerequisite fixes from Section 8 are present in your branch history.

### 5.2 Stage 2 — During Development

1. Restrict all file modifications to your assigned scope (Section 3).
2. Avoid touching shared configuration files (`pyproject.toml`, `config.py`) unless strictly necessary and coordinated.
3. Commit frequently using conventional, descriptive commit messages:
   - Format: `<scope>: <imperative description>`
   - Example: `parser: add AST anchor detection for prompt injection patterns`
4. Run incremental subsystem tests continuously:
   ```bash
   python -m pytest developer-2/tests
   ```

### 5.3 Stage 3 — Before Committing (Pre-Commit Hygiene)

1. Review staged files:
   ```bash
   git status
   git diff --staged
   ```
2. Verify that no temporary files, debug logs, virtual environment artifacts, or secrets are staged.
3. Enforce docs and path hygiene:
   - **Never hardcode Windows drive paths** (e.g., drive-letter root paths such as `C` followed by `:\`) in code or markdown documentation. Use repository-relative paths.
   - **Never use local file URI schemes** (e.g., `file:` followed by `///`) in tracked files.
   - **Never commit stray markdown files** to the repository root. Only approved repository documentation (`README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `CHANGELOG.md`, `readbeforemurger.md`) is permitted at root.
   - Avoid hardcoded test pass assertions (`\b\d+\s+passed\b`) outside `docs/evidence/`.
   - Avoid referencing frontend build distributions in core documentation; frontend build artifacts belong to Developer 3.

### 5.4 Stage 4 — Before Merging or Rebasing

1. Verify merge-base and commit graph:
   ```bash
   git merge-base origin/main HEAD
   git log --oneline --graph origin/main..HEAD
   ```
2. Check for overlapping changes on integration-sensitive files:
   ```bash
   git diff --name-only origin/main...HEAD
   ```
3. Complete the **File-Overlap Review Checklist**:
   - [ ] Are all modifications to the 6 integration-sensitive files strictly required?
   - [ ] Do all modified functions preserve original return types and exception semantics?
   - [ ] Are default configuration parameters preserved in `skillsentry/core/config.py`?
   - [ ] Do decision thresholds in `skillsentry/core/decisions/__init__.py` match upstream specifications?
   - [ ] Do semantic and calibration unit tests pass without skipping?
4. Execute the mandatory validation test suite (Section 6).

### 5.5 Stage 5 — After Integration

1. Inspect the merged tree diff:
   ```bash
   git diff origin/main..HEAD
   ```
2. Re-run the full test suite in an isolated environment.
3. Record the integrated commit SHAs in the pull request integration report.

---

## 6. Mandatory PASS/FAIL Merge Gates

A pull request or branch cannot be merged into `main` unless **every applicable gate passes**. A single failure halts integration immediately.

```
┌─────────────────────────────────────────────────────────────┐
│                 MANDATORY MERGE GATES                      │
├─────────────────┬───────────────────────────────────────────┤
│ Scope Gate      │ Changes strictly within assigned scope    │
│ History Gate    │ No rewritten SHAs; clean merge-base       │
│ Dependency Gate │ Declared in pyproject.toml & installed    │
│ Overlap Gate    │ 6 sensitive files verified hunk-by-hunk   │
│ Testing Gate    │ Core tests + Subsystem tests 100% green   │
│ Regression Gate │ Expected verdicts (20/20 & 8/8) pass      │
│ Hygiene Gate    │ Zero drive letters, zero stray root docs  │
│ Review Gate     │ Peer developer sign-off recorded          │
└─────────────────┴───────────────────────────────────────────┘
```

### Gate 1: Scope Gate
* **Condition:** All modified files must fall within the developer's assigned subsystem or be an authorized shared contract edit.
* **Failure Trigger:** PR contains unrelated formatting, extraneous documentation, frontend UI assets in a backend PR, or unassigned modules.
* **Remedy:** Revert out-of-scope files or split them into a dedicated PR.

### Gate 2: History Gate
* **Condition:** Commit history must be linear or contain clean merge commits without duplicate or rewritten upstream commits.
* **Failure Trigger:** Branch contains duplicate commit messages with altered SHAs, or merge-base is disconnected from `origin/main`.
* **Remedy:** Re-branch from `origin/main` and cherry-pick unique feature commits.

### Gate 3: Dependency & Import Gate
* **Condition:** All imports must resolve in a clean virtual environment without warnings or missing packages.
* **Failure Trigger:** `ModuleNotFoundError` during test collection or missing entries in `pyproject.toml`.
* **Remedy:** Declare dependency in `pyproject.toml` and verify installation via `pip install -e .`.

### Gate 4: Overlap Gate
* **Condition:** All changes to the 6 integration-sensitive files (`decisions/__init__.py`, `config.py`, `test_laya_semantic.py`, `test_cache_identity.py`, `test_calibration.py`, `test_calibration_fit.py`) must have line-by-line justification.
* **Failure Trigger:** Overwriting upstream logic, altering default parameters, or disabling upstream tests.
* **Remedy:** Reconcile differences line-by-line against `origin/main`.

### Gate 5: Testing Gate
* **Condition:** All test suites must execute and complete successfully:
  1. Core test suite: `python -m pytest tests`
  2. Subsystem test suite: `python -m pytest developer-2/tests`
  3. No runtime mocks guard: `python -m pytest tests/unit/test_no_mocks_in_runtime.py`
* **Failure Trigger:** Any failed or unexpected skipped test.
* **Remedy:** Resolve the underlying code defect before requesting review.

### Gate 6: Regression Gate
* **Condition:** Both regression gates must achieve 100% compliance:
  1. Subsystem gate: `python developer-2/tests/check_expected_verdicts.py` (20/20 passing)
  2. Core static gate: `python tests/check_expected_verdicts.py --static-only` (8/8 passing)
  3. Citation accuracy gate: `python tests/check_citation_accuracy.py` (6/6 passing)
* **Failure Trigger:** Any fixture verdict mismatch, degraded risk score, or citation failure.
* **Remedy:** Debug stage fusion or static detector logic.

### Gate 7: Documentation & Path Hygiene Gate
* **Condition:** Docs hygiene suite must pass: `python -m pytest tests/unit/test_docs_hygiene.py`.
* **Failure Trigger:** Hardcoded local drive paths, local file protocol schemes, unapproved root markdown files, or untracked UI claims.
* **Remedy:** Sanitize file paths to repository-relative format.

### Gate 8: Review & Sign-Off Gate
* **Condition:** Explicit review approval from the developer responsible for overlapping subsystems (e.g., Developer 1 approval for `fusion.py` changes).
* **Failure Trigger:** Unilateral merge without review.
* **Remedy:** Conduct synchronous review and document sign-off in the PR.

---

## 7. Practical Git Command Reference

Use these tested, non-destructive commands for routine inspection and validation.

### 7.1 Inspecting Topology & Commit Graph

```bash
# 1. Check current branch and working tree status
git status

# 2. Check remotes and tracking configuration
git remote -v
git branch -vv

# 3. Find merge-base with origin/main
git merge-base origin/main HEAD

# 4. View ahead / behind commit counts
git rev-list --left-right --count origin/main...HEAD

# 5. Inspect unique commits on feature branch not on origin/main
git log --oneline origin/main..HEAD

# 6. Graph visualization of recent branch history
git log --graph --oneline --decorate -n 15 origin/main HEAD
```

### 7.2 Inspecting Diffs & Overlapping Files

```bash
# 1. List all files modified on feature branch compared to origin/main
git diff --name-only origin/main...HEAD

# 2. Inspect diff of a specific integration-sensitive file
git diff origin/main...HEAD -- skillsentry/core/verdict/fusion.py

# 3. Check for whitespace or formatting errors
git diff --check origin/main...HEAD
```

### 7.3 Safe Synchronization (No History Rewriting)

```bash
# Recommended: Create a clean split branch directly off origin/main
git fetch origin
git checkout -b feature/<feature-name>-v2 origin/main

# Restore or cherry-pick specific commits cleanly
git cherry-pick <commit-sha>

# If merging upstream main into feature branch:
git checkout feature/<feature-name>
git fetch origin
git merge origin/main --no-ff -m "chore: synchronize feature branch with origin/main"
```

### 7.4 Aborting Interrupted Operations (Safe Recovery)

```bash
# Abort a conflicting merge without losing uncommitted work
git merge --abort

# Abort an accidental rebase safely
git rebase --abort

# Check reflog for previous commit heads if an operation goes wrong
git reflog -n 10
```

> [!CAUTION]
> **Never execute destructive commands** (`git reset --hard`, `git clean -fdx`) without first verifying that your working tree changes are committed to a backup branch (e.g., `backup/dev2-cdd2629`).

---

## 8. Merge Request Checklist & PR Report Template

Every merge request submitted for integration into `main` must include the following completed template.

### 8.1 Pre-Merge Verification Checklist

- [ ] Branch originates from verified `origin/main` head.
- [ ] Merge base confirmed (`git merge-base origin/main HEAD`).
- [ ] No duplicate or replayed commit SHAs present (`git log origin/main..HEAD`).
- [ ] All third-party dependencies declared in `pyproject.toml`.
- [ ] Full unit test suite passes cleanly (`pytest tests` and `pytest developer-2/tests`).
- [ ] Zero runtime mocks verified (`pytest tests/unit/test_no_mocks_in_runtime.py`).
- [ ] Both regression gates pass (`check_expected_verdicts.py`).
- [ ] Citation accuracy verified (`check_citation_accuracy.py`).
- [ ] Docs hygiene verified (`pytest tests/unit/test_docs_hygiene.py`).
- [ ] No hardcoded machine paths, local drive prefixes, or local file protocol URIs.
- [ ] No stray root markdown files introduced.
- [ ] Backup branch created prior to merge operation.

### 8.2 Pull Request Report Template

```markdown
### PR Identification
- **Feature Name:** [e.g., Developer 2 Split: AST Anchors & Vision Scanner]
- **Source Branch:** `feature/<name>`
- **Target Branch:** `main`
- **Merge Base SHA:** [e.g., 53b15988be0ee69374465df9d2c18ab9d40a2bb1]

### Changes Summary
- **Module(s) Modified:** [e.g., skillsentry/core/parser, skillsentry/core/vision]
- **Total Commits:** [e.g., 3]
- **Files Changed:** [Number of files]

### Sensitive File Review
- **Shared Files Modified:** [List or None]
- **Justification for Shared Modifications:** [Explanation]

### Verification & Test Evidence
- **Core Tests Result:** PASS ([number] passed, [number] skipped, 0 failed)
- **Subsystem Tests Result:** PASS ([number] passed, 0 failed)
- **Regression Gate Result:** 20/20 fixtures passing
- **Static Gate Result:** 8/8 fixtures passing
- **Citation Accuracy Result:** 6/6 fixtures passing
- **Docs Hygiene Result:** PASS (Zero path/URL/markdown violations)
- **Runtime Mock Isolation:** PASS (Zero runtime mocks)

### Prerequisite Checks
- [x] Verified evasion-floor fix (`50384dd`) present in branch history.
- [x] Verified zero frontend (`ui/`) artifacts in backend PR.
```

---

## 9. Outstanding Fixes & Prerequisite Register

This register tracks all critical cross-cutting fixes, their verified source revisions, and their current integration status across branches.

| Fix / Task Description | Responsible Owner | Source Reference / Commit | Status | Required Dependent Work | Verification Evidence |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **Evasion-Floor Override (`fusion.py`)** | Developer 1 (`PranayChandra`) | Commit `50384dd` on `origin/main` | **VERIFIED** on `origin/main` | Overrides verdict score to 100 when `Stage.EVASION` triggers. | Verified line 67 in `skillsentry/core/verdict/fusion.py` (`override_floor = 100 if override.source == Stage.EVASION else 95`). |
| **`slack-notif-mal` Sandbox Score of 100** | Developer 1 (`PranayChandra`) | `docs/checklists/dev1-backend-ai.md` | **IN PROGRESS** | Requires Developer 1 to rebase onto `50384dd` and execute sandbox harness. | Sandbox execution transcript against `fixtures/malicious/slack-notif-mal` pending verification. |
| **Audit of 6 Integration-Sensitive Files** | Developer 1 & Developer 2 | Branches `feature/developer-2` & `origin/main` | **PENDING AUDIT** | Line-by-line reconciliation of `decisions/__init__.py`, `config.py`, and test files. | Detailed hunk-by-hunk diff review before final merge into `main`. |
| **Integration of Clean Developer 2 Split** | Developer 2 | Branch `feature/developer-2-split` | **READY FOR REVIEW** | Replaces monolithic commit `cdd2629` with 3 atomic commits on top of `53b1598`. | All test suites passing, zero history rewriting, clean merge-base at `53b1598`. |
| **Frontend Web Dashboard Quarantine** | Developer 3 | Branch `parked/dashboard-ui` | **QUARANTINED** | Web dashboard development isolated to Developer 3 per `docs/checklists/dev3-frontend.md`. | Frontend files quarantined from backend Python package distribution. |

---

## 10. Document Governance & Maintenance Rules

1. **Mandatory Prior Reading:** Every developer and automated agent must review this document prior to performing any rebase, merge, or synchronization operation.
2. **Rule Modification:** No merge gate may be bypassed, skipped, or disabled. Changes to this document require explicit sign-off from all active developers.
3. **CI Automation Roadmap:**
   - **Gate 2 (History Gate):** Enforce via GitHub Actions branch protection rule: `Require linear history` or `Require branches to be up to date before merging`.
   - **Gate 5 & 6 (Testing & Regression):** Enforce via pre-merge CI job executing `pytest tests`, `pytest developer-2/tests`, and `check_expected_verdicts.py`.
   - **Gate 7 (Docs Hygiene):** Enforce via CI runner running `pytest tests/unit/test_docs_hygiene.py`.
4. **Failure Protocol:** When an integration gate fails:
   - Immediately halt the merge/rebase process.
   - Do not attempt ad-hoc force-pushes or history rewrites.
   - File an issue describing the exact gate failure and error logs.
   - Coordinate with the subsystem owner before retrying integration.

---
*(End of Mandatory Build and Merge Instructions — SkillSentry Project)*
