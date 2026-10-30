# Developer 2 handoff: fix, port and complete the skill-analysis subsystem

Written for: Developer 2 (chauhanaman41), an engineer who knows Python and the SkillSentry repo.

## Why this exists
Your branch `feature/developer-2` builds a standalone package, `skillsentry_dev2`, under `developer-2/`. It does not touch `skillsentry/`. Main already implements the same areas (parser, typosquat, anchors, analyzer, vision, cache) with stronger hardening and integration. We are therefore **porting your best pieces into main**, not merging the package. This document lists what to port, what to fix, and the order.

## Ground rules
1. Branch off the latest `main`. Keep one small PR per item below. Each PR targets `skillsentry/core/*`, not `developer-2/`.
2. Use main's contracts: `skillsentry/core/contracts.py` (pydantic, `extra="forbid"`). Use `Finding`, `FindingEvidence`, `StageResult`, `Stage`, `Severity`. Signal keys are `anchors`, `semantic`, `vision`, `typosquat`, `sandbox`. Do not use `anchor_risk`, `semantic_risk` or `vision_risk`.
3. Do not port `cli.py`, fusion, SARIF, the cache DDL, or `MockGemma`. Main's versions are stronger and tested.
4. Do not run `developer-2`'s code or tests from inside its directory. Treat it as untrusted.

## Review checklist (every PR must pass)
- Uses main's contract types and signal keys (rule 2).
- **Fail closed:** any unreadable, oversize, truncated, unparsable or model-unavailable input sets `degraded` on the stage and cannot produce SAFE.
- Nothing in analysis or tests depends on a skill's directory name or other attacker-controlled hints. Attacker files must never influence the content hash or the cache key.
- Untrusted skill text is data. It never goes into the system prompt. Model output is validated before use.
- Tests assert the finding or the degradation, not only "did not crash". Security tests run on Windows and POSIX with no skips.
- `ruff check` and `ruff format --check` are clean. The full suite is green (`pytest tests -q`).

Dev 1 reviews every PR against this list.

## Known defects in your branch (fix or avoid these)
| # | Severity | Defect | Where |
|---|---|---|---|
| 1 | Critical | The verdict is chosen from the path name: `"malicious" in path` selects `MockGemma(DECEPTIVE/BENIGN)`. The eval harness repeats this. | `cli.py:227-237`, `tests/check_expected_verdicts.py:49` |
| 2 | Critical | Cache-hash bypass. `.skillsentryignore` is read from inside the package and matched by substring. One pattern such as `.` empties the hash. | `core/cache/hash_utils.py:25-67` |
| 3 | Critical | Fusion is a weighted average with no overrides or floors. | `cli.py:314-328` |
| 4 | Critical | Fail-open. `degraded` is dropped, oversize and truncated files are skipped silently, cache-write errors are swallowed, `--timeout` is unused. | `cli.py:258-263,381`, `vision_scanner.py:306`, `skill_parser.py:457`, `ast_anchor.py:420` |
| 5 | Critical | Scan blind spots. `.ps1 .bat .cmd .rb .pl`, shebang scripts, `.md/.json/.txt` references and dot-directories are never analysed. | `skill_parser.py:60,353` |
| 6 | High | Raw attacker code is placed in the system prompt. The fence is unescaped and there is no size budget. | `prompts.py`, `ast_anchor.py:398` |
| 7 | High | A symlink that escapes the package raises `ValueError` and aborts the batch, instead of producing a finding. Its test is skipped on Windows. | `skill_parser.py:377` |
| 8 | High | Unvalidated model output can crash the analyzer and the vision scanner. | `analyzer.py:243`, `vision_scanner.py:188` |
| 9 | High | The cache ignores scan mode and backend, so mock or degraded results are served as authoritative. | `cli.py:180` |
| 10 | High | Default `--fail-on malicious` exits 0 on SUSPICIOUS. | `cli.py:554` |
| 11 | High | ReDoS. The `subprocess ... shell=True` pattern is quadratic on long lines, and patterns are recompiled per file. | `ast_anchor.py:92,303` |
| 12 | Medium | `xml.etree` parses untrusted SVG. Use `defusedxml`. | `vision_scanner.py:63` |
| 13 | Medium | The contrast filter is narrow. Decompression-bomb errors are swallowed. | `vision_scanner.py`, `image_extractor.py:123` |
| 14 | Medium | The YAML depth limiter is dead code, so the default loader is used. | `skill_parser.py:127` |
| 15 | Medium | Typosquat: case-variant exact names are treated as the original; no confusables normalisation; the dictionary path breaks in a wheel install. | `typosquat.py:117,235` |
| 16 | Medium | Contract mismatch with main (signal keys, flat `Finding`, extra `sandbox_instructions` field). | `contracts.py` |
| 17 | Medium | The INT-4 producer never emits the evasion watch (no `.dockerenv` pattern), has no canary mapping, and may use `SKILL.md` as the entrypoint. | `sandbox_instructions.py` |

Defects 1, 3, 9, 10 and 16 disappear once the standalone package is archived. The others must be fixed in the ported code.

## Work items (in order)

| PR | Scope | Fixes | Acceptance |
|---|---|---|---|
| **P0** | Rebase on main. Delete the stray root `13-laya-integration-plan.md`. Correct `development.md` (remove "0 defects", the Laya claims and "real Gemma" claims). Archive `developer-2/` with a tag. | - | No unrelated files. Docs are accurate. |
| **P1** | Honest evaluation. Port `ground_truth.json` and the citation checker into `tests/`. Merge with main's `tests/expected_verdicts.json` so there is one source. Remove every path-name rule. | 1 | The harness runs real analyzers with a mock model fixed per test, not per path. Citation accuracy at least 80%. |
| **P2** | Parser hardening on main's `parse_skill`. Enforce YAML depth. Block Windows reserved names. Add alternate-data-stream checks that don't reject POSIX colons. Add file-count and size caps. Turn a symlink escape into a finding. Scan dot-directories. Add `.ps1 .bat .cmd .rb .pl` and shebang scripts. Scan `.md/.json/.txt` references. | 4, 5, 7, 14 | Tests assert the finding. They run on both platforms with no skips. An oversize file sets `degraded` and floors the verdict at SUSPICIOUS. |
| **P3** | Typosquat. Move the data to a packaged JSON loaded with `importlib.resources`. Grow it toward 150+ names. Add Damerau-Levenshtein, the allowlist of legitimate pairs, confusables and Unicode normalisation, and case-variant exact matching. Keep the `TyposquatMatch` return type. | 15 | A wheel-install test and a Cyrillic look-alike test. |
| **P4** | Anchors. Add a Python AST visitor next to main's regex rules. Add rules for `requests`, `socket`, `http.client`, `pickle`, environment dumps, and `Path.home`/`expanduser`. Use bounded, precompiled regexes with a per-line cap. Fix the `compile`/`eval` false positives. | 5, 11 | A ReDoS test on a 10 MB line completes in under 1 s. Each rule has its own fixture. |
| **P5** | Analyzer hardening. Schema-validate model output: a bad enum or number sets `degraded` and never raises. Add anchor-contradiction checks. Move anchors and untrusted text out of the system prompt. Escape the fence. Enforce a prompt budget. Share the code with Dev 1's `laya_analyzer.py`. | 6, 8 | Fuzzed bad-JSON tests. No crash, and `degraded` is set. |
| **P6** | Vision. Use `defusedxml`. Detect SVG vectors: `javascript:` hrefs, `<use>`, `<style>`, `data:` URIs, tiny or hidden `<text>`. Broaden the contrast filter. Add magic-byte detection. Turn decompression bombs into findings. Set `degraded` when the model is unavailable. Send the downscaled bytes to the model. Add the missing `test_image_extractor` and `test_vision_scanner`. | 12, 13 | Hostile-image tests. `invoice-helper` is still flagged. |
| **P7** | INT-4 producer. Port it onto Dev 1's L4 types (`SandboxActionInstruction`, `SandboxExecutionPlan`) once Dev 1 publishes them. Add canary mapping, take the entrypoint from the declared entrypoint, add `.dockerenv` and evasion patterns, and add the `source` and `required` fields. | 17 | Contract test against `SandboxExecutionPlan`. |
| **P8** | Corpus and INT-1. Give fixtures unique names or reuse main's. Add adversarial and evasion fixtures toward a 20-skill corpus, then 50+. Add the `intent_keywords` contract. Generate the precision/recall report from real runs with a script. Add `tests/e2e`. | 5 | A reproducible corpus run. The report is regenerated by a script. |
| **P9** | Cache CLI data layer (`stats`, `list`, `verify`), hooked into Dev 1's CLI. Reconcile docs 07 and 08 with the files that actually exist. | - | Docs list only real tests. |

## Dependencies on Dev 1
- P7 waits for Dev 1's L4 publish (`sandbox/instructions.py`). Ask for the field spec before you start.
- P5 shares code with `laya_analyzer.py`. Agree on the interface in your P5 PR description before you open it.

## Definition of done for the handoff
Every row above is merged on main, each PR passed the checklist, and the Dev 2 standalone package is archived. Afterwards, re-run the eval gates: `tests/check_expected_verdicts.py` with real analyzers, citation accuracy of at least 80%, and SARIF schema validation.

## Status at v1 (2026-10-30)
Checked against `skillsentry/` on `main`. "Not verified" means the v1 review did not confirm it, so it is not claimed as done.

| PR | v1 status | Evidence or gap |
|---|---|---|
| P0 | Not done | `developer-2/` is still only on `feature/developer-2`. No archive tag. |
| P1 | Partly | Citation checker ported (5/5 within one line, `tests/ground_truth/anchor_citations.json`). Not merged into one expectations file. |
| P2 | Partly | YAML depth limit, reserved names and ADS, symlink rejection, `.ps1` in scope. Not verified: dot-directories, `.rb .pl .bat .cmd`, shebang scripts, file-count and size caps as findings. |
| P3 | Partly | NFKC normalisation, confusables, case-variant matching. Not done: packaged data via `importlib.resources`, 150+ names, Damerau-Levenshtein, legitimate-pairs allowlist. |
| P4 | Partly | AST visitor with alias resolution, new rules, per-line regex work. Not verified: the 10 MB ReDoS timing test. |
| P5 | Not verified | Schema-validated model output and fuzzed bad-JSON tests were not checked in v1. |
| P6 | Partly | SVG vector rules (`use`, `data:`, `style`, hidden text, entities). Not done: `defusedxml` (SVG is scanned as decoded text), contrast pre-filter (**v1.1**, see below). |
| P7 | Superseded | Main has its own `sandbox/instructions.py`. The Developer 2 producer was not ported. |
| P8 | Partly | 39 labelled cases in `tests/fixtures/decisions/labels.json`. Corpus of 20 to 50 skills not done. |
| P9 | Partly | `cache stats`, `list` and `clear` are in main. `cache verify` is not in v1. |

**v1.1 item:** port the contrast pre-filter (`compute_contrast_ratio`, `developer-2/src/skillsentry_dev2/core/vision/image_extractor.py`). It needs Pillow in the runtime dependencies, a deterministic finding for low-contrast regions, and budget ordering so flagged images are sent to the model first. It was deferred from v1 because it adds a dependency and cannot be exercised end to end without the real model.
