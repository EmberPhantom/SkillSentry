## What this changes

<!-- One or two sentences. Link the issue it closes, if any: Closes #123 -->

## Why

## How it was tested

<!-- Paste the commands you ran and their results. -->

- [ ] `scripts/check.sh` passes (lint, format, tests, schema drift, demo smoke), or the failures are explained below

## Checklist

- [ ] Unit tests cover the new logic.
- [ ] The fixture regression is green, and `tests/expected_verdicts.json` is updated if a fusion weight, prompt, anchor or masquerade rule changed.
- [ ] The Verdict JSON contract is unchanged, or the change is additive (new optional fields only) and `schemas/` is regenerated.
- [ ] Docs in `docs/` and `README.md` are updated in this PR for any user-visible change, and `CHANGELOG.md` has an entry under `[Unreleased]`.
- [ ] No new dependencies, or the rationale is in the description.
- [ ] No real credentials, private skills, or real credential formats in tests or fixtures.
- [ ] Malicious fixtures are only run through `skill-sentry-cli scan` (sandboxed).
