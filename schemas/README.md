# Frozen Schemas (v1)

These files are generated from `skill_sentry/core/contracts.py`. Do not edit them
by hand.

| File | Used for |
|:---|:---|
| `verdict.v1.json` | Standalone `Verdict` JSON Schema — the frozen M0 contract. Use this for validation, cache payloads, fixtures, and report tooling. |
| `api.v1.json` | Bundle of every REST/WebSocket model, keyed by model name (`Verdict`, `ScanStartResponse`, `SkillDetail`, `WSMessage`, …). Use this to generate TypeScript types for the UI. |

## Regenerate

```bash
python scripts/export_schema.py
```

CI runs the same command and fails if `schemas/` changes, so a model edit and a
schema update must land in the same PR.

## Compatibility

- v1 is frozen. Additions must be **optional** fields.
- `Verdict.skillId` and `Verdict.scanId` are required additive fields; the
  server always supplies them.
- Canonical stage values are the §5.4 spellings (`deterministicAnchor`,
  `poisonedWell`), not the descriptive labels in §5.3.
- Every response body is camelCase; request bodies are snake_case. See
  `docs/12-contract-additions.md` §12.5.

For TypeScript generation, point your generator at `api.v1.json` and treat the
top-level keys as named schemas. `verdict.v1.json` is self-contained and can be
validated with Ajv, `jsonschema`, or Pydantic.
