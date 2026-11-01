# SkillSentry

**Audit agent skills before you install them.** SkillSentry checks a skill's text and scripts, runs its entrypoint inside a locked-down Docker sandbox, and returns one verdict: `SAFE`, `SUSPICIOUS`, `MALICIOUS`, or `UNSCANNED` when the scan could not finish. Analysis runs on your machine through a local model, and nothing is uploaded.

## Install

```bash
pipx install skill-sentry-cli        # or: python -m pip install skill-sentry-cli
skill-sentry-cli setup              # checks Docker and the local model, builds the sandbox
skill-sentry-cli doctor             # confirms the setup is ready
```

Requirements: Python 3.11 to 3.13, Docker (for the sandbox), and [Ollama](https://ollama.com) for the local model. `skill-sentry-cli doctor` tells you the exact command for anything missing.

## First scan

```bash
skill-sentry-cli scan path/to/my-skill
skill-sentry-cli scan path/to/skills-folder --format sarif --sarif-out results.sarif
```

Exit codes: `0` below the gate, `1` at or above it, `2` a usage error, `3` an operational error. The default gate is `--fail-on suspicious`.

## Documentation

- [User guide](https://github.com/EmberPhantom/SkillSentry/blob/main/docs/16-user-guide.md): install, first scans, reports, dashboard, CI, troubleshooting.
- [CLI reference](https://github.com/EmberPhantom/SkillSentry/blob/main/docs/07-cli-reference.md)
- [Security model](https://github.com/EmberPhantom/SkillSentry/blob/main/docs/04-security.md)
- [Source and issues](https://github.com/EmberPhantom/SkillSentry)

MIT licensed.
