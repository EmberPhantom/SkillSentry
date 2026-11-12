# Overview

SkillSentry audits **agent skills** before you install them. A skill is a folder with a `SKILL.md` file and, often, scripts and images that an AI agent will read and run. SkillSentry checks the folder, runs its entrypoint inside a locked-down sandbox, asks a local model to judge whether the text matches what the code does, and returns one verdict with the evidence behind it.

**Your skills stay on your machine.** Analysis, the local model, and the reports run locally. The cloud model backend is opt-in and off by default.

## What it does

A scan returns one of four results:

| Result | Meaning |
|:---|:---|
| `SAFE` | No suspicious behavior was found. |
| `SUSPICIOUS` | Something needs a person to look at it. Each finding cites a file and line. |
| `MALICIOUS` | Hard evidence of hostile behavior, such as a decoy credential leaving the sandbox. |
| `UNSCANNED` | A stage did not finish, so the verdict cannot be trusted. The reason is printed. |

Every verdict also has a risk score from 0 to 100 and a confidence value.

## How a scan works

A scan runs these stages in order. Each one can only add evidence; a model judgment cannot override a deterministic finding.

| Stage | What it checks |
|:---|:---|
| Cache | Whether the skill is unchanged since its last scan. |
| Spec and typosquat | `SKILL.md` validity, and names that look like known skills. |
| Anchors and model | Deterministic code checks (for example, reads of credential files), then the local model's reading of the text against them. |
| Vision | Hidden text in images, such as white-on-white payloads. |
| Sandbox | The entrypoint runs on a network with no route out. Its DNS and HTTP requests go to a local sinkhole that answers with fake responses. It also has a memory limit and a time limit. |
| Poisoned Well | Decoy credentials are planted in the sandbox. Their appearance in outbound traffic is hard evidence. |
| Evasion | Probes for sandbox detection, such as `/.dockerenv`. A probe is treated as hard evidence. |
| Verdict | Weighted fusion of the signals into the score and verdict. |

The full design is in [architecture](../developer/architecture.md). The threat model and its limits are in [security](../developer/security.md).

## What ships today

- The command-line tool `skill-sentry-cli`: scan, export, cache management, readiness checks, and guided setup. See the [CLI reference](../reference/cli.md).
- Reports as Markdown, JSON, SARIF 2.1.0 (for code-scanning tools), and STIX 2.1 (for indicators of compromise).
- A local web dashboard with a triage table, a live scan console, and per-skill detail.
- A server image for running the dashboard and API in a container.
- Installers for Linux and WSL, and an installer for Windows. macOS and native Windows are best-effort; see the [support policy](../operations/governance.md#204-support-policy).
- Release images and the wheel are signed, and the release includes an SBOM. See [verify a release](../operations/release-process.md#verify-a-release).

## What is planned, not available

These are design proposals. Do not depend on them.

- A GitHub Action for pull request gates.
- A scan `--watch` mode.
- Uploading SARIF to GitHub from the CLI.
- An MCP proxy that enforces policy while an agent runs.
- Signed verdicts and a community indicator feed.
- A team server with authentication.

## Targets

These are the goals the project measures itself against. They are not guarantees, and the current figures are not yet re-measured for each release. See [testing and evaluation](../developer/testing.md).

| Target | Goal |
|:---|:---|
| Malicious fixtures detected | 2 of 2 |
| Benign fixtures wrongly flagged | 0 of 4 |
| Cached re-scan | under 2 seconds |
| Uncached scan on a typical laptop | under 90 seconds |

## Design principles

1. **Local first.** Scanning runs on your machine. The cloud backend is opt-in, and SkillSentry sends no telemetry.
2. **Evidence, not opinion.** Every `MALICIOUS` and `SUSPICIOUS` verdict cites the file and line behind it.
3. **Hard evidence wins.** A decoy credential in outbound traffic, or a sandbox-detection probe, forces `MALICIOUS` regardless of the model's reading.
4. **Fail safe.** An error never produces `SAFE`. A degraded scan reports `UNSCANNED`.
5. **Stable contracts.** The JSON verdict format is versioned and frozen. Changes are additive.

## Glossary

| Term | Meaning |
|:---|:---|
| **Agent skill** | A folder with `SKILL.md`, and often scripts and assets, that extends an AI agent. |
| **Anchor** | A deterministic finding from code analysis. The model must not contradict it. |
| **Decoy credential (canary)** | A fake credential planted in the sandbox. It carries a marker of the form `SKS-` followed by eight hexadecimal characters. |
| **Poisoned Well** | The active-defense stage: it plants decoy credentials and tracks where they go. |
| **Masquerade** | The sandbox layer that hides its own artifacts, so probing malware reveals itself. |
| **IOC** | An indicator of compromise, such as a command-and-control domain, harvested during a Poisoned Well run. |
| **Verdict** | `SAFE`, `SUSPICIOUS`, or `MALICIOUS`, with a risk score and a confidence value. |
| **SARIF** | Static Analysis Results Interchange Format, a standard machine-readable report. |

## Where to go next

- New users: the [user guide](guide.md).
- Command reference: the [CLI reference](../reference/cli.md).
- Contributors: [CONTRIBUTING.md](../../CONTRIBUTING.md) and the [developer setup](../developer/getting-started.md).
- Prior art on agent-skill and agent-tool risk: [Snyk's ToxicSkills research](https://snyk.io/blog/toxicskills-malicious-ai-agent-skills-clawhub/) and the [Agent Skills specification](https://agentskills.io/specification).
