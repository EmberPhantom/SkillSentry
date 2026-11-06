# 20 · Governance

> How SkillSentry is maintained, who decides what, how releases are cut, and what is supported. Contributors should read this with [CONTRIBUTING.md](../../CONTRIBUTING.md); participation is covered by the [Code of Conduct](../../.github/CODE_OF_CONDUCT.md).

---

## 20.1 Roles

| Role | Who | Can do |
|:---|:---|:---|
| **Maintainer** | The repository owner, `@EmberPhantom` (see [CODEOWNERS](../../.github/CODEOWNERS)) | Merge pull requests, push release tags, approve the `pypi` publishing environment, handle security reports, make decisions in 20.2 |
| **Contributor** | Anyone who opens an issue or pull request | Propose changes; review; discuss |
| **Community** | Users and reporters | File issues, join discussions, report vulnerabilities privately |

SkillSentry has one maintainer account today. Adding maintainers means adding their handles to CODEOWNERS and granting them repository access; this document then applies to all of them.

## 20.2 How decisions are made

**Routine changes** (bug fixes, documentation, new detections that do not change scoring) need one maintainer review, green CI, and the checklist in the [pull request template](../../.github/PULL_REQUEST_TEMPLATE.md).

**Decisions that need an explicit maintainer decision**, recorded in the pull request or an issue before merge:

- the Verdict JSON contract and the schemas in `schemas/` (see [docs/05](../reference/api.md) §5.5)
- fusion weights, tier thresholds, and the list of stages
- sandbox hardening and the network sinkhole
- Poisoned Well canary formats and marker rules
- the community IOC feed (opt-in, not implemented yet; see [docs/04](../developer/security.md) §4.10)
- any change that makes a verdict less strict, such as a new path to `SAFE`

A breaking contract change needs a new contract version, a migration path, and a changelog entry. Additive changes (new optional fields) are the default route.

**Disagreements** are settled in the issue or pull request. If they cannot be settled there, the maintainer decides and writes down the reason in that thread, so the decision can be found later.

## 20.3 Releases

- Only maintainers push tags that match `v*`. The release workflow ([docs/17](release-process.md)) builds, tests, signs the images, and attaches the SBOM.
- Release candidates (`vX.Y.ZrcN`) publish to TestPyPI and to a GitHub pre-release.
- Final tags publish to PyPI only after a reviewer approves the `pypi` environment.
- Every release is checked with the commands in [docs/17 §4, Verify a release](release-process.md#verify-a-release) before its notes are published.

## 20.4 Support policy

| Item | Policy |
|:---|:---|
| Security fixes | The current release line, as listed in [SECURITY.md](../../SECURITY.md#supported-versions). |
| Python | 3.11, 3.12, and 3.13 are supported. 3.14 is tested in CI as a non-blocking check and is not supported yet. |
| Linux | Supported. Ubuntu-class systems are what CI and the release build use. |
| WSL 2 | Best-effort. Requires Docker Desktop with WSL integration for sandbox scans. |
| macOS and native Windows | Best-effort and not verified on real machines. Installers exist. |
| Local model backend (Ollama) | Supported. Verdicts depend on the model you install, so pin it in your configuration. |
| Cloud model backend | Opt-in and outside the support commitment. Skill content leaves your machine when it is used. |

Response times are targets, not guarantees. [SUPPORT.md](../../.github/SUPPORT.md) describes where to ask for help.

## 20.5 Maintainer settings checklist

Nothing in this section has been applied. A maintainer runs these once, after reading them. Each command changes the public GitHub repository.

```bash
# 1. Private vulnerability reporting, which SECURITY.md relies on.
gh api -X PUT repos/EmberPhantom/SkillSentry/private-vulnerability-reporting

# 2. Description, topics, Discussions, and deleting merged branches.
gh repo edit EmberPhantom/SkillSentry \
  --description "Audit AI agent skills before you install them. Local, sandboxed, with active defense." \
  --add-topic agent-skills --add-topic supply-chain-security --add-topic sandbox \
  --enable-discussions --delete-branch-on-merge

# 3. Branch protection on main: required checks, one approving review, code-owner review,
#    no force pushes, no deletion. Save the JSON below as protection.json first.
gh api -X PUT repos/EmberPhantom/SkillSentry/branches/main/protection --input protection.json

# 4. Dependabot alerts and automated security updates.
gh api -X PUT repos/EmberPhantom/SkillSentry/vulnerability-alerts
gh api -X PUT repos/EmberPhantom/SkillSentry/automated-security-fixes

# 5. Secret scanning and push protection. Save the JSON below as security.json first.
gh api -X PATCH repos/EmberPhantom/SkillSentry --input security.json
```

`protection.json`:

```json
{
  "required_status_checks": {
    "strict": true,
    "contexts": [
      "Lint + contract tests (Python 3.11)",
      "Lint + contract tests (Python 3.12)",
      "Lint + contract tests (Python 3.13)",
      "Demo server smoke test",
      "Dashboard build (Node 24)"
    ]
  },
  "enforce_admins": true,
  "required_pull_request_reviews": {
    "required_approving_review_count": 1,
    "require_code_owner_reviews": true
  },
  "restrictions": null,
  "allow_force_pushes": false,
  "allow_deletions": false
}
```

`security.json`:

```json
{
  "security_and_analysis": {
    "secret_scanning": { "status": "enabled" },
    "secret_scanning_push_protection": { "status": "enabled" }
  }
}
```

Before you run these:

- The `contexts` names must match the job names shown in a real CI run. Open one pull request, check the names on its checks page, then update the list. A wrong name blocks every merge.
- The endpoint paths are the GitHub REST API names. `gh api` does not check them ahead of time, so run each command once and read the response.
- `gh repo edit` flags were checked against `gh repo edit --help`.

## 20.6 Changing this document

Changes to governance go through a pull request, like any other change, and need the maintainer's approval. Record the reason in the pull request description.
