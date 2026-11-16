# OpenSSF Scorecard decisions

The Scorecard workflow (`.github/workflows/scorecard.yml`) reports to the repository's code-scanning alerts. This page records what we did about each structural check and why. Update it when a decision changes.

## Pinned dependencies

Every dependency install is hash-locked and uses `--require-hashes`:

| Context | Install | Lock file |
|:---|:---|:---|
| CI tests and lint | `pip install --require-hashes -r requirements-dev.txt`, then the project with `--no-deps` | `requirements-dev.txt` |
| CI and release build tools | `pip install --require-hashes -r requirements-tools.txt` | `requirements-tools.txt` |
| Release SBOM tool | `pip install --require-hashes -r requirements-sbom.txt` | `requirements-sbom.txt` |
| Server image (`Dockerfile`) | runtime dependencies from `requirements-runtime.txt`; the project wheel, built in an earlier stage, is installed by its hash with `--no-deps` | `requirements-runtime.txt` |
| Sandbox image (`Dockerfile.sandbox`) | `pip install --require-hashes -r requirements-sandbox.txt` | `skill_sentry_cli/core/sandbox/assets/requirements-sandbox.txt` |

These installs are deliberately not hash-locked, because their job is to resolve the wheel the way a user does:

- The clean-environment install in `ci.yml`, which checks that the built wheel's metadata installs and runs.
- The SBOM environment in `release.yml`, so the SBOM lists what a user's `pip install` gets.
- The user installers (`install.sh`, `install.ps1`) and the wheel check in `scripts/build_release.sh`, which install the released wheel for an end user.

Regenerate every lock with `scripts/lock.sh` (needs `uv`). Dependabot's `pip` entries cover `/` and the sandbox folder; its version bumps to a compiled lock must be checked against `scripts/lock.sh` output in the pull request.

## Structural checks

| Check | Decision | Reason |
|:---|:---|:---|
| Security-Policy | Addressed | `SECURITY.md` now links the private reporting form directly. Private vulnerability reporting is enabled on the repository. |
| SAST | Addressed | CodeQL runs on pull requests and on a schedule (`.github/workflows/codeql.yml`), covering Python, JavaScript/TypeScript and Actions. |
| CI-Tests | Addressed | CI runs lint, types, unit and contract tests on Linux, macOS and Windows for every pull request. |
| Code-Review | Accepted | The repository has one maintainer, so no change has an approving reviewer who is not its author. Pull requests are still required, CI must pass, and changes get a second, independent review before merge. The score stays low until a second approver exists. |
| Maintained | Accepted | The check scores 0 for any repository younger than 90 days. It clears with time and ongoing commits and Dependabot activity. |
| Fuzzing | Accepted for now | No fuzzer is integrated. The package parsers (front matter, manifests, report rendering) are good candidates for property-based tests. That adds a dependency and a CI job, so it needs its own decision. |
| CII-Best-Practices | Accepted for now | Earning the badge means the maintainer registering the project at bestpractices.dev and answering its questionnaire. That is a manual, outward-facing step. |

## Alerts expected to remain

After this change, the open code-scanning alerts should be the Scorecard checks marked Accepted above (Code-Review, Maintained, Fuzzing, CII-Best-Practices). Security-Policy and the Dockerfile pinning alert should clear on the next Scorecard run. One CodeQL alert in a test file (`py/incomplete-url-substring-sanitization`) is separate from Scorecard and is not covered here.
