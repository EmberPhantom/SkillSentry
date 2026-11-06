# 17 · Release process (maintainers)

This is the runbook for publishing a version of SkillSentry. It has two parts: the steps only a maintainer with the accounts can do, and what the release workflow does once a tag is pushed.

**Names.** The Python distribution is `skill-sentry-cli`, the module is `skill_sentry_cli`, and the command is `skill-sentry-cli`. The product is still called SkillSentry. The sandbox image is published as `skillsentry-sandbox` and the server image as `skill-sentry-server`, both under `ghcr.io/emberphantom`.

## 1. One-time setup (maintainer)

Create the accounts and register the trusted publishers as described in [18-registry-accounts.md](18-registry-accounts.md). That manual covers both indexes, two-factor setup, the pending publisher values, and recovery.

In the repository settings, the following is also needed:

- **Environments:** `testpypi` (no protection rules) and `pypi` (required reviewer, so no one can publish alone).
- **Packages:** after the first image push, set `skillsentry-sandbox` and `skill-sentry-server` to public, so anyone can pull them.
- **Branch protection on `main`:** the pull request needs one approving review from a code owner, and these checks must pass before merge: `Lint + contract tests (Python 3.11)`, `Lint + contract tests (Python 3.12)`, `Lint + contract tests (Python 3.13)`, `Demo server smoke test`, and `Dashboard build (Node 24)`. The Windows, macOS, installer, and Python 3.14 jobs are informational. The maintainer may bypass the review requirement; see [docs/20 §20.5](20-governance.md#205-maintainer-settings-checklist).

## 2. Cutting a pre-release (dry run)

```bash
# On main, after the change set is merged:
#   1. set __version__ in skill_sentry_cli/core/version.py, and VERSION in install.sh
#      and the default -Version in install.ps1, to the new version, e.g. 2.1.0rc3
#   2. move the matching notes into docs/CHANGELOG.md under a new version heading
#   3. merge that pull request, then tag the merge commit
#
# A version tag is never moved or reused. Check first with `git tag -l 'v*'`.
git tag -a v2.1.0rc3 -m "SkillSentry 2.1.0rc3"
git push origin v2.1.0rc3
```

The workflow then publishes to TestPyPI and creates a GitHub pre-release. Install it in a clean environment to check it:

```bash
python3.12 -m venv /tmp/rc-check && . /tmp/rc-check/bin/activate
python -m pip install --index-url https://test.pypi.org/simple/ \
  --extra-index-url https://pypi.org/simple/ skill-sentry-cli==2.1.0rc3
skill-sentry-cli --version
```

## 3. Final release

Only after the release candidate checks out:

```bash
git tag -a v2.1.0 -m "SkillSentry 2.1.0"
git push origin v2.1.0
```

The `Checks` and `Build artifacts` jobs run. The `Publish to PyPI (approval required)` job then waits for a reviewer to approve the `pypi` environment. Approve it only after you have checked the build's artifacts and the release notes. Once published, a version can never be re-uploaded, so a broken release gets a new version number.

## 4. What the workflow produces

| Artifact | Where it goes |
|:---|:---|
| `skill_sentry-<v>-py3-none-any.whl`, `skill_sentry-<v>.tar.gz` | PyPI (or TestPyPI for rc), GitHub release |
| `install.sh` | GitHub release |
| `SHA256SUMS` | GitHub release; `install.sh` verifies the wheel against it |
| Build provenance attestations | Attached to the wheel and sdist |
| `sbom.cdx.json` (CycloneDX 1.6) | GitHub release. Lists every package the wheel installs. |
| Sandbox image, both architectures | `ghcr.io/emberphantom/skillsentry-sandbox:<v>`; its digest is written into the wheel |
| Server image, both architectures | `ghcr.io/emberphantom/skill-sentry-server:<v>` |
| Image signatures and provenance | Both images, signed keyless by digest; BuildKit SBOM and provenance are attached to the images |

The sandbox digest is written into `skill_sentry_cli/data/sandbox_image.json` before the wheel is built. `skill-sentry-cli setup` pulls that exact digest, so an installed version uses the image it shipped with. Source checkouts have no digest and build the image locally.

### Verify a release

Signatures are keyless: the certificate names the release workflow and the tag it ran from, so no key has to be trusted in advance.

```bash
# Server image: the signature must come from a release tag of this repository's workflow.
cosign verify ghcr.io/emberphantom/skill-sentry-server:<v> \
  --certificate-identity-regexp '^https://github.com/EmberPhantom/SkillSentry/\.github/workflows/release\.yml@refs/tags/v' \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com

# Wheel: the provenance attestation names the repository and the commit it was built from.
gh attestation verify skill_sentry_cli-<v>-py3-none-any.whl --repo EmberPhantom/SkillSentry
```

The same identity check applies to the sandbox image. Compare the SBOM with the installed environment with any SBOM reader, for example `cyclonedx-py environment` run against your own venv.

## 5. Checks before tagging

Build the dashboard before the sdist: the sdist carries the built dashboard, and a build without it fails. `scripts/build_release.sh` does this in order.

```bash
python -m pip install -e ".[dev]"
ruff check skill_sentry_cli tests scripts && ruff format --check skill_sentry_cli tests scripts
pytest tests -q
scripts/build_release.sh      # dashboard, wheel, fresh-venv install
python scripts/check_wheel.py dist/*.whl
```

## 6. Limits

- The workflow itself runs only on GitHub. A real tag is the only full test of it. The image signing, image SBOM and provenance steps have not run on GitHub yet, so the first release candidate must be checked with the commands in "Verify a release" before a final tag.
- The SBOM steps were reproduced locally against a built wheel, not in CI.
- Windows has an installer (`install.ps1`) that has not been verified on real machines. macOS has not been verified.
- Hardware for the ARM image is built in CI and not exercised here.
