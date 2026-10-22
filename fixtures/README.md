# SkillSentry fixture corpus

These packages are inert test data for the SkillSentry scanner. They are not
installed or executed outside the Docker sandbox.

| Fixture | Band | Static score (MockGemma) | Demonstrates |
|:---|:---|:---:|:---|
| `benign/pdf-summarizer` | SAFE | 0 | ordinary local file summarisation |
| `benign/git-helper` | SAFE | 0 | local git status helper |
| `benign/image-resizer` | SAFE | 0 | local image processing |
| `benign/weather-fetch` | SAFE | 0 | declared, read-only network call |
| `malicious/cloud-sync-pro` | MALICIOUS | 99 | credential read + DNS tunnelling |
| `malicious/invoice-helper` | MALICIOUS | 95 | white-on-white prompt injection in `logo.png` |
| `malicious/slack-notif-mal` | MALICIOUS | 99 | sandbox-evasion probe + Slack-token exfil over HTTP |
| `stretch/g1t-translate` | SUSPICIOUS | 30 | typosquat of `git-translate` |

The static column is verified with the real `ScanEngine` and deterministic
`MockGemma` (no Docker). Full-sandbox expectations live in
`tests/expected_verdicts.json`; they are checked only when Docker and
`skillsentry-sandbox:local` are available, and are reported as `SKIP` otherwise.

## Safety rules

- Never run `malicious/` or `stretch/` directly on a workstation. CI executes
  them only through `skillsentry scan`.
- C2 domains (`evil-collector.net`, `evil-c2.com`) are fictional and reachable
  only through the per-scan sinkhole network.
- The "credentials" read by the malicious fixtures are canaries seeded inside
  the sandbox home. No real secrets are included.
- Exfiltration fixtures use plain HTTP because M1 does not intercept TLS;
  HTTPS evidence is explicitly unverified.
- `fixtures/` is excluded from packaging.

## Acceptance harness

```bash
# static (real engine + MockGemma, no Docker)
python tests/check_expected_verdicts.py --static-only

# full Docker-dependent scan; exits 3 and prints SKIP when prerequisites are absent
python tests/check_expected_verdicts.py --full

# validate an existing SARIF/JSON report
python tests/check_expected_verdicts.py results.sarif --allow-static
python tests/check_expected_verdicts.py results.sarif
```
