# SkillSentry Test Fixtures

Curated corpus of 20 AI Agent Skill packages for testing the analysis pipeline.

## Safety Rules

1. **Fictional domains only** — all malicious fixtures use `evil-collector.net`, `evil-c2.com`, etc.
2. **Fake credentials only** — `AKIA...`, `SKS-...`, never real secrets.
3. **WARNING headers** — every malicious script has a prominent warning comment.
4. **No host execution** — fixtures exist for static analysis testing; never execute scripts.

## Fixture Inventory

### Benign Fixtures (12)

| Fixture | Expected Verdict | Risk | Purpose |
|---------|:----------------:|:----:|---------|
| `benign/pdf-summarizer` | SAFE | 3 | Pure text processing, zero anchors |
| `benign/git-helper` | SAFE | 3 | Git wrapper, must NOT FP vs git-translate |
| `benign/image-resizer` | SAFE | 3 | Local Pillow processing only |
| `benign/weather-fetch` | SAFE | 6 | Declared urllib — proves no FP on legit network |
| `benign/csv-analyzer` | SAFE | 3 | File-heavy CSV stats with stdlib only |
| `benign/markdown-formatter` | SAFE | 11 | Regex text processing, zero dangerous APIs |
| `benign/docker-compose-helper` | SAFE | 16 | subprocess.run without shell=True (must NOT trigger subprocess_shell) |
| `benign/slack-notifier` | SAFE | 28 | Declared Slack webhook usage (borderline but correctly SAFE) |
| `benign/ssh-keygen-helper` | SAFE | 3 | Generates new SSH keys, never reads existing private keys |
| `benign/multi-lang-tool` | SAFE | 3 | Multi-language (.py + .sh + .js), all benign scaffolding |
| `benign/json-formatter` | SAFE | 3 | Pure JSON formatting, zero side effects |
| `benign/backup-tool` | SAFE | 3 | Local zipfile operations, no network |

### Malicious Fixtures (8)

| Fixture | Expected Verdict | Risk | Threat Class | Key Anchors |
|---------|:----------------:|:----:|:-------------|:------------|
| `malicious/invoice-helper` | MALICIOUS | 76 | Credential theft + exfil | credential_read, base64, requests_post |
| `malicious/g1t-translate` | SUSPICIOUS | 50 | Typosquat-only | Homoglyph '1'→'i' impersonation |
| `malicious/obfuscation-only` | SUSPICIOUS | 62 | Obfuscation chain | exec, base64, codecs.decode, rot13 |
| `malicious/instruction-poisoning` | SUSPICIOUS | 45 | Hidden instructions | HTML comment with agent manipulation in SKILL.md |
| `malicious/svg-borne` | MALICIOUS | 71 | SVG injection | `<script>` + `<foreignObject>` in badge.svg |
| `malicious/dns-tunneler` | SUSPICIOUS | 62 | DNS exfiltration | nslookup, credential_read (bash) |
| `malicious/sl4ck-bot` | MALICIOUS | 77 | Typosquat + cred theft | '4'→'a' homoglyph + SLACK_BOT_TOKEN + exfil |
| `malicious/credential-multi` | SUSPICIOUS | 62 | Multi-credential harvest | AWS + SSH + GITHUB_TOKEN + base64 + exfil |

### Risk Score Notes

Fixtures marked **SUSPICIOUS** (not MALICIOUS) are scored without the sandbox execution stage (Stage 4, Dev 1).
With sandbox integration adding the 0.25 weight, obfuscation-only, dns-tunneler, and credential-multi are expected to escalate to MALICIOUS.

## Ground Truth

- `tests/ground_truth.json` — exact line number annotations for anchor patterns
- `tests/expected_verdicts.json` — expected verdicts, risk bands, and required findings
- `tests/fixtures_canned_payloads.json` — Verdict JSON v1 payloads for Dev 1 demo mode

## Detection Metrics

| Metric | Value |
|--------|:-----:|
| Precision | 1.000 |
| Recall | 1.000 |
| F1 Score | 1.000 |
| False Positive Rate | 0.000 |

Full methodology: `developer-2/docs/precision-recall-report.md`
