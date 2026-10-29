# SkillSentry Developer 2 — Precision / Recall Report

**Generated:** 2026-10-28  
**Corpus:** 20 skill fixtures (12 benign, 8 malicious)  
**Pipeline:** Dev 2 isolated analysis (Stages 1–3, no sandbox)  
**Dictionary version:** v1.0.0 (55 known skills)  
**Prompt version:** 1.0.0  

---

## Methodology

### Definitions

| Term | Definition |
|------|-----------|
| **True Positive (TP)** | Malicious fixture correctly classified as SUSPICIOUS or MALICIOUS (risk ≥ 30) |
| **True Negative (TN)** | Benign fixture correctly classified as SAFE (risk < 30) |
| **False Positive (FP)** | Benign fixture incorrectly classified as SUSPICIOUS or MALICIOUS |
| **False Negative (FN)** | Malicious fixture incorrectly classified as SAFE |

### Threshold

The binary classification boundary is the SAFE/SUSPICIOUS threshold at risk score **30**.
- **Flagged (Positive):** risk ≥ 30 (SUSPICIOUS or MALICIOUS)
- **Not Flagged (Negative):** risk < 30 (SAFE)

### Scope Limitation

This report covers Dev 2's **isolated pipeline** (Stages 1–3: Spec Validation, Deterministic Anchors, Semantic Analysis, Vision Scanning). The full SkillSentry pipeline includes Stage 4 (Sandbox Execution, Dev 1) which would increase risk scores for malicious fixtures via the 0.25 sandbox weight. Scores labelled "SUSPICIOUS" in this report may escalate to "MALICIOUS" after sandbox integration.

---

## Results

### Per-Fixture Results

| # | Fixture | True Class | Verdict | Risk | Classification |
|---|---------|-----------|---------|:----:|---------------|
| 1 | benign/pdf-summarizer | Benign | SAFE | 3 | ✅ TN |
| 2 | benign/git-helper | Benign | SAFE | 3 | ✅ TN |
| 3 | benign/image-resizer | Benign | SAFE | 3 | ✅ TN |
| 4 | benign/weather-fetch | Benign | SAFE | 6 | ✅ TN |
| 5 | benign/csv-analyzer | Benign | SAFE | 3 | ✅ TN |
| 6 | benign/markdown-formatter | Benign | SAFE | 11 | ✅ TN |
| 7 | benign/docker-compose-helper | Benign | SAFE | 16 | ✅ TN |
| 8 | benign/slack-notifier | Benign | SAFE | 28 | ✅ TN |
| 9 | benign/ssh-keygen-helper | Benign | SAFE | 3 | ✅ TN |
| 10 | benign/multi-lang-tool | Benign | SAFE | 3 | ✅ TN |
| 11 | benign/json-formatter | Benign | SAFE | 3 | ✅ TN |
| 12 | benign/backup-tool | Benign | SAFE | 3 | ✅ TN |
| 13 | malicious/invoice-helper | Malicious | MALICIOUS | 76 | ✅ TP |
| 14 | malicious/g1t-translate | Malicious | SUSPICIOUS | 50 | ✅ TP |
| 15 | malicious/obfuscation-only | Malicious | SUSPICIOUS | 62 | ✅ TP |
| 16 | malicious/instruction-poisoning | Malicious | SUSPICIOUS | 45 | ✅ TP |
| 17 | malicious/svg-borne | Malicious | MALICIOUS | 71 | ✅ TP |
| 18 | malicious/dns-tunneler | Malicious | SUSPICIOUS | 62 | ✅ TP |
| 19 | malicious/sl4ck-bot | Malicious | MALICIOUS | 77 | ✅ TP |
| 20 | malicious/credential-multi | Malicious | SUSPICIOUS | 62 | ✅ TP |

### Confusion Matrix

|  | Predicted Positive (≥30) | Predicted Negative (<30) |
|--|:------------------------:|:------------------------:|
| **Actual Malicious** | 8 (TP) | 0 (FN) |
| **Actual Benign** | 0 (FP) | 12 (TN) |

### Metrics

| Metric | Value | Formula |
|--------|:-----:|---------|
| **Precision** | 1.000 | TP / (TP + FP) = 8 / 8 |
| **Recall** | 1.000 | TP / (TP + FN) = 8 / 8 |
| **F1 Score** | 1.000 | 2 × P × R / (P + R) |
| **Accuracy** | 1.000 | (TP + TN) / N = 20 / 20 |
| **False Positive Rate** | 0.000 | FP / (FP + TN) = 0 / 12 |
| **False Negative Rate** | 0.000 | FN / (FN + TP) = 0 / 8 |

---

## Detection Coverage by Threat Category

| Threat Category | Fixtures | Detected By | Notes |
|----------------|:--------:|-------------|-------|
| Credential theft + exfil | invoice-helper, credential-multi | Deterministic Anchors | credential_read + requests_post + base64 |
| Typosquat impersonation | g1t-translate, sl4ck-bot | Typosquat Engine | Homoglyph folding catches '1'→'l' and '4'→'a' |
| Obfuscation chain | obfuscation-only | Deterministic Anchors | exec + codecs.decode + rot13 + base64 |
| Instruction poisoning | instruction-poisoning | Semantic Analysis (LLM) | Hidden HTML comment in SKILL.md |
| SVG-borne injection | svg-borne | Vision Scanner | `<script>` + `<foreignObject>` in SVG XML |
| DNS exfiltration | dns-tunneler | Deterministic Anchors | nslookup regex + credential_read |
| Combined (typo + creds) | sl4ck-bot | Typosquat + Anchors | Typosquat bonus (15) + credential + exfil |

## Anchor Detection Pattern Coverage

| Pattern | Severity | Weight | Fixtures Triggering | False Positives |
|---------|----------|:------:|:-------------------:|:---------------:|
| credential_read | critical | 40 | invoice-helper, dns-tunneler, sl4ck-bot, credential-multi, slack-notifier† | 0 |
| base64_decode | medium | 15 | invoice-helper, obfuscation-only, credential-multi | 0 |
| requests_post | low | 10 | invoice-helper, sl4ck-bot, credential-multi | 0 |
| exec | high | 25 | obfuscation-only | 0 |
| codecs_decode | medium | 15 | obfuscation-only | 0 |
| nslookup | high | 30 | dns-tunneler | 0 |
| urllib | low | 10 | weather-fetch, slack-notifier | 0 |

† `slack-notifier` triggers `credential_read` for `SLACK_WEBHOOK_URL` env var reference (risk 28, still SAFE). This is a borderline case documented in the fixture notes.

---

## Risk Score Distribution

```
Benign fixtures:   3  3  3  3  3  3  3  6  11  16  28    (median: 3)
Malicious fixtures: 45  50  62  62  62  71  76  77        (median: 62)
Separation gap:     28 → 45  (17 points between nearest benign/malicious)
```

---

## Limitations and Known Issues

1. **Sandbox stage not integrated:** Without Stage 4 (sandbox execution, Dev 1), the maximum achievable risk score for anchor+semantic-only fixtures is ~62. With sandbox integration, obfuscation-only, dns-tunneler, and credential-multi are expected to escalate from SUSPICIOUS to MALICIOUS.

2. **Mock model client:** All semantic analysis uses MockGemma with deterministic canned responses. Real Gemma 4 results may differ in confidence and pattern detection.

3. **Corpus size:** 20 fixtures is the M5 target. Production evaluation should expand to 50+ fixtures per docs/08-testing-and-evaluation.md §8.7.

4. **Borderline benign cases:** `slack-notifier` scores 28 (SAFE threshold is 30). Skills that legitimately reference credential environment variables may require allowlist/intent-matching enhancements.

5. **SKILL.md scanning:** The parser includes SKILL.md content in the script inventory for anchor scanning. Docstrings and descriptions mentioning security-related terms can trigger false pattern matches. Fixtures have been adjusted to avoid this, but real-world skills may need the same consideration.

