# Citation Accuracy Evaluation Report

- **Date:** 2026-10-30
- **Evaluator:** Developer 2
- **Methodology:** AST anchor scan line citation accuracy evaluated against ground truth annotations in `tests/ground_truth.json`.
- **Matching Criterion:** Exact pattern match within line tolerance $\pm 1$ using greedy bipartite matching without replacement.

## 1. Ground Truth Corpus Summary

Ground truth was established across 9 fixture scripts spanning both malicious and benign categories:

| Fixture Path | Category | Annotations (GT) | Detected Anchors | TP | FP | FN |
|--------------|----------|-------------------|------------------|----|----|----|
| `fixtures/malicious/invoice-helper/scripts/process.py` | Malicious | 3 | 4 | 3 | 1 | 0 |
| `fixtures/malicious/obfuscation-only/scripts/encoder.py` | Malicious | 4 | 7 | 4 | 3 | 0 |
| `fixtures/malicious/dns-tunneler/scripts/diagnostic.sh` | Malicious | 3 | 6 | 3 | 3 | 0 |
| `fixtures/malicious/sl4ck-bot/scripts/bot.py` | Malicious | 2 | 4 | 2 | 2 | 0 |
| `fixtures/malicious/credential-multi/scripts/setup_env.py` | Malicious | 5 | 7 | 5 | 2 | 0 |
| `fixtures/benign/git-helper/scripts/status.py` | Benign | 0 | 0 | 0 | 0 | 0 |
| `fixtures/benign/image-resizer/scripts/resize.py` | Benign | 0 | 0 | 0 | 0 | 0 |
| `fixtures/benign/pdf-summarizer/scripts/summarize.py` | Benign | 0 | 0 | 0 | 0 | 0 |
| `fixtures/benign/weather-fetch/scripts/fetch.py` | Benign | 1 | 2 | 1 | 1 | 0 |
| **Total** | | **18** | **30** | **18** | **12** | **0** |

## 2. Metrics

- **Total Ground Truth Citations ($N_{GT}$):** 18
- **True Positives ($TP$):** 18
- **False Positives ($FP$):** 12
- **False Negatives ($FN$):** 0
- **Precision:** $\frac{TP}{TP + FP} = \frac{18}{30} = 60.00\%$
- **Recall:** $\frac{TP}{TP + FN} = \frac{18}{18} = 100.00\%$
- **F1 Score:** $75.00\%$

## 3. Analysis & Observations

1. **Perfect Anchor Recall (100%):** Every ground truth malicious and structural pattern annotated across the test corpus was successfully detected by `scan_anchors` within $\pm 1$ line of the annotated location.
2. **Additional Detections (False Positives from GT perspective):**
   - The AST scanner detected additional legitimate and suspicious constructs not individually indexed in the initial ground-truth baseline (e.g., secondary base64 calls in `encoder.py`, sub-shell command executions in `diagnostic.sh`, secondary `urllib` calls in `fetch.py`).
   - These detections are valid AST findings for downstream heuristic filters rather than hallucinations, but are strictly counted as $FP$ against the ground truth reference to maintain auditing rigor.
3. **CI Gate Integration:**
   - Regression validation is automated in `tests/check_citation_accuracy.py`.
