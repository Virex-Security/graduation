# VIREX Model Statistical Forensic Report

**Date:** July 2026  
**Target:** `v3.0-lightgbm-onnx` inference model

## 1. Confusion Matrix Analysis
The default argmax predictions reveal extreme confusion exclusively between `normal` traffic and `sqli`:
- **`normal` -> `sqli` (False Positives):** 1,804 benign requests were incorrectly flagged as SQL Injection.
- **`sqli` -> `normal` (False Negatives):** 502 actual SQL Injection payloads completely bypassed the model.
- **Other Classes:** `log4shell`, `xxe`, `ssti`, `xss`, `ssrf`, `path_traversal`, and `command_injection` exhibit near-perfect separation with <15 misclassifications each.

## 2. Per-Class Precision, Recall, and F1
*Evaluated on the 30k Test Split using default argmax thresholds:*

| Class | Precision | Recall | F1 Score |
|---|---|---|---|
| `command_injection` | 99.53% | 99.53% | 99.53% |
| `log4shell` | 100.0% | 99.73% | 99.86% |
| `path_traversal` | 99.90% | 99.91% | 99.90% |
| `ssrf` | 99.86% | 98.66% | 99.26% |
| `ssti` | 99.05% | 97.73% | 98.38% |
| `xss` | 97.85% | 99.21% | 98.53% |
| `xxe` | 98.92% | 98.13% | 98.52% |
| **`normal`** | **95.39%** | **85.20%** | **90.01%** |
| **`sqli`** | **71.35%** | **89.74%** | **79.50%** |

## 3. False Positive Analysis
- **Highest FP Generator:** `sqli`
- **Reason:** The TF-IDF vectorizer operates on character n-grams (`char_wb`). Because the dataset lacks complex benign URLs, the model incorrectly learned that characters like `=`, `?`, and `&` are indicators of SQL injection. Thus, benign REST APIs and query strings are heavily penalized.

## 4. False Negative Analysis
- **Most Frequently Missed:** `sqli`
- **Reason:** 502 SQLi payloads were predicted as `normal`. These are likely short, obfuscated, or deeply encoded payloads that don't trigger the `SecurityFeatureExtractor` regex rules and don't contain enough generic punctuation to surpass the baseline risk threshold.

## 5. ROC Curve Analysis
- **Macro ROC AUC:** 99.68%
- **Per-Class ROC:** Most classes > 99.9%. However, `sqli` drops to **98.19%**, indicating significant overlap with `normal` (99.00%). The high Macro ROC is incredibly misleading because the perfect scores on the small minority classes hide the catastrophic precision collapse in the high-volume `sqli` class.

## 6. Calibration Review
- **Brier Scores:**
  - `log4shell`: 0.00006 (Perfectly calibrated)
  - `normal`: 0.0407 (Poorly calibrated)
  - `sqli`: 0.0415 (Poorly calibrated)
- **Conclusion:** The model's predicted probabilities for `sqli` and `normal` are uncalibrated. The model is highly uncertain in this boundary space. **Isotonic Regression** or **Platt Scaling** (`CalibratedClassifierCV`) should be used during training to map raw tree outputs to true confidence distributions.

## 7. Threshold Simulation Analysis
We simulated decision thresholds from `0.10` to `0.95` to find the optimal trade-off for the problematic `sqli` class:

| Threshold | SQLi Precision | SQLi Recall | SQLi F1 |
|---|---|---|---|
| **0.10** | 59.37% | 99.48% | 74.36% |
| **0.30** | 65.54% | 97.72% | 78.46% |
| **0.50** | 71.37% | 89.74% | 79.51% |
| **0.70** | 94.17% | 69.30% | 79.84% |
| **0.80** | **99.31%** | 66.24% | 79.47% |
| **0.90** | 99.87% | 64.88% | 78.66% |

- **Current Config (`class_thresholds.json`):** Set at `0.1032`, yielding 59% precision (unacceptable FP rate).
- **Recommendation:** Raising the `sqli` threshold to **0.80** instantly stops 99% of false positives, but reduces detection recall to 66%. A threshold of **0.70** provides a balanced 94% precision and 69% recall.

## 8. SHAP & Feature Dominance Analysis
The model is heavily dominated by structural statistical features rather than semantic threat indicators.
- **Dominant Features:** `sec_feat_4` (Special Char Density), `sec_feat_0` (Payload Length), `sec_feat_2` (Entropy), and the TF-IDF nodes for `/`, `=`, and `.`.
- **Feature Redundancy:** `length` and `length_norm`, as well as `entropy` and `entropy_norm`, are perfectly linearly correlated, creating split noise in the LightGBM trees.

---

## 9. Final Improvement Roadmap

### A. Can be fixed without retraining
1. **Emergency Threshold Adjustment:** Raise the `sqli` threshold in `class_thresholds.json` from `0.10` to `0.70` to immediately stop the bleeding of False Positives in production.

### B. Requires retraining
2. **Probability Calibration:** Wrap the LightGBM estimator in `sklearn.calibration.CalibratedClassifierCV(method='isotonic')` to fix the Brier scores for `sqli` and `normal`.
3. **Drop Redundant Features:** Remove `length_norm` and `entropy_norm` from `features.py`.

### C. Requires dataset improvements
4. **Fix the SQLi False Positives:** Inject 20,000+ benign complex REST API payloads (containing `=`, `?`, `&`, JSON, XML) into the `normal` dataset so the model learns that punctuation doesn't strictly equal an attack.

### D. Requires architecture changes
5. **Switch to Word/Char Ensemble:** The `TfidfVectorizer(analyzer="char_wb")` is destroying words. Replace it with a `FeatureUnion` combining word-level TF-IDF (to catch `UNION SELECT`) and char-level TF-IDF (for obfuscation).
6. **Add Pre-Inference Decoding:** Implement URL and HTML decoding before extracting features so obfuscated attacks don't bypass the vectorizer.

*(Prioritized from fastest/highest impact to longest/deepest architectural changes)*
