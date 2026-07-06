# Preprocessing Pipeline Upgrade Report

**Date:** July 2026  
**Target:** VIREX `v3.0-lightgbm-onnx` Preprocessing Pipeline

## 1. Goal
The objective was to improve the ML preprocessing pipeline by adding comprehensive payload normalization (URL decoding, HTML entity decoding, Unicode escape decoding, and lowercasing) *before* the text is passed to the `SecurityFeatureExtractor` and `TfidfVectorizer`. The constraint was to implement this **without retraining the model**.

## 2. Implementation Methodology
A normalization function was drafted to handle:
1. **Unicode Escapes:** Using a safe regex replacement for `\uXXXX` and `\UXXXXXXXX` to avoid `codecs.decode` deprecation warnings on malformed backslashes.
2. **HTML Entities:** Using Python's built-in `html.unescape`.
3. **URL Encoding:** Using a double-pass `urllib.parse.unquote_plus` to handle nested encodings.

An isolated experiment (`test_preprocessing.py`) was created to run the entire ML inference pipeline (TF-IDF + Security Features + LightGBM Predict) on a subset of 5,000 real test payloads. We compared the Baseline (un-normalized) predictions against the Normalized predictions.

## 3. Validation Test Results
The experiment revealed an **immediate and severe performance regression** when applying normalization without retraining the model.

### Macro Metrics
| Metric | Baseline | Normalized | Difference |
|---|---|---|---|
| **Macro Precision** | 96.04% | 92.89% | -3.15% |
| **Macro Recall** | 96.66% | 93.46% | -3.20% |
| **Macro F1-Score** | 96.20% | 92.99% | -3.21% |

### Per-Class F1-Score Impact
| Class | Baseline F1 | Normalized F1 | Impact |
|---|---|---|---|
| `sqli` | 80.39% | 64.02% | **-16.36%** (Severe Regression) |
| `normal` | 90.21% | 81.35% | **-8.85%** (Severe Regression) |
| `xss` | 99.06% | 95.75% | **-3.31%** (Regression) |
| `command_injection` | 99.79% | 99.37% | -0.42% |
| `path_traversal` | 99.96% | 99.96% | No change |
| `log4shell` | 100.0% | 100.0% | No change |
| `ssrf` | 98.77% | 98.77% | No change |
| `ssti` | 99.19% | 99.19% | No change |
| `xxe` | 98.47% | 98.47% | No change |

## 4. Root Cause Analysis
The requirement stated: *"Run validation tests to ensure no regression occurs."* Since regression explicitly occurs, the preprocessing upgrade cannot be deployed without violating production reliability.

The regressions in `sqli`, `normal`, and `xss` are mathematically inevitable when decoding inputs for a model trained on raw text:
1. **Feature Dependency:** The `SecurityFeatureExtractor` contains explicit features like `url_enc_count` and `has_double_encoding`. By decoding the payload before feature extraction, these features are instantly zeroed out. The model heavily relied on these signals to identify attacks.
2. **TF-IDF Vocabulary Destruction:** The `TfidfVectorizer` (using `char_wb`) was trained on exact character sequences like `%20`, `%27`, and `&#x3C;`. Decoding these sequences to ` ` (space), `'` (quote), and `<` creates n-grams the model has never assigned proper weight to.
3. **Statistical Shifts:** `normal` traffic often contains URL-encoded query parameters. Decoding them alters the `entropy` and `length` features, pushing the payload into the decision boundary of an attack, leading to the 8.85% drop in `normal` F1 (False Positives).

## 5. Conclusion & Next Steps
**Do not deploy normalization to production inference without retraining.**

Adding decoding *before* feature extraction is the correct architectural choice for a robust WAF, but it strictly requires generating a normalized training dataset and completely retraining the model and TF-IDF vectorizer. 

If immediate mitigation of encoded bypasses is required, the normalization logic should be added **exclusively to the heuristic fallback layer (`_classify_v1`)** rather than the ML pipeline, as the heuristic layer relies on human-readable regexes (like `SELECT`) which benefit directly from decoding without suffering statistical drift.
