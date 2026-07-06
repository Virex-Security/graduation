# VIREX ML Pipeline Forensic Audit Report

**Date:** July 2026  
**Target:** `v3.0-lightgbm-onnx` inference pipeline and training architecture.

## 1. Pipeline Architecture & Preprocessing Review
The current pipeline feeds raw strings directly from the request into the `SecurityFeatureExtractor` and `TfidfVectorizer`.
- **Payload Normalization:** **Missing.** The pipeline does not normalize payloads (e.g., converting to lowercase globally before vectorization, stripping unnecessary padding).
- **URL / Unicode / HTML Decoding:** **Missing.** There is zero decoding logic applied before feature extraction. A payload like `%27%20OR%20%271%27%3D%271` is evaluated exactly as that literal string. Because the `SecurityFeatureExtractor` relies heavily on exact regex matches (e.g., `(?i)or\s+1=1`), URL-encoded or Unicode-escaped payloads will bypass almost all security features.
- **Feature Extraction Order:** Both TF-IDF and Security features are extracted in parallel and concatenated (`hstack`). This is standard and correct, but because the input is unnormalized, both extractors suffer from the exact same obfuscation bypasses.

## 2. SecurityFeatureExtractor Audit
The `SecurityFeatureExtractor` uses 47 regex-based and statistical heuristics.
- **Redundant & Correlated Features:** 
  - `length` (0) and `length_norm` (1) are linearly correlated.
  - `entropy` (2) and `entropy_norm` (3) are heavily correlated. 
  - Including perfectly correlated features in tree-based models wastes splits and introduces feature importance noise.
- **Dominating Features:** `sec_feat_4` (Special Character Density), `length`, and `entropy` completely dominate the model. The semantic regex features (e.g., `has_union_select`, `shell_cmd_count`) have negligible feature importance compared to these raw structural statistics.

## 3. TF-IDF Vectorizer Audit
- **Analyzer:** `analyzer="char_wb"`
- **N-gram Range:** `(1, 3)`
- **Vocabulary Quality:** By using character n-grams of size 1 to 3, the vectorizer completely shatters semantic words. A keyword like `SELECT` becomes `SE`, `EL`, `LE`, `ECT`. These fragments appear frequently in benign words (e.g., "selection", "element").
- **Conclusion:** Character n-grams alone are insufficient. They force the model to rely on single characters (`/`, `=`, `:`) because the fragments of attack words are too generic. 
- **Recommendation:** A hybrid pipeline combining Word TF-IDF (to catch `script`, `union`, `select`) and Char TF-IDF (to catch obfuscation) is required for true generalization.

## 4. Feature Importance Review
The Top 10 features driving the model are: `sec_feat_4` (special char density), `sec_feat_3`, `sec_feat_2`, `sec_feat_0` (length), and single characters: `/`, `=`, `.`, `:`, `t`, `a`.
- **Why are they important?** Because `char_wb` failed to provide meaningful words, the model defaulted to finding the easiest statistical separation between short benign strings and long attack payloads. It learned that attacks often contain many slashes, equals signs, and dots.
- **Semantics vs Structure:** The model is learning **payload structure**, not attack semantics. It has essentially become a "weirdness detector" rather than an attack classifier.

## 5. False Positive Analysis
- **Why normal requests predict as SQLi:** Normal HTTP GET/POST payloads frequently contain query parameters (e.g., `?id=5&name=John`). This introduces `=`, `&`, and `?` characters, instantly spiking `sec_feat_4` and triggering the TF-IDF nodes for `=`. Because the model equates these characters with SQLi, perfectly benign complex URLs are flagged as SQL Injection.
- **Fix (Without Retraining):** The only way to mitigate this without retraining is to dramatically raise the confidence threshold for `sqli` and `xss` to prevent the model from triggering on weak structural similarities.

## 6. False Negative Analysis
- **Missed Attacks:** URL-encoded attacks, Base64 embedded shells, and nested encodings (e.g., Double URL encoding).
- **Root Cause:** Because there is no decoding pipeline, obfuscated characters fail to trigger the regex rules in `SecurityFeatureExtractor` and create unseen character n-grams in the TF-IDF vectorizer. The payload successfully bypasses the structure-based checks.

## 7. Threshold Review
- **Current state:** `backend/data/class_thresholds.json` sets `sqli` to `0.1032` and `xss` to `0.10`.
- **Audit:** These thresholds are catastrophic. A 10% confidence threshold means the model acts as a tripwire. Any normal payload that slightly resembles an attack in length or punctuation density will be blocked.
- **Optimization:** Based on standard LightGBM probability distributions, thresholds should rarely dip below `0.50` unless the class is critically underrepresented. Given the severe false positive rate, thresholds for `sqli`, `xss`, and `normal` should be optimized to at least `0.65 - 0.80`.

## 8. Calibration Review
- **Calibration Status:** The fact that thresholds were manually lowered to `0.10` strongly indicates that the LightGBM probabilities are uncalibrated. Tree-based models often push probabilities away from 0 and 1, clustering them in the middle.
- **Recommendation:** Implement `CalibratedClassifierCV` (using Isotonic Regression or Platt Scaling) during training. This will map the raw tree outputs to true confidence percentages, allowing for a standardized `0.85` threshold across all classes.

## 9. Generalization & Robustness Review
- **JSON & XML:** The model will struggle massively with JSON and XML bodies. The high density of `"`, `{`, `}`, `<`, and `>` will artificially inflate `sec_feat_4` and single-character TF-IDF scores, leading to immediate false positives.
- **JWT / Auth Tokens:** High-entropy strings (like JWTs or Bearer tokens) will spike `sec_feat_2` (entropy) and `sec_feat_0` (length), likely triggering a false positive.
- **Encoded Payloads:** Vulnerable to bypass via double-encoding or unicode-escaping.

---

## 10. Recommended Improvement Roadmap

### A. Can be implemented WITHOUT Retraining
1. **Optimize Confidence Thresholds:** Update `class_thresholds.json` to raise `sqli` and `xss` thresholds from `0.10` to `0.70+` to instantly cut down false positives.
2. **Implement Pre-Inference Decoding:** Add `urllib.parse.unquote` to the heuristic `_classify_v1` to catch encoded bypasses that the ML model misses.

### B. Requires Retraining
3. **Add Pre-processing Decoding Pipeline:** Add URL, HTML, and Unicode decoding *before* passing the string to the TF-IDF vectorizer and Security Extractor.
4. **Fix TF-IDF Analyzer:** Switch `TfidfVectorizer` to use `analyzer="word"` (or a combined `FeatureUnion` of word and char) to capture semantic keywords like `SELECT` and `script`.
5. **Prune Redundant Features:** Remove `length_norm` and `entropy_norm` from the `SecurityFeatureExtractor` to reduce noise.
6. **Probability Calibration:** Wrap the LightGBM model in `sklearn.calibration.CalibratedClassifierCV` to generate trustworthy probability scores.

### C. Requires Dataset Improvements
7. **Inject Structured Benign Data:** Add thousands of legitimate JSON, XML, GraphQL, and JWT payloads to the `normal` training class so the model unlearns the association between punctuation/entropy and attacks.
8. **Obfuscation Augmentation:** Programmatically apply URL encoding, Unicode escapes, and Base64 encoding to existing attack payloads in the training set so the model learns obfuscation structures.
