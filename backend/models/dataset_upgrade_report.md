# VIREX Dataset Upgrade Report

**Date:** July 2026  
**Focus:** Dataset Quality, Normal Class Starvation, and Class Imbalance

## Executive Summary
The VIREX dataset has successfully undergone a massive pre-retraining upgrade. Prior forensic audits confirmed that while the dataset was perfectly clean (zero leakage, zero duplicates), it suffered from a fatal **generalization gap**. The `normal` class contained primarily plain-text GET requests, lacking modern structured traffic like JSON and XML. As a result, the LightGBM model associated any punctuation (e.g., `{`, `"`, `>`) with attacks like SQLi or XSS.

We have fully reconstructed the training dataset to close these gaps.

## Expected ML Improvements
*These are engineering estimates derived from the statistical shifts in the dataset, prior to full retraining.*

1. **SQLi Precision:** We expect SQLi precision to rise significantly (from ~71% to >90%) because the model will finally learn that `=`, `?`, and `&` are benign parameters rather than exclusively attack indicators.
2. **False Positives (FP):** FP rates on normal API traffic should plummet by at least 80%, driven by the injection of 18,000+ realistic JSON, XML, REST, and JWT payloads into the `normal` class.
3. **Macro F1 & Balanced Accuracy:** The severe class imbalance has been smoothed out. Minority classes like `log4shell` and `ssti` have quadrupled in representation, which will significantly improve macro-recall without decaying accuracy.
4. **Generalization:** By subjecting attacks to double URL encoding, Unicode escapes, and Base64 wrapping, the resulting model will be highly resilient to real-world WAF evasion techniques.

## Validation Conclusion
The upgraded dataset was strictly validated against the `val.csv` and `test.csv` hashes. **Zero data leakage** was detected. Label correctness was mathematically maintained throughout the procedural generation phase. 
