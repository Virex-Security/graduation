# VIREX LightGBM Retraining Report

The VIREX LightGBM model was successfully retrained on the augmented dataset (`train_v4.csv`).

## Architectural Upgrades
1. **Hybrid FeatureUnion:** `TfidfVectorizer(analyzer='char_wb')` was replaced with a `FeatureUnion` combining Word-level TF-IDF (1-2 ngrams) and Character-level TF-IDF (3-5 ngrams).
2. **Isotonic Calibration:** Probability calibration was evaluated during training to resolve the Brier score collapse identified in previous audits.
3. **Engineered Features:** `length_norm` and `entropy_norm` were permanently removed due to extreme Pearson correlation (>0.99) with `length` and `entropy`.
