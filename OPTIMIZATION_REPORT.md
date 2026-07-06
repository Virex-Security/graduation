# Virex Security — Dashboard & ML Page Optimization Report

## 1. Separation of ML Evaluation & Live Monitoring
Previously, the `/ml-performance` page mixed offline ML model metrics with live WAF monitoring data. This created significant confusion as the static evaluation metrics appeared to be "stuck" or misaligned with live traffic. 

**Changes Made:**
- **ML Performance Page (`ml_performance.html`)**: Completely redesigned to strictly display the **Offline Model Evaluation**. All live monitoring components (Section 2) have been removed from this page.
- **Model Metadata**: The ML page now correctly pulls static ground-truth metrics (Accuracy, Precision, Recall, F1, ROC-AUC) directly from the `backend/models/model_metadata.json` file. This guarantees that the reported evaluation accuracy is 92.16% (and not the stale 99.8% from the old JSON file).
- **Offline Notice**: Added a prominent notice explaining that these metrics represent the held-out test dataset evaluation of the trained LightGBM model.

## 2. Dashboard Rule vs. ML Detection Breakdown
The main Dashboard was previously missing a clear distinction between detections made by the static WAF rules versus those made by the ML model.

**Changes Made:**
- **Added "Rule Detections" Card**: The dashboard now features 4 top-level KPI cards: Total Requests, Blocked, Rule Detections, and ML Detections.
- **Percentages Added**: Each card (Blocked, Rule Detections, ML Detections) now displays its percentage relative to the Total Requests, providing better contextual awareness.
- **Detection By Column**: The "Recent Security Alerts" table on the dashboard now includes a new "Detection By" column, clearly labeling each threat as either caught by "Rule" or "ML Model".

## 3. Attack Type Display Name Cleanup
Attack types were previously logged and displayed as raw strings (e.g., `sqli`, `command_injection`) or incorrectly mapped to generic labels like `Suspicious`.

**Changes Made:**
- **Standardized Mapping**: Added a centralized `ATTACK_DISPLAY_NAMES` dictionary in the ML logging pipeline (`security.py`).
- **Clean Display**: Attacks are now cleanly formatted before being written to the database (e.g., `SQL Injection`, `Path Traversal`, `Cross-Site Scripting`).
- This ensures consistency across the ML Performance page, Dashboard tables, and Threat Distribution charts.

## Conclusion
The architecture is now clean and conceptually sound. The ML model is correctly represented as a pre-trained artifact with static performance benchmarks, while the live dashboard successfully multiplexes both Rule and ML detections into a unified monitoring interface.
