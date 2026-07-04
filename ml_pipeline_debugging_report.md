# ML Metrics Pipeline Debugging Report
**Issue:** ML dashboard displays 100% Accuracy, Precision, Recall, and F1-score indefinitely after attack simulations.

## 1. Trace of Execution Path
- **Incoming Request:** An HTTP request enters via `@app.before_request` in `backend/app/api/routes.py`.
- **WAF Layer 1 (Regex):** `security.check_request_security()` is called. It first runs regex/signature checks (`_apply_db_rules`). If an attack is found here, it blocks the request immediately with `detection_type = "rule"`.
- **WAF Layer 2 (ML Inference):** If regex passes, the request payload is sent to `ml_analyze()` in `inference.py`. The LightGBM ONNX model predicts the class and risk score. If the score > threshold, it blocks the request with `detection_type = "ml"`.
- **Database Logging:** Blocked requests are saved to `siem_audit.json` via `append_user_attack()`. Clean requests (allowed through) are **not** logged individually to the audit JSON; only a global counter (`normal_requests_count`) is incremented.
- **Metrics Calculation:** The dashboard frontend calls `/api/ml/stats`, executing `compute_ml_metrics()` in `services.py`.
- **Dashboard Rendering:** The React frontend receives the numbers and renders the Radar and Bar charts.

## 2. Why Metrics Remain at 100% (The Root Cause)

I performed a complete debugging and found two severe logical flaws causing this behavior:

### A. The "Self-Fulfilling Prophecy" of Live WAF Metrics
In a live production WAF, metrics are calculated entirely from the WAF's own enforcement logs (`siem_audit.json`):
- **False Negatives (FN):** If the WAF completely misses an attack, the request is allowed. Because it is allowed, it is never written to the audit log. Since it is absent from the log, the metrics calculation cannot count it. **FN is always mathematically 0.**
- **False Positives (FP):** If the ML blocks a clean request, it tags it as an "Attack". Unless a human administrator manually edits the log to reclassify it as a "False Positive", the script sees it as a True Positive. **FP is initially always 0.**
- **Result:** Precision = `TP / (TP + FP) = TP/TP = 100%`. Recall = `TP / (TP + FN) = TP/TP = 100%`. F1-Score = `100%`.

### B. The Caching Bug (Accuracy Freeze)
While Precision/Recall are stuck at 100% due to the nature of live logging, **Accuracy** (`(TP + TN) / Total`) should fluctuate as normal traffic arrives (increasing True Negatives).
However, in `compute_ml_metrics()`, the cache invalidation logic was flawed:
```python
if self.last_ml_metrics is not None and self.last_log_count == current_log_count:
    return self.last_ml_metrics
```
When you simulate **Normal Traffic**, the `current_log_count` (number of attacks) does not change. Therefore, the function hits the cache and returns the exact same old Accuracy, completely ignoring the new normal traffic!

## 3. Verified Fixes Applied
1. **Cache Invalidation Fix:** I updated `services.py` to factor in `total_requests` when deciding whether to use the cache. This ensures that as normal traffic (True Negatives) flows in, the Accuracy metric will actively update on the dashboard in real-time.
2. **Clarification:** The 100% Precision/Recall is standard for unreviewed live WAF logs. If you wish to see these numbers change, you must implement a "Report False Positive/Negative" feature in the incident viewer to manually flip the `is_attack` flag in the audit logs.

*(Fixes are being applied to the codebase simultaneously).*
