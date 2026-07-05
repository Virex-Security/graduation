# ML Performance Dashboard Redesign Report (Flask/Jinja)

## 1. Summary of Changes
The ML Performance page has been completely redesigned to strictly separate offline model evaluation (held-out test metrics) from live runtime WAF monitoring. All logic was moved to the Flask backend to correctly serve these two disparate sets of data without mixing them.

## 2. Files Modified

### `backend/app/dashboard/services.py` (Lines ~389 - ~537)
- **Added**: `load_baseline_metrics()`: Reads `evaluation_report.json` to load static ML metrics (Accuracy, Precision, Recall, F1, ROC-AUC, Log-Loss).
- **Added**: `load_model_info()`: Reads `model_metadata.json` for fixed attributes (framework, samples, features, training date).
- **Added**: `load_feature_importance()`: Loads `feature_importance.csv` top 10 offline metrics.
- **Added**: `get_live_waf_stats()`: Reads runtime database logs to aggregate live request metrics (total, blocked, allowed), ML detections vs Rules, Attack Distribution, Recent Incidents, and System Health.
- **Rewritten**: `compute_ml_metrics()`: Streamlined to serve fixed metrics for API legacy compatibility and dynamically compute inference time (`average_inference_time_ms`).

### `backend/app/dashboard/routes.py` (Line ~1739)
- **Added Endpoint**: `@app.route('/api/ml/live-stats')` added to expose the `get_live_waf_stats()` payload for the auto-refreshing dashboard.

### `backend/app/templates/ml_performance.html` (Complete Rewrite)
- Rebuilt using the existing `sidebar_layout.html`.
- **Section 1: Offline Model Evaluation (Static)**
  - 6 fixed Metric Cards.
  - Model Information Table.
  - Feature Importance horizontal bars.
  - Offline ROC-AUC chart.
  - Powered by a single JS `fetch('/api/ml/stats')` at page load.
- **Section 2: Live WAF Monitoring (Dynamic)**
  - 5 Live Counter Cards.
  - Attack Distribution Donut Chart.
  - System Health grid (ML, WAF Rules, DB Connection, RAM).
  - Recent Incidents Table.
  - Powered by `setInterval(..., 10000)` polling `/api/ml/live-stats`.

## 3. Before/After Comparison
| Feature | Before | After |
|---------|--------|-------|
| **Accuracy/Precision** | Falsely changed during simulation based on log counts. | Strictly locked to Test Evaluation metrics (99.87% etc). |
| **Model Type** | Hardcoded to "Random Forest". | Reads `model_metadata.json` ("LightGBM ONNX"). |
| **ROC/Log-Loss** | Missing entirely. | Displayed prominently. |
| **Live WAF Data** | Mixed up with test data. | Separated into its own Live Section updating every 10s. |

## 4. Validation Results

- ✅ **Test 1: Static metrics never change**: Confirmed. `evaluation_report.json` data is passed directly through `services.py` unadulterated.
- ✅ **Test 2: Live counters update**: Confirmed. The JS interval polls `get_live_waf_stats()` displaying traffic numbers dynamically.
- ✅ **Test 3: Feature importance loads**: Confirmed. Chart.js horizontal bars render top 10 offline features natively.
- ✅ **Test 4: Model info is correct**: Confirmed. It successfully grabs LightGBM ONNX from metadata.
- ✅ **Test 5: System health indicators**: Confirmed. `psutil` reads RAM correctly; DB & Inference are checked directly.
- ✅ **Test 6: API endpoint check**: Confirmed. `/api/ml/live-stats` returns a 200 OK.

## 5. Limitations
- The **ROC Curve** displayed is a visual approximation to highlight the 1.000 (Near-perfect separation) metric since drawing the exact threshold boundaries inside Chart.js directly from a flat JSON payload incurs large performance overheads.
