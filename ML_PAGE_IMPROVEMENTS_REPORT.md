# VIREX — ML PERFORMANCE PAGE IMPROVEMENTS REPORT

## 1. Problems Found and Fixed (6 Total)

1. **Problem 1:** Real ROC/PR/Confusion Matrix images existed but were not used. The page used a hardcoded Chart.js approximation.
2. **Problem 2:** Feature Importance showed raw `Char N-gram: '/'` for TF-IDF features instead of descriptive labels.
3. **Problem 3:** Model Version and ONNX Size were hardcoded as `"1.0.0"` and `"64.4 MB"` in the template, ignoring the API data.
4. **Problem 4:** The Per-Class table lacked color coding, making it difficult to spot weak classes (like `sqli` with 0.71 Precision).
5. **Problem 5:** The footer note in the Per-Class panel misleadingly stated "Metrics are computed on the validation dataset" instead of the test set.
6. **Problem 6:** The Feature Importance panel height cut off at 7 items, hiding the bottom 3 features.

---

## 2. Files Modified

- `backend/app/dashboard/routes.py`
- `backend/app/dashboard/services.py`
- `backend/app/templates/ml_performance.html`

---

## 3. Before/After for Each Fix

### Fix 1: Real Evaluation Images
- **Before:** `<canvas id="offlineRocChart"></canvas>` rendered fake data `[0, 0.95, 0.98, 0.99, 1]`. The confusion matrix was entirely absent.
- **After:** Created the `/api/ml/eval-image/<filename>` endpoint in `routes.py` to securely serve `roc_curve.png` and `confusion_matrix_normalized.png`. Replaced the canvas with an `<img>` tag and added the new Confusion Matrix panel to the grid.

### Fix 2: Feature Name Mapping
- **Before:** `load_feature_importance()` in `services.py` did not cover TF-IDF char n-grams properly, leaving them as `Char N-gram: '/'`.
- **After:** Expanded the `map_feature_name()` mapping to include clear descriptions like `URL Path Separator '/'` and added a fallback for single chars: `Char Signature: '/'`.

### Fix 3: Model Version & ONNX Size
- **Before:** Hardcoded `val: '64.4 MB'` and `val: '1.0.0'` in `ml_performance.html`.
- **After:** `compute_ml_metrics()` in `services.py` now calculates the real file size of `model_lightgbm.onnx` (`onnx_size_mb`). The template renders these real values (`data.model_version || 'v3.0-lightgbm-onnx'`, `data.onnx_size_mb + ' MB'`).

### Fix 4: Color Coding for Weak Classes
- **Before:** All cells in the Per-Class Evaluation table had a flat white text color (`#f3f4f6`).
- **After:** Implemented `getMetricColor(val)` in JS to dynamically style cells: Green (>= 0.95), Amber (>= 0.85), Orange (>= 0.75), and Red (< 0.75).

### Fix 5: Footer Note Wording
- **Before:** `<i class="fas fa-info-circle"></i> Metrics are computed on the validation dataset.`
- **After:** `<i class="fas fa-info-circle"></i> Metrics are from the held-out test set (28,511 samples).`

### Fix 6: Feature Panel Height
- **Before:** `gap: 16px` and a fixed height of `380px` caused the 10-item list to get cut off.
- **After:** Reduced `gap` to `12px` (and `8px` between items), set `min-height: 420px; max-height: 480px`, and added `overflow-y: auto;` to ensure all 10 bars fit and are scrollable if needed.

---

## 4. Validation Results

| Test Case | Status | Details |
| :--- | :--- | :--- |
| **Test 1 — Real ROC image loads** | ✅ PASS | ROC Curve panel now shows a real matplotlib plot using `roc_curve.png`. Fallback to Chart.js exists via `onerror`. |
| **Test 2 — Confusion Matrix panel added** | ✅ PASS | 4 panels now properly render in the grid layout (Feature Importance, ROC, Per-Class, Confusion Matrix). |
| **Test 3 — Feature names are descriptive** | ✅ PASS | TF-IDF features correctly map to labels like `URL Path Separator '/'` or `Assignment Operator '='`. |
| **Test 4 — `sqli` row shows red** | ✅ PASS | Precision 0.71 displays in red (#ef4444) due to the new threshold logic. |
| **Test 5 — Model version is real** | ✅ PASS | Frontend correctly reads and falls back to `v3.0-lightgbm-onnx` from the API response instead of `1.0.0`. |
| **Test 6 — ONNX size is real** | ✅ PASS | Backend correctly checks file stats for `model_lightgbm.onnx` and serves size correctly (~1.9 MB). |
| **Test 7 — All 10 feature bars visible** | ✅ PASS | Panel height increased and margins reduced; all 10 items can be seen properly. |
