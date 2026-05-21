# ML Model Training Guide

## 🎯 Problem: Inflated Accuracy

The original training data was generated from simple templates, resulting in:
- ❌ 99%+ accuracy (unrealistic)
- ❌ Model memorizes patterns instead of learning
- ❌ Poor performance on real-world data

## ✅ Solution: Realistic Training Data

### Step 1: Generate Realistic Data

```bash
python generate_realistic_training_data.py
```

This creates `data/ml_training_data.csv` with:
- ✅ Real HTTP request structures
- ✅ Actual CVE attack patterns
- ✅ Diverse normal requests
- ✅ Multiple attack types (SQL, XSS, CMDi, Path Traversal, SSRF)

**Output:**
```
✅ Generated 1000 samples
   Normal requests: 350
   SQL Injection: 250
   XSS: 200
   Command Injection: 100
   Path Traversal: 100
```

### Step 2: Train Model with Pipeline

```bash
python train_model.py
```

**New Features:**
- ✅ Uses `sklearn.Pipeline` (prevents data leakage)
- ✅ Detects overfitting automatically
- ✅ Shows false positive rate
- ✅ Saves as single `model_pipeline.pkl` file
- ✅ Displays top 20 important features

**Expected Output:**
```
📊 Training samples: 1000
   Normal:  350 (35.0%)
   Attacks: 650 (65.0%)

🔧 Building ML Pipeline...
🎯 Training Random Forest...

🔄 Running 5-fold cross-validation...
   CV F1 Score: 0.892 ± 0.023
   ✅ Low variance - model is stable

📈 Test Set Evaluation:
   Accuracy: 87.50%
   ROC-AUC:  0.9234
   Precision: 0.891
   Recall:    0.923
   F1-Score:  0.907

   False Positive Rate: 3.21%
   ✅ Low FPR - good for production

🔍 Overfitting Analysis:
   Train Accuracy: 92.13%
   Test Accuracy:  87.50%
   Gap:            4.63%
   ✅ Good generalization
```

### Step 3: Test the Model

```bash
# Test SQL injection
python -c "from app.ml.inference_simple import ml_analyze; print(ml_analyze('SELECT * FROM users WHERE id=1 OR 1=1'))"

# Test XSS
python -c "from app.ml.inference_simple import ml_analyze; print(ml_analyze('<script>alert(1)</script>'))"

# Test normal request
python -c "from app.ml.inference_simple import ml_analyze; print(ml_analyze('search=laptop&category=electronics'))"
```

## 📊 Understanding the Metrics

### Accuracy
- **Good range:** 80-90%
- **Too high (>95%):** Likely overfitting
- **Too low (<75%):** Model needs improvement

### False Positive Rate (FPR)
- **Good:** <5%
- **Acceptable:** 5-10%
- **Bad:** >10% (blocks too many legitimate requests)

### Overfitting Gap
- **Good:** <5% difference between train and test
- **Warning:** 5-10% difference
- **Bad:** >10% difference (model memorized training data)

## 🔧 Tuning the Model

### If Accuracy is Too Low (<80%)

1. **Add more training data:**
   ```bash
   # Edit generate_realistic_training_data.py
   # Increase sample counts in each function
   ```

2. **Increase model complexity:**
   ```python
   # In train_model.py, increase:
   n_estimators=200  # from 100
   max_depth=20      # from 15
   ```

### If False Positive Rate is Too High (>10%)

1. **Increase block threshold:**
   ```python
   # In app/ml/inference_simple.py
   if risk_score >= 0.90:  # from 0.85
       action = "block"
   ```

2. **Add more normal examples:**
   ```bash
   # Edit generate_realistic_training_data.py
   # Increase normal_data count to 500+
   ```

### If Overfitting (Gap >10%)

1. **Reduce model complexity:**
   ```python
   # In train_model.py
   max_depth=10           # from 15
   min_samples_leaf=10    # from 5
   ```

2. **Add regularization:**
   ```python
   max_features='sqrt'    # instead of None
   ```

## 🚀 Production Deployment

### 1. Use the Simple Inference Module

```python
# In your code, replace:
from app.ml.inference import ml_analyze

# With:
from app.ml.inference_simple import ml_analyze
```

### 2. Monitor False Positives

```python
# Log all blocks for review
if result.action == "block":
    logger.warning(f"Blocked: {text} (score: {result.risk_score})")
```

### 3. Retrain Periodically

```bash
# Every month, retrain with new data
python generate_realistic_training_data.py
python train_model.py
```

## 📈 Expected Realistic Performance

| Metric | Target | Acceptable | Poor |
|--------|--------|------------|------|
| Accuracy | 85-90% | 80-85% | <80% |
| Precision | >85% | 75-85% | <75% |
| Recall | >90% | 80-90% | <80% |
| FPR | <5% | 5-10% | >10% |
| Overfitting Gap | <5% | 5-10% | >10% |

## ⚠️ Common Mistakes

1. **Using synthetic data** → Use realistic HTTP requests
2. **No pipeline** → Always use `sklearn.Pipeline`
3. **Ignoring FPR** → Monitor false positives in production
4. **No retraining** → Retrain monthly with new attack patterns
5. **Too complex model** → Start simple, increase complexity only if needed

## 🎓 Further Improvements

1. **Use real CVE dataset:** Download from NVD or Exploit-DB
2. **Add more attack types:** CSRF, XXE, SSTI, Deserialization
3. **Feature engineering:** Extract URL structure, parameter names, etc.
4. **Ensemble methods:** Combine ML with rule-based detection
5. **Online learning:** Update model with production feedback

---

**Questions?** Check `SECURITY.md` or open an issue.
