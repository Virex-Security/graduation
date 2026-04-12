# Virex Security — ML Upgrade v2 Documentation

## ما اتغير

| | قبل (v1) | بعد (v2) |
|---|---|---|
| Dataset | 3,300 sample | **53,000 sample** |
| Attack types | 6 (regex بعد المودل) | **10 (من المودل مباشرة)** |
| Model | RandomForest فقط | **XGBoost + RF Ensemble** |
| Features | TF-IDF raw text فقط | **TF-IDF + 29 Security Features** |
| Output | binary (attack/normal) | **multi-class + confidence + severity** |
| Anomaly detection | ❌ | ✅ Isolation Forest |
| Model versioning | ❌ | ✅ ModelRegistry |
| Explainability | ❌ | ✅ Top features per decision |
| Backward compat | — | ✅ `ml_detect()` نفس الـ signature |

---

## الـ Attack Classes (10 classes)

| ID | Class | Severity |
|----|-------|----------|
| 0 | normal | none |
| 1 | sql_injection | high |
| 2 | xss | medium |
| 3 | command_injection | critical |
| 4 | path_traversal | medium |
| 5 | ssrf | high |
| 6 | xxe | high |
| 7 | ssti | high |
| 8 | log4shell | critical |
| 9 | brute_force | low |

---

## الملفات الجديدة

```
app/ml/
├── __init__.py          # exports محدّثة
├── inference.py         # ★ ML engine الرئيسي — محدّث كامل
├── features.py          # SecurityFeatureExtractor (29 feature)
├── anomaly.py           # AnomalyDetector (Isolation Forest)
├── model_registry.py    # versioning + rollback
└── explainer.py         # شرح القرارات بالـ top features

scripts/
├── collect_datasets.py  # يولّد 53k sample من payloads حقيقية
├── train_fast.py        # تدريب سريع للاختبار (10k sample)
└── train_multiclass.py  # تدريب كامل (XGBoost + LightGBM + RF)

data/
├── ml_training_data_v2.csv   # dataset جديدة (53k)
├── model_v2.pkl              # المودل الجديد
├── vectorizer_v2.pkl         # TF-IDF vectorizer
├── sec_features_v2.pkl       # SecurityFeatureExtractor
├── label_encoder_v2.pkl      # LabelEncoder للـ 10 classes
└── evaluation/
    ├── metrics_v2.json        # نتائج التدريب
    └── confusion_matrix_v2.png

tests/
└── test_ml_v2.py      # 39 test شامل كل الكود الجديد
```

---

## طريقة الاستخدام

### 1. تدريب المودل (أول مرة)

```bash
# توليد الـ dataset (مرة واحدة بس)
python scripts/collect_datasets.py

# تدريب سريع للاختبار (~2 دقيقة)
python scripts/train_fast.py

# تدريب كامل لأفضل أداء (~15-20 دقيقة)
python scripts/train_multiclass.py
```

### 2. استخدام الـ inference في الكود

```python
from app.ml.inference import ml_analyze, ml_detect

# الـ API الجديدة — multi-class
decision = ml_analyze("' OR 1=1 UNION SELECT password FROM users--")

print(decision.attack_type)         # "sql_injection"
print(decision.severity)            # "high"
print(decision.confidence)          # 0.97
print(decision.action)              # "block"
print(decision.risk_score)          # 0.98
print(decision.class_probabilities) # {"sql_injection": 0.97, "normal": 0.01, ...}
print(decision.model_version)       # "v2.0"

# الـ API القديمة (backward compatible — لا تتكسر)
is_attack, risk = ml_detect("SELECT * FROM users WHERE 1=1")
```

### 3. Explainability — ليه اتبلوك؟

```python
from app.ml.explainer import get_explainer

explainer = get_explainer()
result = explainer.explain(
    text="' OR 1=1 UNION SELECT password--",
    attack_type="sql_injection",
    risk_score=0.97
)

print(result["explanation"])
# "SQL injection — the request contains SQL syntax designed to manipulate database queries."

for feat in result["top_features"]:
    print(f"  {feat['description']}: {feat['value']}")
# SQL keywords (SELECT, UNION...): 3.0
# UNION SELECT pattern: 1.0
# SQL comment sequences: 1.0
```

### 4. Anomaly Detection (Zero-day)

```python
from app.ml.anomaly import get_anomaly_detector

detector = get_anomaly_detector()

# تدريب على normal traffic (اختياري — المودل بيلود من disk)
detector.fit(normal_texts=["search query", "GET /home", ...])

# اكتشاف
result = detector.predict("some_weird_payload")
print(result["is_anomaly"])    # True/False
print(result["anomaly_score"]) # -0.42 (أقل = أكثر شذوذاً)
```

### 5. Model Registry

```python
from app.ml.model_registry import get_registry

registry = get_registry()

# تسجيل مودل جديد
registry.register_model(
    model_path="data/model_v2.pkl",
    metrics={"accuracy": 0.99, "f1_macro": 0.98},
    version="v2.0"
)

# مقارنة إصدارين
comparison = registry.compare_versions("v1.0", "v2.0")
print(comparison["accuracy"])  # {"v1": 0.85, "v2": 0.99, "diff": 0.14}

# rollback
registry.rollback("v1.0")
```

---

## الـ MLDecision Object (الجديد)

```python
class MLDecision:
    risk_score: float           # 0.0-1.0 (overall risk)
    action: str                 # "allow" | "monitor" | "block"
    attack_type: str            # "sql_injection" | "xss" | ... | "normal"
    attack_class_id: int        # 0-9
    confidence: float           # confidence في الـ predicted class
    severity: str               # "critical" | "high" | "medium" | "low" | "none"
    class_probabilities: dict   # {"sql_injection": 0.92, "xss": 0.03, ...}
    from_cache: bool
    model_version: str          # "v2.0"

    # properties
    should_block: bool
    should_monitor: bool

    # methods
    to_dict() -> dict           # للـ JSON serialization
```

---

## تشغيل الـ Tests

```bash
# كل الـ tests الجديدة (39 test)
python -m pytest tests/test_ml_v2.py -v

# كل الـ tests (جديدة + قديمة)
python -m pytest tests/ -v
```

---

## الـ Environment Variables

```env
ML_THRESHOLD_BLOCK=0.85      # فوق الـ score ده → block (default: 0.85)
ML_THRESHOLD_MONITOR=0.60    # فوق الـ score ده → monitor (default: 0.60)
ML_RETRAIN_INTERVAL=3600     # إعادة تدريب كل X ثانية (default: 3600)
ML_CACHE_SIZE=1024           # حجم الـ LRU cache (default: 1024)
ML_CACHE_TTL=300             # صلاحية الـ cache بالثواني (default: 300)
ML_LOG_PREDICTIONS=false     # تسجيل كل prediction في predictions_log.jsonl
```

---

## نتائج التدريب (Fast Mode على 10k sample)

```
Accuracy      : 100.00%
F1 (macro)    : 1.0000
F1 (weighted) : 1.0000

                   precision  recall  f1-score  support
      brute_force      1.00    1.00      1.00      113
command_injection      1.00    1.00      1.00      189
        log4shell      1.00    1.00      1.00       76
           normal      1.00    1.00      1.00      566
   path_traversal      1.00    1.00      1.00      189
    sql_injection      1.00    1.00      1.00      302
             ssrf      1.00    1.00      1.00      113
             ssti      1.00    1.00      1.00       75
              xss      1.00    1.00      1.00      302
              xxe      1.00    1.00      1.00       75
```

> للتدريب الكامل على 53k sample باستخدام `train_multiclass.py` مع SMOTE و LightGBM
> متوقع accuracy أعلى مع تنوع أكبر في الـ test cases الحقيقية.
