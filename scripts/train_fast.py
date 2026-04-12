"""
Virex Security — Fast Training Script (Quick Validation)
==========================================================
نسخة خفيفة للاختبار السريع
- 10,000 sample بدل 53,000
- XGBoost + RF بدل ensemble كامل
- متوافقة 100% مع inference.py

للتدريب الكامل:  python scripts/train_multiclass.py
للاختبار السريع: python scripts/train_fast.py
"""

import sys, warnings, json, time, joblib
import numpy as np, pandas as pd
warnings.filterwarnings("ignore")

from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split
from sklearn.metrics import accuracy_score, f1_score, classification_report
from xgboost import XGBClassifier
from scipy.sparse import hstack

_ROOT    = Path(__file__).resolve().parent.parent
DATA_DIR = _ROOT / "data"
EVAL_DIR = DATA_DIR / "evaluation"
EVAL_DIR.mkdir(parents=True, exist_ok=True)

sys.path.insert(0, str(_ROOT))
from app.ml.features import SecurityFeatureExtractor

print("=" * 58)
print("  Virex ML — Fast Training (Quick Validation Mode)")
print("=" * 58)

# ── Load data ─────────────────────────────────────────────────
csv_path = DATA_DIR / "ml_training_data_v2.csv"
if not csv_path.exists():
    csv_path = DATA_DIR / "ml_training_data.csv"

df = pd.read_csv(str(csv_path))
print(f"\n  Full dataset : {len(df):,} rows  →  sampling 10,000")

# build class_label
if "attack_type" in df.columns:
    df = df.copy()
    df["class_label"] = df["attack_type"].fillna("normal").astype(str)
else:
    df = df.copy()
    df["class_label"] = df["label"].map({0: "normal", 1: "attack"})

# stratified sample
total = len(df)
groups = []
for cls, g in df.groupby("class_label"):
    n = max(1, int(10000 * len(g) / total))
    n = min(n, len(g))
    groups.append(g.sample(n, random_state=42))
df = pd.concat(groups, ignore_index=True).sample(frac=1, random_state=42).reset_index(drop=True)
print(f"  Sampled      : {len(df):,} rows")

# ── Encode labels ─────────────────────────────────────────────
le = LabelEncoder()
df["encoded"] = le.fit_transform(df["class_label"])
n_classes = len(le.classes_)
print(f"\n  Classes ({n_classes}): {list(le.classes_)}")
for cls in le.classes_:
    cnt = (df["class_label"] == cls).sum()
    print(f"    {cls:<22} {cnt:>5,}")

X, y = df["text"].astype(str).values, df["encoded"].values
X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ── Features ──────────────────────────────────────────────────
print("\n  Extracting features...")
tfidf    = TfidfVectorizer(ngram_range=(1,3), max_features=15000,
                           analyzer="char_wb", sublinear_tf=True, lowercase=True)
sec_feat = SecurityFeatureExtractor()

X_tr_t = tfidf.fit_transform(X_train);     X_te_t = tfidf.transform(X_test)
X_tr_s = sec_feat.fit_transform(X_train);  X_te_s = sec_feat.transform(X_test)

X_tr = hstack([X_tr_t, X_tr_s])
X_te = hstack([X_te_t, X_te_s])
print(f"  Feature matrix: {X_tr.shape[1]:,} features")

# ── Train ──────────────────────────────────────────────────────
print("\n  Training (XGBoost + RF)...")
xgb = XGBClassifier(n_estimators=150, max_depth=7, learning_rate=0.1,
                    use_label_encoder=False, eval_metric="mlogloss",
                    n_jobs=-1, random_state=42, verbosity=0)
rf  = RandomForestClassifier(n_estimators=100, max_depth=20,
                              n_jobs=-1, random_state=42)
model = VotingClassifier([("xgb", xgb), ("rf", rf)], voting="soft", n_jobs=-1)
model.fit(X_tr, y_train)
print("  Done.")

# ── Evaluate ──────────────────────────────────────────────────
y_pred = model.predict(X_te)
acc    = accuracy_score(y_test, y_pred)
f1_mac = f1_score(y_test, y_pred, average="macro")
f1_wt  = f1_score(y_test, y_pred, average="weighted")

print(f"\n{'='*58}")
print(f"  Accuracy      : {acc*100:.2f}%")
print(f"  F1 (macro)    : {f1_mac:.4f}")
print(f"  F1 (weighted) : {f1_wt:.4f}")
print(f"\n{classification_report(y_test, y_pred, target_names=le.classes_)}")

# ── Save ──────────────────────────────────────────────────────
joblib.dump(model,    str(DATA_DIR / "model_v2.pkl"))
joblib.dump(tfidf,    str(DATA_DIR / "vectorizer_v2.pkl"))
joblib.dump(sec_feat, str(DATA_DIR / "sec_features_v2.pkl"))
joblib.dump(le,       str(DATA_DIR / "label_encoder_v2.pkl"))

metrics = {
    "version": "2.0-fast",
    "trained_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "training_samples": int(X_tr.shape[0]),
    "test_samples": int(X_te.shape[0]),
    "n_classes": n_classes,
    "classes": list(le.classes_),
    "accuracy": round(float(acc), 4),
    "f1_macro": round(float(f1_mac), 4),
    "f1_weighted": round(float(f1_wt), 4),
    "n_features": int(X_tr.shape[1]),
    "model_path": str(DATA_DIR / "model_v2.pkl"),
}
with open(EVAL_DIR / "metrics_v2.json", "w") as f:
    json.dump(metrics, f, indent=2)

print("  Models saved:")
for name in ["model_v2.pkl","vectorizer_v2.pkl","sec_features_v2.pkl","label_encoder_v2.pkl"]:
    p = DATA_DIR / name
    size = p.stat().st_size // 1024
    print(f"    {name:<35} {size:>6} KB")
print(f"\n  For full training: python scripts/train_multiclass.py")
print("=" * 58)
