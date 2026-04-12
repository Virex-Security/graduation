"""
Virex Security — Multi-Class ML Training Script
=================================================
يدرّب ensemble model (XGBoost + LightGBM + RF)
على 10 classes: normal + 9 attack types
يحفظ: model_v2.pkl, vectorizer_v2.pkl, label_encoder_v2.pkl
"""

import sys
import warnings
import joblib
import numpy as np
import pandas as pd
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import matplotlib.gridspec as gridspec
import seaborn as sns
warnings.filterwarnings("ignore")

from pathlib import Path
from sklearn.ensemble import RandomForestClassifier, VotingClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.pipeline import Pipeline, FeatureUnion
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    classification_report, accuracy_score, confusion_matrix,
    f1_score, precision_score, recall_score
)
from imblearn.over_sampling import SMOTE
from imblearn.pipeline import Pipeline as ImbPipeline
from xgboost import XGBClassifier
from lightgbm import LGBMClassifier
from scipy.sparse import hstack

# ── Paths ─────────────────────────────────────────────────────
_SCRIPT_DIR   = Path(__file__).resolve().parent
_PROJECT_ROOT = _SCRIPT_DIR.parent
DATA_DIR      = _PROJECT_ROOT / "data"
EVAL_DIR      = DATA_DIR / "evaluation"
EVAL_DIR.mkdir(parents=True, exist_ok=True)

TRAINING_CSV  = DATA_DIR / "ml_training_data_v2.csv"
MODEL_PATH    = DATA_DIR / "model_v2.pkl"
VEC_PATH      = DATA_DIR / "vectorizer_v2.pkl"
SEC_FEAT_PATH = DATA_DIR / "sec_features_v2.pkl"
LE_PATH       = DATA_DIR / "label_encoder_v2.pkl"

# fall back to original CSV if v2 not generated yet
if not TRAINING_CSV.exists():
    TRAINING_CSV = DATA_DIR / "ml_training_data.csv"
    print(f"[WARN] v2 dataset not found — falling back to {TRAINING_CSV}")
    print("[WARN] Run scripts/collect_datasets.py first for best results")

# ── load features module ──────────────────────────────────────
sys.path.insert(0, str(_PROJECT_ROOT))
from app.ml.features import SecurityFeatureExtractor


# ─────────────────────────────────────────────────────────────
# 1. LOAD & PREPARE DATA
# ─────────────────────────────────────────────────────────────
print("=" * 58)
print("  Virex ML Training — Multi-Class Ensemble v2")
print("=" * 58)

df = pd.read_csv(str(TRAINING_CSV))
print(f"\n  Dataset : {TRAINING_CSV.name}")
print(f"  Rows    : {len(df):,}")

# handle both old (binary) and new (multi-class) CSV formats
if "attack_type" in df.columns:
    df["class_label"] = df["attack_type"].fillna("normal")
else:
    # old binary CSV: infer class from label column
    df["class_label"] = df["label"].map({0: "normal", 1: "attack"})

# encode labels
le = LabelEncoder()
df["encoded"] = le.fit_transform(df["class_label"])
n_classes = len(le.classes_)

print(f"\n  Classes ({n_classes}):")
for cls, cnt in df["class_label"].value_counts().items():
    print(f"    {cls:<22} {cnt:>6,}")

X = df["text"].astype(str).values
y = df["encoded"].values

X_train, X_test, y_train, y_test = train_test_split(
    X, y, test_size=0.2, random_state=42, stratify=y
)

# ─────────────────────────────────────────────────────────────
# 2. BUILD FEATURE MATRIX
# ─────────────────────────────────────────────────────────────
print("\n  Building features...")

tfidf = TfidfVectorizer(
    ngram_range=(1, 3),
    max_features=20000,
    analyzer="char_wb",
    sublinear_tf=True,
    lowercase=True,
    strip_accents="unicode",
)
sec_feat = SecurityFeatureExtractor()

X_train_tfidf = tfidf.fit_transform(X_train)
X_test_tfidf  = tfidf.transform(X_test)

X_train_sec   = sec_feat.fit_transform(X_train)
X_test_sec    = sec_feat.transform(X_test)

X_train_full  = hstack([X_train_tfidf, X_train_sec])
X_test_full   = hstack([X_test_tfidf,  X_test_sec])

print(f"  Feature matrix: {X_train_full.shape[1]:,} features")

# ─────────────────────────────────────────────────────────────
# 3. HANDLE CLASS IMBALANCE WITH SMOTE
# ─────────────────────────────────────────────────────────────
print("  Applying SMOTE for class balance...")
try:
    min_samples = min(np.bincount(y_train))
    k = min(5, min_samples - 1) if min_samples > 1 else 1
    smote = SMOTE(random_state=42, k_neighbors=k)
    X_train_bal, y_train_bal = smote.fit_resample(X_train_full, y_train)
    print(f"  After SMOTE: {X_train_bal.shape[0]:,} samples")
except Exception as e:
    print(f"  SMOTE skipped ({e}) — using original distribution")
    X_train_bal, y_train_bal = X_train_full, y_train

# ─────────────────────────────────────────────────────────────
# 4. TRAIN ENSEMBLE
# ─────────────────────────────────────────────────────────────
print("\n  Training ensemble (XGBoost + LightGBM + RF)...")

xgb = XGBClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.1,
    use_label_encoder=False,
    eval_metric="mlogloss",
    n_jobs=-1,
    random_state=42,
    verbosity=0,
)

lgbm = LGBMClassifier(
    n_estimators=300,
    max_depth=8,
    learning_rate=0.1,
    n_jobs=-1,
    random_state=42,
    verbose=-1,
)

rf = RandomForestClassifier(
    n_estimators=200,
    max_depth=25,
    n_jobs=-1,
    random_state=42,
)

ensemble = VotingClassifier(
    estimators=[("xgb", xgb), ("lgbm", lgbm), ("rf", rf)],
    voting="soft",
    n_jobs=-1,
)

ensemble.fit(X_train_bal, y_train_bal)
print("  Training complete.")

# ─────────────────────────────────────────────────────────────
# 5. EVALUATE
# ─────────────────────────────────────────────────────────────
y_pred = ensemble.predict(X_test_full)
y_prob = ensemble.predict_proba(X_test_full)

acc    = accuracy_score(y_test, y_pred)
f1_mac = f1_score(y_test, y_pred, average="macro")
f1_wt  = f1_score(y_test, y_pred, average="weighted")
prec   = precision_score(y_test, y_pred, average="macro", zero_division=0)
rec    = recall_score(y_test, y_pred, average="macro", zero_division=0)
cm     = confusion_matrix(y_test, y_pred)

print(f"\n{'='*58}")
print(f"  Accuracy       : {acc*100:.2f}%")
print(f"  F1 (macro)     : {f1_mac:.4f}")
print(f"  F1 (weighted)  : {f1_wt:.4f}")
print(f"  Precision(mac) : {prec:.4f}")
print(f"  Recall (mac)   : {rec:.4f}")
print(f"\n{classification_report(y_test, y_pred, target_names=le.classes_)}")

# ─────────────────────────────────────────────────────────────
# 6. CONFUSION MATRIX PLOT
# ─────────────────────────────────────────────────────────────
DARK_BG = "#0f172a"; CARD_BG = "#1e293b"; TEXT = "#f8fafc"
fig, ax = plt.subplots(figsize=(14, 11), facecolor=DARK_BG)
ax.set_facecolor(CARD_BG)
cm_norm = cm.astype("float") / cm.sum(axis=1)[:, np.newaxis]
sns.heatmap(
    cm_norm, annot=True, fmt=".2f", cmap="Blues",
    xticklabels=le.classes_, yticklabels=le.classes_,
    ax=ax, linewidths=0.5, linecolor=DARK_BG,
    annot_kws={"size": 9, "color": "white"},
)
ax.set_title(f"Virex ML v2 — Confusion Matrix\nAccuracy: {acc*100:.2f}% | F1: {f1_mac:.3f}",
             color=TEXT, fontsize=14, pad=14)
ax.set_xlabel("Predicted", color=TEXT); ax.set_ylabel("True", color=TEXT)
ax.tick_params(colors=TEXT, rotation=45)
plt.tight_layout()
cm_path = EVAL_DIR / "confusion_matrix_v2.png"
plt.savefig(str(cm_path), dpi=150, bbox_inches="tight")
plt.close()
print(f"\n  Confusion matrix saved → {cm_path}")

# ─────────────────────────────────────────────────────────────
# 7. SAVE MODELS
# ─────────────────────────────────────────────────────────────
DATA_DIR.mkdir(parents=True, exist_ok=True)
joblib.dump(ensemble,  str(MODEL_PATH))
joblib.dump(tfidf,     str(VEC_PATH))
joblib.dump(sec_feat,  str(SEC_FEAT_PATH))
joblib.dump(le,        str(LE_PATH))

print(f"\n  Models saved:")
print(f"    {MODEL_PATH}")
print(f"    {VEC_PATH}")
print(f"    {SEC_FEAT_PATH}")
print(f"    {LE_PATH}")

# ─────────────────────────────────────────────────────────────
# 8. SAVE METRICS JSON
# ─────────────────────────────────────────────────────────────
import json, time
metrics = {
    "version":         "2.0",
    "trained_at":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    "training_samples": int(X_train_bal.shape[0]),
    "test_samples":    int(X_test_full.shape[0]),
    "n_classes":       n_classes,
    "classes":         list(le.classes_),
    "accuracy":        round(float(acc),  4),
    "f1_macro":        round(float(f1_mac), 4),
    "f1_weighted":     round(float(f1_wt),  4),
    "precision_macro": round(float(prec),   4),
    "recall_macro":    round(float(rec),    4),
    "n_features":      int(X_train_full.shape[1]),
    "model_path":      str(MODEL_PATH),
}
metrics_path = EVAL_DIR / "metrics_v2.json"
with open(metrics_path, "w") as f:
    json.dump(metrics, f, indent=2)
print(f"    {metrics_path}")
print("=" * 58)
