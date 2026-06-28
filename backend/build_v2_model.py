"""
Virex Security — Build v2 Multi-Class Model
============================================
Pipeline:
  TF-IDF (1-3 ngrams, 3000 features)
  + SecurityFeatureExtractor (37 security features)
  → hstack → RandomForestClassifier (300 trees, depth=15)
  → 10 attack classes

Output files:
  data/model_v2.pkl
  data/vectorizer_v2.pkl
  data/sec_features_v2.pkl
  data/label_encoder_v2.pkl
  data/evaluation_report.json  (updated)
  data/model_registry.json     (updated)

Usage:
  cd backend
  python build_v2_model.py
"""

import sys
import os
import json
import time
import logging
import warnings
import joblib
import numpy as np
import pandas as pd
from pathlib import Path
from scipy.sparse import hstack

from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.preprocessing import LabelEncoder
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.metrics import (
    accuracy_score, f1_score, precision_score, recall_score,
    roc_auc_score, classification_report, confusion_matrix,
)

warnings.filterwarnings("ignore")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
logger = logging.getLogger("build_v2")

# ── paths ──────────────────────────────────────────────────────────
ROOT           = Path(__file__).parent
DATA_DIR       = ROOT / "data"
DATA_DIR.mkdir(exist_ok=True)

MODEL_V2_PATH    = DATA_DIR / "model_v2.pkl"
VEC_V2_PATH      = DATA_DIR / "vectorizer_v2.pkl"
SEC_FEAT_V2_PATH = DATA_DIR / "sec_features_v2.pkl"
LE_V2_PATH       = DATA_DIR / "label_encoder_v2.pkl"
EVAL_PATH        = DATA_DIR / "evaluation_report.json"
REGISTRY_PATH    = DATA_DIR / "model_registry.json"

# Try v3 first, then v2, then v1
for candidate in ["ml_training_data_v3.csv", "ml_training_data_v2.csv", "ml_training_data.csv"]:
    TRAINING_PATH = DATA_DIR / candidate
    if TRAINING_PATH.exists():
        break


# ── helpers ────────────────────────────────────────────────────────

def banner(msg: str):
    print("\n" + "─" * 65)
    print(f"  {msg}")
    print("─" * 65)


def _load_data() -> pd.DataFrame:
    banner(f"Loading data: {TRAINING_PATH.name}")
    df = pd.read_csv(str(TRAINING_PATH))
    logger.info(f"Loaded {len(df):,} rows — columns: {list(df.columns)}")

    # Normalise column names
    df.columns = [c.strip().lower() for c in df.columns]

    # Determine label column
    if "attack_type" in df.columns:
        df["attack_type"] = df["attack_type"].str.strip().str.lower()
        logger.info(f"Classes: {sorted(df['attack_type'].unique())}")
        logger.info(f"Distribution:\n{df['attack_type'].value_counts().to_string()}")
        return df[["text", "attack_type"]].dropna()
    elif "label" in df.columns:
        # Binary → convert 0/1 to normal/attack
        df["attack_type"] = df["label"].apply(lambda x: "normal" if int(x) == 0 else "attack")
        logger.warning("Only binary labels found — training binary model (not ideal for v2)")
        return df[["text", "attack_type"]].dropna()
    else:
        raise ValueError("Training CSV must have 'attack_type' or 'label' column")


def _split(df: pd.DataFrame):
    X = df["text"].values
    y = df["attack_type"].values

    X_tv, X_test, y_tv, y_test = train_test_split(
        X, y, test_size=0.15, random_state=42, stratify=y,
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_tv, y_tv, test_size=0.12, random_state=42, stratify=y_tv,
    )
    logger.info(
        f"Split — train:{len(y_train):,}  val:{len(y_val):,}  test:{len(y_test):,}"
    )
    return X_train, X_val, X_test, y_train, y_val, y_test


def _build_vectorizers():
    from app.ml.features import SecurityFeatureExtractor

    vec = TfidfVectorizer(
        ngram_range    = (1, 3),
        max_features   = 3000,
        lowercase      = True,
        strip_accents  = "unicode",
        sublinear_tf   = True,
        min_df         = 2,
        max_df         = 0.95,
        analyzer       = "char_wb",   # character-level → catches obfuscation better
    )
    sec = SecurityFeatureExtractor()
    return vec, sec


def _make_features(vec, sec, X, fit=False):
    if fit:
        Xt = vec.fit_transform(X)
    else:
        Xt = vec.transform(X)
    Xs = sec.transform(X)
    return hstack([Xt, Xs], format="csr")


def _build_classifier(n_classes: int) -> RandomForestClassifier:
    return RandomForestClassifier(
        n_estimators    = 300,
        max_depth       = 15,          # prevent overfitting
        min_samples_leaf= 5,           # generalisation
        min_samples_split=10,
        max_features    = "sqrt",
        class_weight    = "balanced",
        random_state    = 42,
        n_jobs          = -1,
    )


def _evaluate(clf, le, X_test_f, y_test, class_names, X_train_f, y_train):
    banner("Evaluation on Test Set")

    y_pred     = clf.predict(X_test_f)
    y_prob     = clf.predict_proba(X_test_f)
    y_train_pred = clf.predict(X_train_f)

    # Decode label indices back to class names
    pred_names  = le.inverse_transform(y_pred)
    true_names  = le.inverse_transform(y_test)
    train_names = le.inverse_transform(y_train_pred)
    true_train  = le.inverse_transform(y_train)

    train_acc = accuracy_score(true_train, train_names)
    test_acc  = accuracy_score(true_names, pred_names)
    f1_macro  = f1_score(true_names, pred_names, average="macro",    zero_division=0)
    f1_weight = f1_score(true_names, pred_names, average="weighted", zero_division=0)
    prec_macro = precision_score(true_names, pred_names, average="macro", zero_division=0)
    rec_macro  = recall_score(true_names, pred_names, average="macro",    zero_division=0)
    gap        = train_acc - test_acc

    try:
        roc_auc = roc_auc_score(
            y_test, y_prob, multi_class="ovr", average="macro",
            labels=list(range(len(class_names)))
        )
    except Exception:
        roc_auc = None

    cm_np = confusion_matrix(y_test, y_pred, labels=list(range(len(class_names))))
    total_fp = total_fn = 0
    for i in range(len(class_names)):
        tp = cm_np[i, i]
        total_fp += int(cm_np[:, i].sum() - tp)
        total_fn += int(cm_np[i, :].sum() - tp)

    per_class = classification_report(
        true_names, pred_names, zero_division=0, output_dict=True
    )

    print(f"\n  Train Accuracy : {train_acc*100:.2f}%")
    print(f"  Test  Accuracy : {test_acc*100:.2f}%")
    print(f"  Overfit Gap   : {gap*100:.2f}%  {'✅' if gap < 0.05 else '⚠️'}")
    print(f"  F1 (macro)    : {f1_macro*100:.2f}%")
    print(f"  Precision     : {prec_macro*100:.2f}%")
    print(f"  Recall        : {rec_macro*100:.2f}%")
    if roc_auc:
        print(f"  ROC-AUC       : {roc_auc*100:.2f}%")
    print(f"  FP / FN       : {total_fp} / {total_fn}")

    print(f"\n  Per-class report:")
    for cls in class_names:
        if cls in per_class:
            m = per_class[cls]
            bar = "✅" if m["f1-score"] >= 0.85 else ("⚠️" if m["f1-score"] >= 0.70 else "❌")
            print(
                f"    {cls:22s}  P={m['precision']:.2f}  R={m['recall']:.2f}  "
                f"F1={m['f1-score']:.2f}  {bar}"
            )

    return {
        "train_accuracy":         round(train_acc, 4),
        "test_accuracy":          round(test_acc, 4),
        "f1_macro":               round(f1_macro, 4),
        "f1_weighted":            round(f1_weight, 4),
        "precision_macro":        round(prec_macro, 4),
        "recall_macro":           round(rec_macro, 4),
        "roc_auc_macro":          round(roc_auc, 4) if roc_auc else None,
        "overfitting_gap":        round(gap, 4),
        "total_false_positives":  total_fp,
        "total_false_negatives":  total_fn,
        "confusion_matrix":       cm_np.tolist(),
        "class_names":            class_names,
        "per_class_report":       per_class,
        "model_version":          "v2.0",
        "trained_at":             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
    }


def _save_evaluation(metrics: dict):
    with open(EVAL_PATH, "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, ensure_ascii=False)
    logger.info(f"Evaluation report saved → {EVAL_PATH}")


def _update_registry(metrics: dict):
    reg = {"active_version": "v2.0", "models": {}}
    if REGISTRY_PATH.exists():
        try:
            with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
                reg = json.load(f)
        except Exception:
            pass

    reg["models"]["v2.0"] = {
        "version":       "v2.0",
        "model_path":    str(MODEL_V2_PATH),
        "registered_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "metrics":       metrics,
        "active":        True,
    }
    # Deactivate old
    for v, m in reg["models"].items():
        if v != "v2.0":
            m["active"] = False
    reg["active_version"] = "v2.0"

    with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump(reg, f, indent=2, ensure_ascii=False)
    logger.info(f"Model registry updated → {REGISTRY_PATH}")


# ── main ───────────────────────────────────────────────────────────

def build():
    t0 = time.time()
    banner("Virex v2 Model Builder")

    # 1. Load
    df = _load_data()

    # 2. Encode labels
    le          = LabelEncoder()
    y_encoded   = le.fit_transform(df["attack_type"].values)
    class_names = list(le.classes_)
    df["y"]     = y_encoded
    logger.info(f"Classes ({len(class_names)}): {class_names}")

    # 3. Split
    X_train, X_val, X_test, y_train, y_val, y_test = _split(
        df.rename(columns={"y": "attack_type"})
          .assign(attack_type=y_encoded)
    )
    # Re-split using encoded y
    X_tv, X_test, y_tv, y_test = train_test_split(
        df["text"].values, y_encoded,
        test_size=0.15, random_state=42, stratify=y_encoded,
    )
    X_train, X_val, y_train, y_val = train_test_split(
        X_tv, y_tv,
        test_size=0.12, random_state=42, stratify=y_tv,
    )
    logger.info(
        f"Train:{len(y_train):,}  Val:{len(y_val):,}  Test:{len(y_test):,}"
    )

    # 4. Vectorize (fit on TRAIN only — no data leakage)
    banner("Building feature matrices")
    vec, sec = _build_vectorizers()

    logger.info("Fitting TF-IDF + SecurityFeatureExtractor on training set...")
    X_train_f = _make_features(vec, sec, X_train, fit=True)
    X_val_f   = _make_features(vec, sec, X_val)
    X_test_f  = _make_features(vec, sec, X_test)
    logger.info(f"Feature matrix shape: {X_train_f.shape}")

    # 5. Train
    banner("Training RandomForestClassifier (300 trees)")
    clf = _build_classifier(len(class_names))
    clf.fit(X_train_f, y_train)

    # 6. Validation check
    y_val_pred = clf.predict(X_val_f)
    val_acc    = accuracy_score(y_val, y_val_pred)
    val_f1     = f1_score(y_val, y_val_pred, average="macro", zero_division=0)
    logger.info(f"Validation — Acc:{val_acc*100:.2f}%  F1:{val_f1*100:.2f}%")

    # 7. Full evaluation
    metrics = _evaluate(clf, le, X_test_f, y_test, class_names, X_train_f, y_train)
    metrics["val_accuracy"] = round(val_acc, 4)
    metrics["val_f1_macro"] = round(val_f1, 4)
    metrics["train_samples"]= int(len(y_train))
    metrics["val_samples"]  = int(len(y_val))
    metrics["test_samples"] = int(len(y_test))

    # 8. Save artifacts
    banner("Saving model artifacts")
    joblib.dump(clf, str(MODEL_V2_PATH))
    joblib.dump(vec, str(VEC_V2_PATH))
    joblib.dump(sec, str(SEC_FEAT_V2_PATH))
    joblib.dump(le,  str(LE_V2_PATH))

    sizes = {
        "model_v2.pkl":       MODEL_V2_PATH.stat().st_size,
        "vectorizer_v2.pkl":  VEC_V2_PATH.stat().st_size,
        "sec_features_v2.pkl":SEC_FEAT_V2_PATH.stat().st_size,
        "label_encoder_v2.pkl":LE_V2_PATH.stat().st_size,
    }
    for name, size in sizes.items():
        print(f"  ✅ {name:28s} {size/1024:.0f} KB")

    # 9. Persist metrics
    _save_evaluation(metrics)
    _update_registry(metrics)

    elapsed = time.time() - t0
    banner(f"Done in {elapsed:.1f}s")
    print(f"\n  Test Accuracy : {metrics['test_accuracy']*100:.2f}%")
    print(f"  F1 (macro)    : {metrics['f1_macro']*100:.2f}%")
    print(f"  Overfit Gap   : {metrics['overfitting_gap']*100:.2f}%")
    print("\n  The v2 model is now active.")
    print("  Restart your Flask app — inference.py will auto-load v2.\n")


if __name__ == "__main__":
    # Add project root to sys.path so we can import app.ml.features
    sys.path.insert(0, str(Path(__file__).parent))
    build()
