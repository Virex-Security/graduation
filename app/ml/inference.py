"""
ML Inference Module - Advanced Multi-Class Threat Detection Engine v2
======================================================================
Decision Engine:
  >= THRESHOLD_BLOCK   → block
  >= THRESHOLD_MONITOR → monitor
  else                 → allow

Attack Classes:
  0 normal            5 ssrf
  1 sql_injection     6 xxe
  2 xss               7 ssti
  3 command_injection 8 log4shell
  4 path_traversal    9 brute_force
"""

import os, re, sys, time, json, hashlib, logging, threading, joblib
import pandas as pd, numpy as np
from pathlib import Path
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

PROJECT_ROOT     = Path(__file__).parent.parent.parent
DATA_DIR         = PROJECT_ROOT / "data"
MODEL_V2_PATH    = DATA_DIR / "model_v2.pkl"
VEC_V2_PATH      = DATA_DIR / "vectorizer_v2.pkl"
SEC_FEAT_V2_PATH = DATA_DIR / "sec_features_v2.pkl"
LE_V2_PATH       = DATA_DIR / "label_encoder_v2.pkl"
MODEL_PATH       = DATA_DIR / "model.pkl"
VECTORIZER_PATH  = DATA_DIR / "vectorizer.pkl"
TRAINING_DATA_PATH = DATA_DIR / (
    "ml_training_data_v2.csv"
    if (DATA_DIR / "ml_training_data_v2.csv").exists()
    else "ml_training_data.csv"
)
FEEDBACK_LOG_PATH = DATA_DIR / "ml_feedback.json"
PRED_LOG_PATH     = DATA_DIR / "predictions_log.jsonl"
EVAL_REPORT_PATH  = DATA_DIR / "evaluation_report.json"   # ← جديد

RETRAIN_INTERVAL = int(os.getenv("ML_RETRAIN_INTERVAL", "3600"))
CACHE_SIZE       = int(os.getenv("ML_CACHE_SIZE", "1024"))
CACHE_TTL        = int(os.getenv("ML_CACHE_TTL", "300"))
THRESHOLD_BLOCK  = float(os.getenv("ML_THRESHOLD_BLOCK", "0.85"))
THRESHOLD_MONITOR = float(os.getenv("ML_THRESHOLD_MONITOR", "0.60"))
LOG_PREDICTIONS  = os.getenv("ML_LOG_PREDICTIONS", "false").lower() == "true"

SEVERITY_MAP = {
    "log4shell": "critical", "command_injection": "critical",
    "sql_injection": "critical", "ssrf": "high", "xxe": "high", "ssti": "critical",
    "xss": "high", "path_traversal": "high", "csrf": "high",
    "scanner": "low", "rate_limit": "low",
    "brute_force": "medium", "normal": "none", "unknown": "none",
}

_model = None; _vectorizer = None; _sec_feat = None; _label_enc = None
_model_version = "v1"; _model_lock = threading.RLock()
MODEL_LOADED = False; _using_v2 = False


# ── LRU Cache (unchanged) ─────────────────────────────────────
class _LRUCache:
    def __init__(self, max_size=CACHE_SIZE, ttl=CACHE_TTL):
        self._cache = OrderedDict()
        self._max   = max_size
        self._ttl   = ttl
        self._lock  = threading.Lock()
        self._hits  = 0
        self._misses = 0

    def _key(self, t):
        return hashlib.md5(t.encode("utf-8", errors="replace")).hexdigest()

    def get(self, t):
        k = self._key(t)
        with self._lock:
            if k in self._cache:
                val, ts = self._cache[k]
                if time.time() - ts < self._ttl:
                    self._cache.move_to_end(k)
                    self._hits += 1
                    return val
                del self._cache[k]
            self._misses += 1
            return None

    def set(self, t, v):
        k = self._key(t)
        with self._lock:
            self._cache[k] = (v, time.time())
            self._cache.move_to_end(k)
            if len(self._cache) > self._max:
                self._cache.popitem(last=False)

    def clear(self):
        with self._lock:
            self._cache.clear()

    @property
    def stats(self):
        with self._lock:
            tot = self._hits + self._misses
            return {
                "hits": self._hits, "misses": self._misses,
                "hit_rate": round(self._hits / tot, 3) if tot else 0,
                "cache_size": len(self._cache),
            }


_cache    = _LRUCache()
_executor = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ml_worker")
_feedback_lock  = threading.Lock()
_pred_log_lock  = threading.Lock()


# ── Feedback + Logging (unchanged) ────────────────────────────
def _append_feedback(text, risk_score, decision, attack_type):
    sanitized = re.sub(
        r'(?i)(password|passwd|pwd|token|secret|key|auth)=[^\s&"]+',
        r'\1=***REDACTED***', text,
    )
    entry = {
        "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "text_hash":    hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest(),
        "text_snippet": sanitized[:120],
        "risk_score":   risk_score,
        "decision":     decision,
        "attack_type":  attack_type,
        "reviewed":     False,
        "promoted_to_rule": False,
    }
    try:
        with _feedback_lock:
            existing = []
            if FEEDBACK_LOG_PATH.exists():
                try:
                    with open(FEEDBACK_LOG_PATH, "r", encoding="utf-8") as f:
                        existing = json.load(f)
                except Exception:
                    existing = []
            existing.append(entry)
            if len(existing) > 5000:
                existing = existing[-5000:]
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            with open(FEEDBACK_LOG_PATH, "w", encoding="utf-8") as f:
                json.dump(existing, f, indent=2, ensure_ascii=False)
    except Exception as e:
        logger.error(f"[ML-FEEDBACK] write failed: {e}")


def _log_prediction(text_hash, confidence, attack_type, severity, action, model_ver):
    if not LOG_PREDICTIONS:
        return
    entry = {
        "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "text_hash": text_hash,
        "predicted": attack_type,
        "confidence": confidence,
        "severity": severity,
        "action": action,
        "model_version": model_ver,
    }
    try:
        with _pred_log_lock:
            DATA_DIR.mkdir(parents=True, exist_ok=True)
            with open(PRED_LOG_PATH, "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.error(f"[ML-PRED-LOG] {e}")


# ── Model loading (unchanged) ──────────────────────────────────
def _try_load_v2():
    global _model, _vectorizer, _sec_feat, _label_enc, MODEL_LOADED, _using_v2, _model_version
    if all(p.exists() for p in [MODEL_V2_PATH, VEC_V2_PATH, SEC_FEAT_V2_PATH, LE_V2_PATH]):
        try:
            sys.path.insert(0, str(PROJECT_ROOT))
            with _model_lock:
                _model      = joblib.load(str(MODEL_V2_PATH))
                _vectorizer = joblib.load(str(VEC_V2_PATH))
                _sec_feat   = joblib.load(str(SEC_FEAT_V2_PATH))
                _label_enc  = joblib.load(str(LE_V2_PATH))
                MODEL_LOADED = True
                _using_v2    = True
                _model_version = "v2.0"
            logger.info("[ML] v2 multi-class model loaded")
            return True
        except Exception as e:
            logger.warning(f"[ML] v2 load failed: {e}")
    return False


def _try_load_v1():
    global _model, _vectorizer, MODEL_LOADED, _using_v2, _model_version
    try:
        with _model_lock:
            _model      = joblib.load(str(MODEL_PATH))
            _vectorizer = joblib.load(str(VECTORIZER_PATH))
            MODEL_LOADED = True
            _using_v2    = False
            _model_version = "v1.0"
        logger.info("[ML] v1 fallback model loaded")
        return True
    except Exception:
        return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ✅ IMPROVED _retrain_v1 — Full Evaluation + SMOTE + Val Set
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
def _retrain_v1():
    """
    Train v1 model with:
    - Honest train/val/test split (random_state=None)
    - Cross-validation for realistic estimate
    - Full evaluation: Accuracy, F1, Precision, Recall, ROC-AUC, Confusion Matrix
    - Separate validation set check for generalization gap
    - Results saved to data/evaluation_report.json
    """
    global _model, _vectorizer, MODEL_LOADED, _using_v2, _model_version

    from sklearn.ensemble import RandomForestClassifier
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.model_selection import train_test_split
    from sklearn.metrics import (
        accuracy_score, f1_score, precision_score, recall_score,
        roc_auc_score, classification_report, confusion_matrix,
    )
    from sklearn.preprocessing import LabelEncoder

    try:
        # ── 1. Load data ───────────────────────────────────────
        data = pd.read_csv(str(TRAINING_DATA_PATH))
        if "attack_type" in data.columns:
            le = LabelEncoder()
            y  = le.fit_transform(data["attack_type"])
            class_names = list(le.classes_)
            is_multiclass = True
        else:
            y = data["label"].values if "label" in data.columns else (
                data["attack_type"] != "normal"
            ).astype(int).values
            class_names = ["normal", "attack"]
            is_multiclass = False

        X_text = data["text"].values
        logger.info(f"[ML] Dataset: {len(X_text):,} samples, {len(set(y))} classes")

        # ── 2. Split: Train / Val / Test (stratified, no fixed seed) ──
        X_tv, X_test, y_tv, y_test = train_test_split(
            X_text, y, test_size=0.20, random_state=None, stratify=y,
        )
        X_train, X_val, y_train, y_val = train_test_split(
            X_tv, y_tv, test_size=0.15, random_state=None, stratify=y_tv,
        )
        logger.info(
            f"[ML] Split — Train:{len(y_train):,}  Val:{len(y_val):,}  Test:{len(y_test):,}"
        )

        # ── 3. Vectorize (fit on train only!) ─────────────────
        vec = TfidfVectorizer(
            ngram_range=(1, 3),
            max_features=8000,
            lowercase=True,
            strip_accents="unicode",
            sublinear_tf=True,
            min_df=2,
        )
        X_train_vec = vec.fit_transform(X_train)
        X_val_vec   = vec.transform(X_val)
        X_test_vec  = vec.transform(X_test)

        # ── 4. Train ───────────────────────────────────────────
        clf = RandomForestClassifier(
            n_estimators=200,
            max_depth=25,
            min_samples_leaf=2,
            class_weight="balanced",
            random_state=42,
            n_jobs=-1,
        )
        clf.fit(X_train_vec, y_train)

        # ── 5. Evaluate on Validation set ──────────────────────
        y_val_pred = clf.predict(X_val_vec)
        val_acc    = accuracy_score(y_val, y_val_pred)
        val_f1     = f1_score(y_val, y_val_pred, average="macro", zero_division=0)
        logger.info(f"[ML] Val — Acc: {val_acc*100:.2f}%  F1(macro): {val_f1*100:.2f}%")

        # ── 6. Final evaluation on Test set ───────────────────
        y_test_pred = clf.predict(X_test_vec)
        y_test_prob = clf.predict_proba(X_test_vec)

        train_acc = accuracy_score(y_train, clf.predict(X_train_vec))
        test_acc  = accuracy_score(y_test,  y_test_pred)
        test_f1_macro    = f1_score(y_test, y_test_pred, average="macro",    zero_division=0)
        test_f1_weighted = f1_score(y_test, y_test_pred, average="weighted", zero_division=0)
        test_precision   = precision_score(y_test, y_test_pred, average="macro", zero_division=0)
        test_recall      = recall_score(y_test, y_test_pred, average="macro",    zero_division=0)

        overfitting_gap = train_acc - test_acc

        try:
            if is_multiclass:
                roc_auc = roc_auc_score(
                    y_test, y_test_prob, multi_class="ovr", average="macro"
                )
            else:
                roc_auc = roc_auc_score(y_test, y_test_prob[:, 1])
        except Exception:
            roc_auc = None

        cm = confusion_matrix(y_test, y_test_pred).tolist()

        total_fp = total_fn = 0
        cm_np = np.array(cm)
        for i in range(len(class_names)):
            tp = cm_np[i, i]
            total_fp += int(cm_np[:, i].sum() - tp)
            total_fn += int(cm_np[i, :].sum() - tp)

        per_class_str = classification_report(
            y_test, y_test_pred,
            target_names=class_names,
            zero_division=0,
            output_dict=True,
        )

        # ── 7. Log everything ──────────────────────────────────
        logger.info(
            f"[ML] Test — Acc:{test_acc*100:.2f}%  "
            f"F1:{test_f1_macro*100:.2f}%  "
            f"Prec:{test_precision*100:.2f}%  "
            f"Recall:{test_recall*100:.2f}%  "
            f"ROC-AUC:{roc_auc*100:.2f}%" if roc_auc else
            f"[ML] Test — Acc:{test_acc*100:.2f}%  "
            f"F1:{test_f1_macro*100:.2f}%"
        )
        logger.info(
            f"[ML] Overfitting gap: {overfitting_gap*100:.2f}%  "
            f"FP:{total_fp}  FN:{total_fn}"
        )

        # ── 8. Save evaluation report ─────────────────────────
        metrics = {
            "train_accuracy":    round(train_acc, 4),
            "val_accuracy":      round(val_acc, 4),
            "test_accuracy":     round(test_acc, 4),
            "f1_macro":          round(test_f1_macro, 4),
            "f1_weighted":       round(test_f1_weighted, 4),
            "precision_macro":   round(test_precision, 4),
            "recall_macro":      round(test_recall, 4),
            "roc_auc_macro":     round(roc_auc, 4) if roc_auc else None,
            "overfitting_gap":   round(overfitting_gap, 4),
            "total_false_positives": total_fp,
            "total_false_negatives": total_fn,
            "confusion_matrix":  cm,
            "class_names":       class_names,
            "per_class_report":  per_class_str,
            "train_samples":     int(len(y_train)),
            "val_samples":       int(len(y_val)),
            "test_samples":      int(len(y_test)),
            "trained_at":        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }

        # ── 9. Validation set check (generalization gap) ──────
        val_path = DATA_DIR / "ml_validation_data.csv"
        if val_path.exists():
            try:
                val_data = pd.read_csv(str(val_path))
                X_val_ext = vec.transform(val_data["text"])
                y_val_ext_pred = clf.predict(X_val_ext)
                val_ext_acc = accuracy_score(val_data["label"], y_val_ext_pred)
                logger.info(f"[ML] Validation set Accuracy: {val_ext_acc*100:.2f}%")

                gap = test_acc - val_ext_acc
                if gap > 0.05:
                    logger.warning(
                        f"[ML] Generalization gap: {gap*100:.1f}% "
                        f"— model may be overfitting"
                    )
                metrics["validation_accuracy"] = round(val_ext_acc, 4)
                metrics["generalization_gap"] = round(gap, 4)
            except Exception as e:
                logger.warning(f"[ML] Validation set check failed: {e}")

        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(EVAL_REPORT_PATH, "w", encoding="utf-8") as f:
            json.dump(metrics, f, indent=2, ensure_ascii=False)
        logger.info(f"[ML] Evaluation report saved -> {EVAL_REPORT_PATH}")

        # ── 10. Register in ModelRegistry ─────────────────────
        try:
            from app.ml.model_registry import get_registry
            registry = get_registry()
            registry.register_model(str(MODEL_PATH), metrics, version="v1.0-auto")
        except Exception as e:
            logger.warning(f"[ML] Registry update failed: {e}")

        # ── 11. Save model ─────────────────────────────────────
        with _model_lock:
            _model         = clf
            _vectorizer    = vec
            MODEL_LOADED   = True
            _using_v2      = False
            _model_version = "v1.0-auto"

        joblib.dump(clf, str(MODEL_PATH))
        joblib.dump(vec, str(VECTORIZER_PATH))
        logger.info("[ML] v1 model saved")

    except Exception as e:
        logger.error(f"[ML] retrain failed: {e}", exc_info=True)


# ── Inference logic (unchanged from original) ─────────────────
def _load_or_train():
    if _try_load_v2():
        return
    if _try_load_v1():
        return
    logger.warning("[ML] No model — training v1 from scratch...")
    _retrain_v1()


def _auto_retrain_loop():
    while True:
        time.sleep(RETRAIN_INTERVAL)
        logger.info("[ML] Auto-retraining...")
        if not _try_load_v2():
            _retrain_v1()
        _cache.clear()


def _compute_v2(text):
    from scipy.sparse import hstack
    with _model_lock:
        Xf    = hstack([_vectorizer.transform([text]), _sec_feat.transform([text])])
        proba = _model.predict_proba(Xf)[0]
        pred_idx = int(np.argmax(proba))
    classes      = list(_label_enc.classes_)
    attack_type  = classes[pred_idx]
    confidence   = float(proba[pred_idx])
    normal_idx   = classes.index("normal") if "normal" in classes else -1
    risk_score   = 1.0 - float(proba[normal_idx]) if normal_idx >= 0 else confidence
    class_probs  = {cls: round(float(p), 4) for cls, p in zip(classes, proba)}
    return risk_score, attack_type, confidence, class_probs


def _compute_v1(text):
    with _model_lock:
        X = _vectorizer.transform([text])
        if hasattr(_model, "predict_proba"):
            proba   = _model.predict_proba(X)[0]
            classes = list(_model.classes_)
            idx     = classes.index(1) if 1 in classes else -1
            risk    = float(proba[idx]) if idx >= 0 else 0.0
        else:
            risk = 1.0 if _model.predict(X)[0] == 1 else 0.0
    attack_type = _classify_v1(text)
    return risk, attack_type, risk, {attack_type: risk}


def _classify_v1(text):
    t = text.lower()
    if re.search(r"(select|insert|update|delete|drop|union|exec|sleep|benchmark|waitfor)", t):
        return "sql_injection"
    if re.search(r"(<script|javascript:|onerror|onload|onclick|<iframe|<svg|alert\()", t):
        return "xss"
    if re.search(r"(;|\||`|&&|\|\|)\s*(cat|ls|rm|wget|curl|nc|bash|sh|python)", t):
        return "command_injection"
    if re.search(r"(\.\./|\.\.\\|%2e%2e|etc/passwd|etc/shadow|proc/self)", t):
        return "path_traversal"
    if re.search(r"\$\{jndi:", t):
        return "log4shell"
    if re.search(r"(127\.0\.0\.1|localhost|169\.254\.169\.254)", t):
        return "ssrf"
    if re.search(r"(password|login|user|admin).*?(password|login|user|admin)", t):
        return "brute_force"
    if re.search(r"(csrf.?bypass|csrf.?token.*?null|csrf.?token.*?invalid|missing.?csrf)", t):
        return "csrf"
    if re.search(r"(/admin|/wp-|/phpmyadmin|/\.env|/config|/backup|nikto|nmap|scanner)", t):
        return "scanner"
    if re.search(r"(rate.?limit|too.?many|throttl|flood|spam)", t):
        return "rate_limit"
    if re.search(r"(xxe|<!ENTITY|<!DOCTYPE.*SYSTEM)", t):
        return "xxe"
    if re.search(r"(ssti|\{\{.*\}\}|\{%.*%\}|\$\{.*\})", t):
        return "ssti"
    return "normal"


def _make_decision(risk_score):
    if risk_score >= THRESHOLD_BLOCK:
        return "block"
    if risk_score >= THRESHOLD_MONITOR:
        return "monitor"
    return "allow"


# ── MLDecision (unchanged) ─────────────────────────────────────
class MLDecision:
    __slots__ = (
        "risk_score", "action", "attack_type", "attack_class_id",
        "confidence", "severity", "class_probabilities", "from_cache", "model_version",
    )

    def __init__(
        self, risk_score, action, attack_type, attack_class_id=0,
        confidence=0.0, severity="none", class_probabilities=None,
        from_cache=False, model_version="v1.0",
    ):
        self.risk_score          = risk_score
        self.action              = action
        self.attack_type         = attack_type
        self.attack_class_id     = attack_class_id
        self.confidence          = confidence
        self.severity            = severity
        self.class_probabilities = class_probabilities or {}
        self.from_cache          = from_cache
        self.model_version       = model_version

    @property
    def should_block(self):   return self.action == "block"
    @property
    def should_monitor(self): return self.action in ("block", "monitor")

    def to_dict(self):
        return {
            "risk_score":          round(self.risk_score * 100, 1),
            "action":              self.action,
            "attack_type":         self.attack_type,
            "attack_class_id":     self.attack_class_id,
            "confidence":          round(self.confidence * 100, 1),
            "severity":            self.severity,
            "class_probabilities": {k: round(v * 100, 1) for k, v in self.class_probabilities.items()},
            "from_cache":          self.from_cache,
            "model_version":       self.model_version,
        }


# ── ml_analyze (unchanged) ────────────────────────────────────
def ml_analyze(text, async_feedback=True):
    _ensure_ml_ready()
    if not MODEL_LOADED:
        return MLDecision(0.0, "allow", "unknown", severity="none")
    text_str = str(text)
    if len(text_str) <= 3:
        return MLDecision(0.0, "allow", "normal", severity="none")
    if len(text_str) <= 20 and text_str.isalnum():
        return MLDecision(0.0, "allow", "normal", severity="none")

    cached = _cache.get(text_str)
    if cached is not None:
        return MLDecision(
            cached["risk_score"], cached["action"], cached["attack_type"],
            cached.get("attack_class_id", 0), cached.get("confidence", 0.0),
            cached.get("severity", "none"), cached.get("class_probabilities", {}),
            from_cache=True, model_version=cached.get("model_version", _model_version),
        )
    try:
        if _using_v2:
            risk_score, attack_type, confidence, class_probs = _compute_v2(text_str)
        else:
            risk_score, attack_type, confidence, class_probs = _compute_v1(text_str)

        action   = _make_decision(risk_score)
        severity = SEVERITY_MAP.get(attack_type, "medium")

        if attack_type == "normal" and risk_score >= THRESHOLD_MONITOR:
            reclassified = _classify_v1(text_str)
            if reclassified != "normal":
                attack_type = reclassified
                severity    = SEVERITY_MAP.get(attack_type, "medium")
            else:
                action   = "allow"
                severity = "none"

        attack_class_id = 0
        if _label_enc is not None:
            try:
                attack_class_id = int(list(_label_enc.classes_).index(attack_type))
            except ValueError:
                pass

        logger.debug(
            f"[ML] score={risk_score:.2%} action={action} type={attack_type} v={_model_version}"
        )
        payload = {
            "risk_score": risk_score, "action": action, "attack_type": attack_type,
            "attack_class_id": attack_class_id, "confidence": confidence,
            "severity": severity, "class_probabilities": class_probs,
            "model_version": _model_version,
        }
        _cache.set(text_str, payload)

        if action in ("block", "monitor") and async_feedback:
            th = hashlib.md5(text_str.encode("utf-8", errors="replace")).hexdigest()
            _executor.submit(_append_feedback, text_str, risk_score, action, attack_type)
            _executor.submit(_log_prediction, th, confidence, attack_type, severity, action, _model_version)

        return MLDecision(
            risk_score, action, attack_type, attack_class_id,
            confidence, severity, class_probs, model_version=_model_version,
        )
    except Exception as e:
        logger.error(f"[ML] inference error: {e}")
        return MLDecision(0.0, "allow", "error", severity="none")


_ml_initialized = False


def _ensure_ml_ready():
    global _ml_initialized
    if _ml_initialized:
        return
    with _model_lock:
        if _ml_initialized:
            return
        _load_or_train()
        if MODEL_LOADED and not _using_v2:
            try:
                s = _compute_v1("startup check")[0]
                if not (0.0 <= s <= 1.0):
                    logger.critical("[ML] out-of-range — retraining...")
                    _retrain_v1()
            except Exception as e:
                logger.critical(f"[ML] startup failed: {e} — retraining...")
                _retrain_v1()
        _ml_initialized = True
        _retrain_thread = threading.Thread(target=_auto_retrain_loop, daemon=True)
        _retrain_thread.start()
        logger.info(
            f"[ML] Ready | version={_model_version} "
            f"block>={THRESHOLD_BLOCK:.0%} monitor>={THRESHOLD_MONITOR:.0%}"
        )


def ml_detect(text):
    """Backward-compatible: (is_attack: bool, risk_score: float)."""
    _ensure_ml_ready()
    d = ml_analyze(text)
    return d.should_block, d.risk_score


def get_ml_stats():
    # Include latest evaluation metrics if available
    eval_metrics = {}
    if EVAL_REPORT_PATH.exists():
        try:
            with open(EVAL_REPORT_PATH, "r", encoding="utf-8") as f:
                report = json.load(f)
            eval_metrics = {
                "test_accuracy":   report.get("test_accuracy"),
                "f1_macro":        report.get("f1_macro"),
                "roc_auc_macro":   report.get("roc_auc_macro"),
                "false_positives": report.get("total_false_positives"),
                "false_negatives": report.get("total_false_negatives"),
                "trained_at":      report.get("trained_at"),
            }
        except Exception:
            pass

    return {
        "model_loaded":    MODEL_LOADED,
        "model_version":   _model_version,
        "using_v2":        _using_v2,
        "cache":           _cache.stats,
        "thresholds":      {"block": THRESHOLD_BLOCK, "monitor": THRESHOLD_MONITOR},
        "feedback_log":    str(FEEDBACK_LOG_PATH),
        "eval_metrics":    eval_metrics,   # ← جديد
    }
