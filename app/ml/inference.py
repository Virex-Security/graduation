"""
ML Inference Module - Advanced Threat Detection Engine
Decision Engine:
  >= THRESHOLD_BLOCK   → block
  >= THRESHOLD_MONITOR → monitor
  else                 → allow
"""
import os
import re
import time
import json
import hashlib
import logging
import threading
import joblib
import pandas as pd
from pathlib import Path
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
from dotenv import load_dotenv

load_dotenv()
logger = logging.getLogger(__name__)

# ── Paths ─────────────────────────────────────────────────────
PROJECT_ROOT       = Path(__file__).parent.parent.parent
DATA_DIR           = PROJECT_ROOT / "data"
MODEL_PATH         = DATA_DIR / "model.pkl"
VECTORIZER_PATH    = DATA_DIR / "vectorizer.pkl"
TRAINING_DATA_PATH = DATA_DIR / "ml_training_data.csv"
FEEDBACK_LOG_PATH  = DATA_DIR / "ml_feedback.json"

# ── Config (from .env with defaults) ─────────────────────────
RETRAIN_INTERVAL  = 3600
CACHE_SIZE        = 1024
CACHE_TTL         = 300
THRESHOLD_BLOCK   = float(os.getenv("ML_THRESHOLD_BLOCK",   "0.90"))
THRESHOLD_MONITOR = float(os.getenv("ML_THRESHOLD_MONITOR", "0.70"))

# ── Global State ──────────────────────────────────────────────
_model        = None
_vectorizer   = None
_model_lock   = threading.RLock()
MODEL_LOADED  = False


# ── LRU Cache ─────────────────────────────────────────────────
class _LRUCache:
    def __init__(self, max_size=CACHE_SIZE, ttl=CACHE_TTL):
        self._cache  = OrderedDict()
        self._max    = max_size
        self._ttl    = ttl
        self._lock   = threading.Lock()
        self._hits   = 0
        self._misses = 0

    def _key(self, text):
        return hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()

    def get(self, text):
        k = self._key(text)
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

    def set(self, text, value):
        k = self._key(text)
        with self._lock:
            self._cache[k] = (value, time.time())
            self._cache.move_to_end(k)
            if len(self._cache) > self._max:
                self._cache.popitem(last=False)

    def clear(self):
        with self._lock:
            self._cache.clear()

    @property
    def stats(self):
        with self._lock:
            total = self._hits + self._misses
            return {
                "hits":       self._hits,
                "misses":     self._misses,
                "hit_rate":   round(self._hits / total, 3) if total else 0,
                "cache_size": len(self._cache),
            }


_cache         = _LRUCache()
_executor      = ThreadPoolExecutor(max_workers=4, thread_name_prefix="ml_worker")
_feedback_lock = threading.Lock()


# ── Feedback Loop ─────────────────────────────────────────────
def _append_feedback(text, risk_score, decision, attack_type):
    sanitized_text = re.sub(
        r'(?i)(password|passwd|pwd|token|secret|key|auth)=[^\s&"]+',
        r'\1=***REDACTED***',
        text
    )
    entry = {
        "timestamp":        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "text_hash":        hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest(),
        "text_snippet":     sanitized_text[:120],
        "risk_score":       risk_score,
        "decision":         decision,
        "attack_type":      attack_type,
        "reviewed":         False,
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


# ── Model Training ────────────────────────────────────────────
def _load_or_train():
    global _model, _vectorizer, MODEL_LOADED
    try:
        with _model_lock:
            _model      = joblib.load(str(MODEL_PATH))
            _vectorizer = joblib.load(str(VECTORIZER_PATH))
            MODEL_LOADED = True
        logger.info("[ML] Model loaded from disk")
    except Exception:
        logger.warning("[ML] No model — training from scratch...")
        _retrain_model()


def _merge_feedback_into_training():
    merged_count = 0
    try:
        if not FEEDBACK_LOG_PATH.exists():
            return 0
        with _feedback_lock:
            with open(FEEDBACK_LOG_PATH, "r", encoding="utf-8") as f:
                feedback = json.load(f)
                
            new_entries = []
            for entry in feedback:
                if entry.get("reviewed") and not entry.get("promoted_to_rule"):
                    new_entries.append(entry)
                    entry["promoted_to_rule"] = True
                    
            if not new_entries:
                return 0
                
            import csv
            with open(TRAINING_DATA_PATH, "a", encoding="utf-8", newline="") as f:
                writer = csv.writer(f)
                for entry in new_entries:
                    text = entry.get("text_snippet", "")
                    label = 1 if entry.get("decision") == "block" else 0
                    writer.writerow([text, label])
                    
            with open(FEEDBACK_LOG_PATH, "w", encoding="utf-8") as f:
                json.dump(feedback, f, indent=2, ensure_ascii=False)
                
            merged_count = len(new_entries)
            logger.info(f"[ML-FEEDBACK] Merged {merged_count} reviewed items into training CSV.")
    except Exception as e:
        logger.error(f"[ML-FEEDBACK] merge failed: {e}")
    return merged_count

def _retrain_model():
    _merge_feedback_into_training()
    global _model, _vectorizer, MODEL_LOADED
    try:
        data = pd.read_csv(str(TRAINING_DATA_PATH))
        X_train, X_test, y_train, y_test = train_test_split(
            data["text"], data["label"],
            test_size=0.2, random_state=42, stratify=data["label"],
        )
        vec = TfidfVectorizer(ngram_range=(1, 2), max_features=5000, lowercase=True)
        X_tr = vec.fit_transform(X_train)
        clf  = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
        clf.fit(X_tr, y_train)
        with _model_lock:
            _model       = clf
            _vectorizer  = vec
            MODEL_LOADED = True
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(clf, str(MODEL_PATH))
        joblib.dump(vec, str(VECTORIZER_PATH))
        from sklearn.metrics import accuracy_score
        acc = accuracy_score(y_test, clf.predict(vec.transform(X_test)))
        logger.info(f"[ML] Retrained — Accuracy: {acc*100:.2f}%")
    except Exception as e:
        logger.error(f"[ML] Retrain failed: {e}")


def _auto_retrain_loop():
    while True:
        time.sleep(RETRAIN_INTERVAL)
        logger.info("[ML] Auto-retraining...")
        _retrain_model()
        _cache.clear()


# ── Risk Score ────────────────────────────────────────────────
def _compute_risk_score(text):
    with _model_lock:
        X = _vectorizer.transform([text])
        if hasattr(_model, "predict_proba"):
            proba   = _model.predict_proba(X)[0]
            classes = list(_model.classes_)
            idx     = classes.index(1) if 1 in classes else -1
            return float(proba[idx]) if idx >= 0 else 0.0
        raw = _model.predict(X)[0]
        return 1.0 if raw == 1 else 0.0


def _classify_attack_type(text):
    t = text.lower()
    if re.search(r"(select|insert|update|delete|drop|union|exec|sleep|benchmark|waitfor)", t, re.I):
        return "SQL Injection"
    if re.search(r"(<script|javascript:|onerror|onload|onclick|<iframe|<svg|alert\()", t, re.I):
        return "XSS"
    if re.search(r"(;|\||\`|&&|\|\|)\s*(cat|ls|rm|wget|curl|nc|bash|sh|python)", t, re.I):
        return "Command Injection"
    if re.search(r"(\.\./|\.\.\\|%2e%2e|etc/passwd|etc/shadow|proc/self)", t, re.I):
        return "Path Traversal"
    if re.search(r"(password|login|user|admin)", t, re.I):
        return "Brute Force"
    return "Anomaly"


def _make_decision(risk_score):
    if risk_score >= THRESHOLD_BLOCK:
        return "block"
    if risk_score >= THRESHOLD_MONITOR:
        return "monitor"
    return "allow"


# ── Decision Object ───────────────────────────────────────────
class MLDecision:
    __slots__ = ("risk_score", "action", "attack_type", "from_cache")

    def __init__(self, risk_score, action, attack_type, from_cache=False):
        self.risk_score  = risk_score
        self.action      = action
        self.attack_type = attack_type
        self.from_cache  = from_cache

    @property
    def should_block(self):
        return self.action == "block"

    @property
    def should_monitor(self):
        return self.action in ("block", "monitor")

    def to_dict(self):
        return {
            "risk_score":  round(self.risk_score * 100, 1),
            "action":      self.action,
            "attack_type": self.attack_type,
            "from_cache":  self.from_cache,
        }


# ── Public API ────────────────────────────────────────────────
def ml_analyze(text, async_feedback=True):
    if not MODEL_LOADED:
        return MLDecision(0.0, "allow", "Unknown")
    text_str = str(text)
    if len(text_str) <= 3:
        return MLDecision(0.0, "allow", "None")
    if len(text_str) <= 20 and text_str.isalnum():
        return MLDecision(0.0, "allow", "None")

    cached = _cache.get(text_str)
    if cached is not None:
        return MLDecision(cached["risk_score"], cached["action"],
                          cached["attack_type"], from_cache=True)
    try:
        risk_score  = _compute_risk_score(text_str)
        attack_type = _classify_attack_type(text_str) if risk_score >= THRESHOLD_MONITOR else "None"
        action      = _make_decision(risk_score)
        logger.debug(f"[ML] score={risk_score:.2%} action={action} type={attack_type}")
        _cache.set(text_str, {"risk_score": risk_score, "action": action, "attack_type": attack_type})
        if action in ("block", "monitor") and async_feedback:
            _executor.submit(_append_feedback, text_str, risk_score, action, attack_type)
        return MLDecision(risk_score, action, attack_type)
    except Exception as e:
        logger.error(f"[ML] error: {e}")
        return MLDecision(0.0, "allow", "Error")


def ml_detect(text):
    """Backward-compatible: (is_attack: bool, risk_score: float)."""
    d = ml_analyze(text)
    return d.should_block, d.risk_score


def get_ml_stats():
    return {
        "model_loaded": MODEL_LOADED,
        "cache":        _cache.stats,
        "thresholds":   {"block": THRESHOLD_BLOCK, "monitor": THRESHOLD_MONITOR},
        "feedback_log": str(FEEDBACK_LOG_PATH),
    }


# ── Startup ───────────────────────────────────────────────────
_load_or_train()

if MODEL_LOADED:
    try:
        test_score = _compute_risk_score("startup validation check")
        if not (0.0 <= test_score <= 1.0):
            logger.critical(f"[ML] predict_proba returned {test_score} (out of 0.0-1.0 range)! Version mismatch detected. Retraining model...")
            _retrain_model()
    except Exception as e:
        logger.critical(f"[ML] Startup validation failed with error: {e}. Retraining model...")
        _retrain_model()

_retrain_thread = threading.Thread(target=_auto_retrain_loop, daemon=True)
_retrain_thread.start()
logger.info(f"[ML] Ready | block≥{THRESHOLD_BLOCK:.0%} monitor≥{THRESHOLD_MONITOR:.0%} cache={CACHE_SIZE}")
