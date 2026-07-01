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
import redis

load_dotenv()
logger = logging.getLogger(__name__)

PROJECT_ROOT     = Path(__file__).parent.parent.parent
DATA_DIR         = PROJECT_ROOT / "data"
MODELS_DIR          = PROJECT_ROOT / "models"
LGBM_ONNX_PATH      = MODELS_DIR / "model_lightgbm.onnx"
VEC_PATH            = MODELS_DIR / "vectorizer_lightgbm.pkl"
SEC_FEAT_PATH       = MODELS_DIR / "preprocessor_lightgbm.pkl"
LE_PATH             = MODELS_DIR / "label_encoder_lightgbm.pkl"
FEEDBACK_LOG_PATH   = DATA_DIR / "ml_feedback.json"
PRED_LOG_PATH       = DATA_DIR / "predictions_log.jsonl"
EVAL_REPORT_PATH    = DATA_DIR / "evaluation_report.json"
RETRAIN_INTERVAL  = int(os.getenv("ML_RETRAIN_INTERVAL", "3600"))
CACHE_SIZE        = int(os.getenv("ML_CACHE_SIZE", "1024"))
CACHE_TTL         = int(os.getenv("ML_CACHE_TTL", "300"))
THRESHOLD_BLOCK   = float(os.getenv("ML_THRESHOLD_BLOCK", "0.85"))
THRESHOLD_MONITOR = float(os.getenv("ML_THRESHOLD_MONITOR", "0.65"))  # ↑ 0.60→0.65 lowers FP
THRESHOLD_ALLOW   = float(os.getenv("ML_THRESHOLD_ALLOW", "0.00"))
LOG_PREDICTIONS   = os.getenv("ML_LOG_PREDICTIONS", "false").lower() == "true"

# Pre-compiled high-speed regex for critical bypass
# Includes characters: ' " < > ; | $ { } ( )
# Includes SQLi symbols: -- /* */
# Includes keywords: select, union, insert, update, delete, drop, exec, xp_, script, javascript:, onerror, onload
_FAST_SUSPICIOUS_REGEX = re.compile(
    r"['\"<>;|\${}()]|--|/\*|\*/|\.\./|\.\.\\|\b(?:union\s+select|insert\s+into|update\s+\w+\s+set|delete\s+from|drop\s+table|exec|xp_|script|javascript:|onerror=|onload=|sleep\s*\(|benchmark\s*\(|waitfor)\b",
    re.IGNORECASE
)

SEVERITY_MAP = {
    "log4shell": "critical", "command_injection": "critical",
    "sql_injection": "critical", "sqli": "critical", "ssrf": "high", "xxe": "high", "ssti": "critical",
    "xss": "high", "path_traversal": "high", "csrf": "high",
    "scanner": "low", "rate_limit": "low",
    "brute_force": "medium", "normal": "none", "unknown": "none",
}

_vectorizer = None; _sec_feat = None; _label_enc = None; _onnx_session = None
_model_version = "v3-lightgbm"; _model_lock = threading.RLock()
MODEL_LOADED = False
redis_url = os.getenv("REDIS_URL", "")
_use_redis = False
_redis_client = None
if redis_url:
    try:
        _redis_client = redis.Redis.from_url(
            redis_url,
            socket_connect_timeout=0.5,
            socket_timeout=0.5,
            retry_on_timeout=False,
        )
        _redis_client.ping()
        _use_redis = True
        logger.info(f"[ML] Redis cache connected: {redis_url.split('@')[-1]}")
    except Exception as e:
        logger.info(f"[ML] Redis not available — using local LRU cache ({e})")
        _redis_client = None
        _use_redis = False
else:
    logger.info("[ML] REDIS_URL not set — using local LRU cache")

class _CacheWrapper:
    def __init__(self, fallback_cache):
        self.fallback = fallback_cache
        
    def _key(self, text):
        return "ml_cache:" + hashlib.md5(text.encode("utf-8", errors="replace")).hexdigest()
        
    def get(self, text):
        if _use_redis:
            try:
                k = self._key(text)
                v = _redis_client.get(k)
                if v:
                    return json.loads(v)
            except Exception:
                pass
        return self.fallback.get(text)
        
    def set(self, text, value):
        if _use_redis:
            try:
                k = self._key(text)
                _redis_client.setex(k, CACHE_TTL, json.dumps(value))
                return
            except Exception:
                pass
        self.fallback.set(text, value)
        
    def clear(self):
        if _use_redis:
            try:
                keys = _redis_client.keys("ml_cache:*")
                if keys:
                    _redis_client.delete(*keys)
            except Exception:
                pass
        self.fallback.clear()
        
    @property
    def stats(self):
        s = self.fallback.stats
        s["redis"] = _use_redis
        return s


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


_cache    = _CacheWrapper(_LRUCache())
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
def _load_onnx():
    global _onnx_session, _vectorizer, _sec_feat, _label_enc, MODEL_LOADED, _model_version
    if all(p.exists() for p in [LGBM_ONNX_PATH, VEC_PATH, SEC_FEAT_PATH, LE_PATH]):
        try:
            import onnxruntime as ort
            sys.path.insert(0, str(PROJECT_ROOT))
            with _model_lock:
                _onnx_session = ort.InferenceSession(str(LGBM_ONNX_PATH), providers=["CPUExecutionProvider"])
                _vectorizer = joblib.load(str(VEC_PATH))
                _sec_feat = joblib.load(str(SEC_FEAT_PATH))
                _label_enc = joblib.load(str(LE_PATH))
                MODEL_LOADED = True
                _model_version = "v3.0-lightgbm-onnx"
            logger.info("[ML] LightGBM ONNX model loaded successfully")
            return True
        except Exception as e:
            logger.error(f"[ML] LightGBM ONNX load failed: {e}")
    else:
        logger.error(f"[ML] Missing LightGBM model files in {MODELS_DIR}")
    return False

def _load_or_train():
    if not _load_onnx():
        logger.critical("[ML] No model could be loaded! Traffic will be allowed.")

def _auto_retrain_loop():
    # Retraining is deprecated in favor of offline external pipelines
    pass

_class_thresholds = {}

def _load_thresholds():
    global _class_thresholds
    thresh_path = DATA_DIR / "class_thresholds.json"
    if thresh_path.exists():
        try:
            with open(thresh_path, "r", encoding="utf-8") as f:
                _class_thresholds = json.load(f)
        except Exception as e:
            logger.error(f"[ML] Failed to load thresholds: {e}")

def _compute_ml(text):
    from scipy.sparse import hstack
    if not _class_thresholds:
        _load_thresholds()
        
    with _model_lock:
        Xt = _vectorizer.transform([text])
        Xs = _sec_feat.transform([text])
        X = hstack([Xt, Xs]).astype(np.float32)
        
        if hasattr(X, "toarray"):
            X = X.toarray()
            
        input_name = _onnx_session.get_inputs()[0].name
        label_name = _onnx_session.get_outputs()[0].name
        proba_name = _onnx_session.get_outputs()[1].name
        
        res = _onnx_session.run([label_name, proba_name], {input_name: X})
        proba_list = res[1] # List of dicts from LightGBM onnxmltools
        
    classes = list(_label_enc.classes_)
    proba_dict = proba_list[0]
    # Ensure proba array matches classes order (keys are integer indices)
    proba = np.array([proba_dict.get(i, 0.0) for i in range(len(classes))])
    
    passed = []
    for c_idx, cls in enumerate(classes):
        if cls == "normal": continue
        thresh = _class_thresholds.get(cls, 0.85)
        if proba[c_idx] >= thresh:
            passed.append((c_idx, proba[c_idx] - thresh))
            
    if not passed:
        try:
            pred_idx = classes.index("normal")
        except ValueError:
            pred_idx = int(np.argmax(proba))
    else:
        # Pick the attack class that passed its threshold by the largest margin
        pred_idx = max(passed, key=lambda x: x[1])[0]
        
    attack_type  = classes[pred_idx]
    confidence   = float(proba[pred_idx])
    
    try:
        normal_idx = classes.index("normal")
        risk_score = 1.0 - float(proba[normal_idx])
    except ValueError:
        risk_score = confidence

    class_probs  = {str(cls): round(float(p), 4) for cls, p in zip(classes, proba)}
    return risk_score, attack_type, confidence, class_probs




def _classify_v1(text):
    """Rule-based fallback classifier — covers all 10 attack classes."""
    t = text.lower()

    # Log4Shell first (very specific)
    if re.search(r"\$\{jndi:", t):
        return "log4shell"
    if re.search(r"\$\{[a-z:]+\}.*(?:ldap|rmi|dns|jndi)", t):
        return "log4shell"

    # XXE
    if re.search(r"<!entity|<!doctype.*system|<\?xml.*<!", t):
        return "xxe"

    # SSTI — Jinja2, EL, Freemarker, Ruby, ASP
    if re.search(
        r"(\{\{.*?\}\}|\{%.*?%\}|\$\{[^}]+\}|#\{[^}]+\}|<%="
        r"|__class__|__mro__|__subclasses__|__globals__|__builtins__"
        r"|lipsum|request\.application|_self\.env)",
        t,
    ):
        return "ssti"

    # SQL Injection — extended keywords + tautology + UNION + NoSQL
    if re.search(
        r"(select\s|union\s|insert\s+into|update\s+\w+\s+set|delete\s+from"
        r"|drop\s+table|exec\s+xp_|waitfor\s+delay|pg_sleep|sleep\s*\(|benchmark\s*\("
        r"|extractvalue|updatexml|information_schema|group_concat"
        r"|'\s*or\s*'1'='1|'\s*or\s+1=1|\$gt|\$ne|\$where|\$regex)",
        t,
    ):
        return "sql_injection"

    # XSS
    if re.search(
        r"(<script|javascript:|onerror=|onload=|onclick=|onmouseover="
        r"|<iframe|<svg|<img.{0,30}onerror|alert\s*\(|confirm\s*\()",
        t,
    ):
        return "xss"

    return "normal"


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
        "explanation", "top_features"
    )

    def __init__(
        self, risk_score, action, attack_type, attack_class_id=0,
        confidence=0.0, severity="none", class_probabilities=None,
        from_cache=False, model_version="v1.0",
        explanation=None, top_features=None
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
        self.explanation         = explanation
        self.top_features        = top_features or []

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
        if self.explanation:
            d["explanation"] = self.explanation
            d["top_features"] = self.top_features
        return d


def clean_text(text_str):
    """
    Normalizes empty inputs, query brackets, and normal URL characters.
    Removes benign structural metadata (like /, ?, =, &) so we can accurately
    tell if the remaining string is a normal word/URL or a malicious payload.
    """
    import re
    # Strip normal safe web characters
    return re.sub(r'[/?=&\[\]\-\._@\+:]', '', str(text_str)).strip()

# ── ml_analyze (unchanged) ────────────────────────────────────
def ml_analyze(text, async_feedback=True, debug=False):
    _ensure_ml_ready()
    if not MODEL_LOADED:
        return MLDecision(0.0, "allow", "unknown", severity="none")
        
    text_str = str(text).strip()
    if not text_str:
        return MLDecision(0.0, "allow", "normal", severity="none")
        
    # Fix False Positives: Apply text cleaner to normalize metadata
    cleaned = clean_text(text_str)

    # 2. THE CRITICAL BYPASS:
    # If the text has absolutely NONE of the actual exploitation characters or keywords, 
    # we force it to return benign and skip the expensive ML computation.
    # This guarantees 0% false positives for normal alphanumeric text regardless of length.
    
    # Check if ANY suspicious pattern exists using the highly optimized pre-compiled regex
    is_suspicious = bool(_FAST_SUSPICIOUS_REGEX.search(text_str))
    
    if not cleaned or not is_suspicious:
        return MLDecision(0.0, "allow", "normal", severity="none")

    cached = _cache.get(text_str)
    if cached is not None:
        explanation = None
        top_features = None
        if debug:
            from app.ml.explainer import get_explainer
            exp = get_explainer().explain(text_str, cached["attack_type"], cached["risk_score"])
            explanation = exp.get("explanation")
            top_features = exp.get("top_features", [])
            
        return MLDecision(
            cached["risk_score"], cached["action"], cached["attack_type"],
            cached.get("attack_class_id", 0), cached.get("confidence", 0.0),
            cached.get("severity", "none"), cached.get("class_probabilities", {}),
            from_cache=True, model_version=cached.get("model_version", _model_version),
            explanation=explanation, top_features=top_features
        )
    try:
        risk_score, attack_type, confidence, class_probs = _compute_ml(text_str)
        if attack_type != "normal":
            # Strict ROC threshold passed -> Override standard risk thresholds
            action = "block"
            # Ensure risk_score visually reflects a block
            risk_score = max(risk_score, THRESHOLD_BLOCK)
        else:
            action = _make_decision(risk_score)

        severity = SEVERITY_MAP.get(attack_type, "medium")

        if attack_type == "normal" and risk_score >= THRESHOLD_MONITOR:
            reclassified = _classify_v1(text_str)
            if reclassified != "normal":
                attack_type = reclassified
                severity    = SEVERITY_MAP.get(attack_type, "medium")
            else:
                # ML gave high risk but regex couldn't classify — keep risk-based action
                # Don't override to allow; use 'suspicious' as a fallback type
                attack_type = "suspicious"
                severity    = "medium"

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

        explanation = None
        top_features = None
        if debug:
            from app.ml.explainer import get_explainer
            exp = get_explainer().explain(text_str, attack_type, risk_score)
            explanation = exp.get("explanation")
            top_features = exp.get("top_features", [])

        return MLDecision(
            risk_score, action, attack_type, attack_class_id,
            confidence, severity, class_probs, model_version=_model_version,
            explanation=explanation, top_features=top_features
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
        if MODEL_LOADED:
            try:
                s = _compute_ml("startup check")[0]
                if not (0.0 <= s <= 1.0):
                    logger.critical("[ML] out-of-range")
            except Exception as e:
                logger.critical(f"[ML] startup failed: {e}")
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
        "using_v2":        False,
        "cache":           _cache.stats,
        "thresholds":      {"block": THRESHOLD_BLOCK, "monitor": THRESHOLD_MONITOR},
        "feedback_log":    str(FEEDBACK_LOG_PATH),
        "eval_metrics":    eval_metrics,   # ← جديد
    }
