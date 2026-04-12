"""
Virex Security — Anomaly Detector
===================================
يكتشف zero-day attacks وأي traffic غير طبيعي
حتى لو المودل الرئيسي ما شافهاش قبل كده
"""

import logging
import threading
import numpy as np
import joblib
from pathlib import Path
from sklearn.ensemble import IsolationForest

logger = logging.getLogger(__name__)

PROJECT_ROOT   = Path(__file__).resolve().parent.parent.parent
DATA_DIR       = PROJECT_ROOT / "data"
ANOMALY_PATH   = DATA_DIR / "anomaly_model.pkl"


class AnomalyDetector:
    """
    يتدرب على الـ normal traffic بس.
    يرجع anomaly_score: كلما قل كلما كان أكثر شذوذاً.
    score < -0.1  → suspicious
    score < -0.3  → likely anomaly
    """

    def __init__(self):
        self._model  = IsolationForest(
            contamination=0.05,
            n_estimators=200,
            max_samples="auto",
            random_state=42,
            n_jobs=-1,
        )
        self._lock   = threading.Lock()
        self._fitted = False
        self._load()

    # ── persistence ──────────────────────────────────────────
    def _load(self):
        if ANOMALY_PATH.exists():
            try:
                self._model  = joblib.load(str(ANOMALY_PATH))
                self._fitted = True
                logger.info("[Anomaly] model loaded from disk")
            except Exception as e:
                logger.warning(f"[Anomaly] load failed: {e}")

    def save(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(self._model, str(ANOMALY_PATH))
        logger.info("[Anomaly] model saved")

    # ── feature extraction (standalone, no external deps) ────
    @staticmethod
    def _vectorize(texts):
        import re, math
        rows = []
        for text in texts:
            t = str(text)
            n = max(len(t), 1)

            # entropy
            freq = {}
            for ch in t:
                freq[ch] = freq.get(ch, 0) + 1
            entropy = -sum((c/n)*math.log2(c/n) for c in freq.values() if c)

            rows.append([
                n,
                entropy,
                len(re.findall(r"[!@#$%^&*()\[\]{};:'\",<>?/\\|`~=+\-]", t)) / n,
                len(re.findall(r"%[0-9a-fA-F]{2}", t)),
                len(re.findall(r"&#?\w+;", t)),
                t.count("../"),
                int(bool(re.search(r"\b(select|union|exec|drop)\b", t, re.I))),
                int(bool(re.search(r"(<script|onerror|javascript:)", t, re.I))),
                int(bool(re.search(r"[;|`]", t))),
                int(bool(re.search(r"\$\{jndi:", t, re.I))),
            ])
        return np.array(rows, dtype=np.float32)

    # ── public API ───────────────────────────────────────────
    def fit(self, normal_texts: list):
        """تدريب على normal traffic بس."""
        X = self._vectorize(normal_texts)
        with self._lock:
            self._model.fit(X)
            self._fitted = True
        self.save()
        logger.info(f"[Anomaly] fitted on {len(normal_texts):,} normal samples")

    def predict(self, text: str) -> dict:
        """
        Returns:
            is_anomaly  : bool
            anomaly_score: float (-1 worst … 0 neutral … +0.5 normal)
            confidence  : float 0-1
        """
        if not self._fitted:
            return {"is_anomaly": False, "anomaly_score": 0.0, "confidence": 0.0}
        try:
            X = self._vectorize([text])
            with self._lock:
                score = float(self._model.decision_function(X)[0])
                pred  = int(self._model.predict(X)[0])   # -1 anomaly, 1 normal

            is_anomaly = pred == -1
            # normalise score to 0-1 confidence
            confidence = float(np.clip(abs(score) * 2, 0, 1))
            return {
                "is_anomaly":    is_anomaly,
                "anomaly_score": round(score, 4),
                "confidence":    round(confidence, 3),
            }
        except Exception as e:
            logger.error(f"[Anomaly] predict error: {e}")
            return {"is_anomaly": False, "anomaly_score": 0.0, "confidence": 0.0}


# ── singleton ─────────────────────────────────────────────────
_detector = None
_det_lock  = threading.Lock()

def get_anomaly_detector() -> AnomalyDetector:
    global _detector
    if _detector is None:
        with _det_lock:
            if _detector is None:
                _detector = AnomalyDetector()
    return _detector
