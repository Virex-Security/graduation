import time
import threading
import joblib
import pandas as pd
from pathlib import Path
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split
import logging

logger = logging.getLogger(__name__)

# Setup paths to data directory
PROJECT_ROOT = Path(__file__).parent.parent
DATA_DIR = PROJECT_ROOT / "data"
MODEL_PATH = DATA_DIR / "model.pkl"
VECTORIZER_PATH = DATA_DIR / "vectorizer.pkl"
TRAINING_DATA_PATH = DATA_DIR / "ml_training_data.csv"

# Global model state
_model = None
_vectorizer = None
_model_lock = threading.Lock()
MODEL_LOADED = False
RETRAIN_INTERVAL = 3600  # retrain every 1 hour

def _load_or_train():
    """Load existing model or train from scratch."""
    global _model, _vectorizer, MODEL_LOADED
    try:
        _model      = joblib.load(str(MODEL_PATH))
        _vectorizer = joblib.load(str(VECTORIZER_PATH))
        MODEL_LOADED = True
        print("✅ ML Model loaded from disk")
    except Exception:
        print("⚠️  No model found — training from scratch...")
        _retrain_model()

def _retrain_model():
    """Train/retrain the ML model from ml_training_data.csv."""
    global _model, _vectorizer, MODEL_LOADED
    try:
        data = pd.read_csv(str(TRAINING_DATA_PATH))
        X_train, X_test, y_train, y_test = train_test_split(
            data['text'], data['label'],
            test_size=0.2, random_state=42, stratify=data['label']
        )
        vec = TfidfVectorizer(ngram_range=(1, 2), max_features=5000, lowercase=True)
        X_tr = vec.fit_transform(X_train)
        clf  = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
        clf.fit(X_tr, y_train)

        with _model_lock:
            _model      = clf
            _vectorizer = vec
            MODEL_LOADED = True

        # Ensure data directory exists
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        joblib.dump(clf, str(MODEL_PATH))
        joblib.dump(vec, str(VECTORIZER_PATH))

        from sklearn.metrics import accuracy_score
        acc = accuracy_score(y_test, clf.predict(vec.transform(X_test)))
        print(f"✅ ML Model retrained — Accuracy: {acc*100:.2f}%  Samples: {len(data)}")
    except Exception as e:
        print(f"❌ Retrain failed: {e}")

def _auto_retrain_loop():
    """Background thread: retrain model every RETRAIN_INTERVAL seconds."""
    while True:
        time.sleep(RETRAIN_INTERVAL)
        print("🔄 Auto-retraining ML model...")
        _retrain_model()

# Load model on startup
_load_or_train()

# Start background auto-retrain thread
_retrain_thread = threading.Thread(target=_auto_retrain_loop, daemon=True)
_retrain_thread.start()
print(f"🔄 Auto-retrain scheduled every {RETRAIN_INTERVAL//60} minutes")

def ml_detect(text):
    """Run ML model on text and return (is_attack, raw_prediction).

    The existing code simply returned a boolean, but we now expose the raw
    prediction value so that callers can make additional decisions. A log
    entry is also emitted showing the text snippet and prediction for
    debugging/analytics.
    """
    if not MODEL_LOADED:
        return False, None

    # bypass ML check for trivial strings (avoid false positives on things
    # like passwords or usernames)
    text_str = str(text)
    if len(text_str) <= 3:
        return False, 0
    if len(text_str) <= 20 and text_str.isalnum():
        return False, 0

    try:
        with _model_lock:
            X = _vectorizer.transform([text_str])
            raw = _model.predict(X)[0]
        is_att = raw == 1
        logger.debug(f"[ML DETECT] text='{' '.join(text_str.split()[:8])}' pred={raw}")
        return is_att, raw
    except Exception as e:
        logger.error(f"[ML DETECT] model error: {e}")
        return False, None
