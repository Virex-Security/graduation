"""
Simple ML Inference using Pipeline
===================================
Loads model_pipeline.pkl and makes predictions
"""
import joblib
import logging
from pathlib import Path
from dataclasses import dataclass

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent.parent
DATA_DIR = PROJECT_ROOT / "data"
PIPELINE_PATH = DATA_DIR / "model_pipeline.pkl"

# Fallback to old model if pipeline doesn't exist
MODEL_PATH = DATA_DIR / "model.pkl"
VECTORIZER_PATH = DATA_DIR / "vectorizer.pkl"

_pipeline = None
_model = None
_vectorizer = None
MODEL_LOADED = False


@dataclass
class MLDecision:
    """ML prediction result"""
    risk_score: float
    action: str  # "allow", "monitor", "block"
    attack_type: str
    confidence: float = 0.0
    severity: str = "none"
    
    def __str__(self):
        return f"MLDecision(risk={self.risk_score:.2f}, action={self.action}, type={self.attack_type})"


def _load_model():
    """Load ML model (pipeline or separate model+vectorizer)"""
    global _pipeline, _model, _vectorizer, MODEL_LOADED
    
    # Try loading pipeline first
    if PIPELINE_PATH.exists():
        try:
            _pipeline = joblib.load(PIPELINE_PATH)
            MODEL_LOADED = True
            logger.info(f"[ML] Pipeline loaded from {PIPELINE_PATH}")
            return True
        except Exception as e:
            logger.error(f"[ML] Failed to load pipeline: {e}")
    
    # Fallback to old model
    if MODEL_PATH.exists() and VECTORIZER_PATH.exists():
        try:
            _model = joblib.load(MODEL_PATH)
            _vectorizer = joblib.load(VECTORIZER_PATH)
            MODEL_LOADED = True
            logger.info(f"[ML] Model+Vectorizer loaded (legacy mode)")
            return True
        except Exception as e:
            logger.error(f"[ML] Failed to load model: {e}")
    
    logger.warning("[ML] No model found. Run: python train_model.py")
    return False


def ml_analyze(text: str) -> MLDecision:
    """
    Analyze text for security threats using ML
    
    Args:
        text: Input text to analyze (HTTP request, parameter, etc.)
    
    Returns:
        MLDecision with risk score and recommended action
    """
    global _pipeline, _model, _vectorizer, MODEL_LOADED
    
    # Load model on first use
    if not MODEL_LOADED:
        _load_model()
    
    # If still not loaded, return safe default
    if not MODEL_LOADED:
        return MLDecision(
            risk_score=0.0,
            action="allow",
            attack_type="unknown",
            confidence=0.0,
            severity="none"
        )
    
    try:
        text_str = str(text)
        
        # Predict using pipeline or model+vectorizer
        if _pipeline:
            prediction = _pipeline.predict([text_str])[0]
            probabilities = _pipeline.predict_proba([text_str])[0]
        else:
            X = _vectorizer.transform([text_str])
            prediction = _model.predict(X)[0]
            probabilities = _model.predict_proba(X)[0]
        
        # Get risk score (probability of attack class)
        if prediction == 1:  # Attack
            risk_score = float(probabilities[1])
        else:  # Normal
            risk_score = 0.0
        
        # Determine action based on thresholds
        if risk_score >= 0.85:
            action = "block"
            severity = "high"
        elif risk_score >= 0.60:
            action = "monitor"
            severity = "medium"
        else:
            action = "allow"
            severity = "low"
        
        # Classify attack type (simple heuristic)
        attack_type = _classify_attack_type(text_str) if prediction == 1 else "normal"
        
        return MLDecision(
            risk_score=risk_score,
            action=action,
            attack_type=attack_type,
            confidence=risk_score,
            severity=severity
        )
        
    except Exception as e:
        logger.error(f"[ML] Prediction error: {e}")
        return MLDecision(
            risk_score=0.0,
            action="allow",
            attack_type="error",
            confidence=0.0,
            severity="none"
        )


def _classify_attack_type(text: str) -> str:
    """Simple rule-based attack classification"""
    text_lower = text.lower()
    
    # SQL Injection
    if any(kw in text_lower for kw in ['union', 'select', 'drop', 'insert', 'delete', 'update', '--', 'or 1=1', 'sleep(']):
        return "sql_injection"
    
    # XSS
    if any(kw in text_lower for kw in ['<script', 'onerror', 'onload', 'javascript:', 'alert(', 'document.cookie']):
        return "xss"
    
    # Command Injection
    if any(kw in text_lower for kw in ['|', ';', '`', '$(', 'bash', 'sh', 'wget', 'curl', 'nc ']):
        return "command_injection"
    
    # Path Traversal
    if any(kw in text_lower for kw in ['../', '..\\', '/etc/passwd', 'windows/system32']):
        return "path_traversal"
    
    # SSRF
    if any(kw in text_lower for kw in ['169.254.169.254', 'localhost', '127.0.0.1', 'file://']):
        return "ssrf"
    
    return "unknown_attack"


def ml_detect(text: str) -> tuple:
    """
    Legacy function for backward compatibility
    Returns: (is_attack: bool, attack_type: str, confidence: float)
    """
    result = ml_analyze(text)
    is_attack = result.action in ["monitor", "block"]
    return (is_attack, result.attack_type, result.confidence)


def get_ml_stats() -> dict:
    """Get ML model statistics"""
    return {
        "model_loaded": MODEL_LOADED,
        "model_type": "pipeline" if _pipeline else "legacy",
        "model_path": str(PIPELINE_PATH if _pipeline else MODEL_PATH),
        "thresholds": {
            "block": 0.85,
            "monitor": 0.60
        }
    }


# Load model on module import
_load_model()
