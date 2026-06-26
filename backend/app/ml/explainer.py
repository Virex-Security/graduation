"""
Virex Security — Prediction Explainer
=======================================
يشرح ليه المودل قرر يبلوك request معين
مفيد جداً لمراجعة false positives
"""

import logging
import threading
import numpy as np
from pathlib import Path

logger = logging.getLogger(__name__)


class PredictionExplainer:
    """
    يستخدم الـ security features لشرح القرار بدون
    الحاجة لـ SHAP على الـ ensemble الكامل (بطيء).
    """

    # feature names بنفس ترتيب SecurityFeatureExtractor
    FEATURE_NAMES = [
        "length", "length_norm",
        "entropy", "entropy_norm",
        "special_char_ratio",
        "sql_keyword_count", "has_union_select", "sql_comment_count",
        "html_tag_count", "js_event_count",
        "shell_meta_count", "shell_cmd_count",
        "has_path_traversal", "dotdot_slash_count", "dotdot_back_count",
        "url_enc_count", "url_enc_ratio", "has_html_entities",
        "has_jndi", "has_ssrf_host", "has_xxe", "has_ssti",
        "ampersand_count", "question_mark_count", "equals_count",
        "single_quote_imbalance", "double_quote_imbalance",
        "max_nesting_depth", "has_null_byte",
    ]

    # وصف بالعربي/الإنجليزي لكل feature
    FEATURE_DESCRIPTIONS = {
        "sql_keyword_count":      "SQL keywords (SELECT, UNION, DROP…)",
        "has_union_select":       "UNION SELECT pattern",
        "sql_comment_count":      "SQL comment sequences (--, #, /*…*/)",
        "html_tag_count":         "HTML tags (<script>, <img>, <iframe>…)",
        "js_event_count":         "JavaScript event handlers (onerror, onload…)",
        "shell_meta_count":       "Shell metacharacters (;, |, `, &)",
        "shell_cmd_count":        "Shell commands (cat, wget, nc, bash…)",
        "has_path_traversal":     "Path traversal patterns (../)",
        "url_enc_ratio":          "High URL-encoding density",
        "has_html_entities":      "HTML entity encoding",
        "has_jndi":               "JNDI lookup (Log4Shell pattern)",
        "has_ssrf_host":          "Internal host reference (SSRF)",
        "has_xxe":                "XML External Entity declaration",
        "has_ssti":               "Server-Side Template Injection markers",
        "single_quote_imbalance": "Unbalanced single quotes",
        "entropy":                "High character entropy (obfuscation)",
        "has_null_byte":          "Null byte injection",
    }

    ATTACK_MESSAGES = {
        "sql_injection":     "SQL injection — the request contains SQL syntax designed to manipulate database queries.",
        "xss":               "Cross-Site Scripting — the request contains JavaScript or HTML designed to execute in a browser.",
        "command_injection": "Command injection — the request contains shell metacharacters or OS commands.",
        "path_traversal":    "Path traversal — the request attempts to access files outside the web root.",
        "ssrf":              "Server-Side Request Forgery — the request references internal hosts or cloud metadata endpoints.",
        "xxe":               "XML External Entity — the payload declares external XML entities to read local files.",
        "ssti":              "Server-Side Template Injection — the payload contains template expression syntax.",
        "log4shell":         "Log4Shell (CVE-2021-44228) — JNDI lookup detected in user-supplied input.",
        "brute_force":       "Brute force / credential stuffing — repeated authentication attempts with common credentials.",
        "normal":            "No attack detected — request appears legitimate.",
        "attack":            "Generic attack pattern detected.",
    }

    def __init__(self, sec_feature_extractor=None):
        self._extractor = sec_feature_extractor
        self._lock      = threading.Lock()

    def explain(self, text: str, attack_type: str, risk_score: float) -> dict:
        """
        Returns a structured explanation of why the request was flagged.
        """
        try:
            return self._build_explanation(text, attack_type, risk_score)
        except Exception as e:
            logger.error(f"[Explainer] error: {e}")
            return self._fallback(attack_type, risk_score)

    def _build_explanation(self, text: str, attack_type: str, risk_score: float) -> dict:
        from app.ml.features import SecurityFeatureExtractor
        extractor = self._extractor or SecurityFeatureExtractor()
        feat_vec  = extractor.transform([text]).toarray()[0]

        # pick top contributing features
        top_features = []
        for name, val in zip(self.FEATURE_NAMES, feat_vec):
            if val <= 0:
                continue
            desc = self.FEATURE_DESCRIPTIONS.get(name, name.replace("_", " "))
            top_features.append({
                "feature":      name,
                "description":  desc,
                "value":        round(float(val), 3),
                "contribution": round(float(val / max(sum(feat_vec), 1)), 3),
                "direction":    "attack",
            })

        top_features.sort(key=lambda x: x["contribution"], reverse=True)
        top_features = top_features[:6]

        message = self.ATTACK_MESSAGES.get(
            attack_type,
            f"Potential {attack_type.replace('_', ' ')} attack detected.",
        )

        return {
            "attack_type":   attack_type,
            "risk_score":    round(risk_score * 100, 1),
            "top_features":  top_features,
            "explanation":   message,
            "feature_count": int(sum(1 for v in feat_vec if v > 0)),
        }

    def _fallback(self, attack_type: str, risk_score: float) -> dict:
        return {
            "attack_type":  attack_type,
            "risk_score":   round(risk_score * 100, 1),
            "top_features": [],
            "explanation":  self.ATTACK_MESSAGES.get(attack_type, "Attack detected."),
            "feature_count": 0,
        }


# ── singleton ─────────────────────────────────────────────────
_explainer = None
_exp_lock   = threading.Lock()

def get_explainer() -> PredictionExplainer:
    global _explainer
    if _explainer is None:
        with _exp_lock:
            if _explainer is None:
                _explainer = PredictionExplainer()
    return _explainer
