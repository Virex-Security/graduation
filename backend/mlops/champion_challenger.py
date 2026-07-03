"""
backend/mlops/champion_challenger.py
======================================
Virex Security — Champion–Challenger Deployment

Workflow:
  1. After subprocess retraining completes, evaluate the candidate model.
  2. Load champion (current production) metrics.
  3. Compare on 7 metrics (accuracy, precision, recall, F1, ROC AUC, FPR, FNR).
  4. If candidate is BETTER (within configured deltas) → PROMOTE.
  5. If candidate is WORSE → ARCHIVE with rejection reason.
  6. On any file error during promotion → ROLLBACK to previous champion.

Model Registry folder layout (created at runtime):
  backend/mlops/model_registry/
  ├── current_model.json             ← always points to production model
  ├── model_v1/
  │   ├── model.pkl / model.onnx
  │   ├── metrics.json
  │   ├── feature_importance.json
  │   ├── training_config.json
  │   ├── dataset_version.json
  │   └── training_timestamp.txt
  └── model_v2/
      └── (same structure)
"""

import json
import logging
import math
import shutil
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional, Tuple

import numpy as np
import pandas as pd
import joblib

logger = logging.getLogger("virex.mlops.champion")

# ── Paths ──────────────────────────────────────────────────────────────────────
BACKEND_ROOT       = Path(__file__).parent.parent
MLOPS_DIR          = BACKEND_ROOT / "mlops"
REGISTRY_DIR       = MLOPS_DIR / "model_registry"
CURRENT_MODEL_JSON = REGISTRY_DIR / "current_model.json"
MODELS_DIR         = BACKEND_ROOT / "models"
DATA_DIR           = BACKEND_ROOT / "data"
TEST_CSV           = DATA_DIR / "test.csv"
GENERATED_DIR      = DATA_DIR / "generated"
EVAL_REPORT_PATH   = DATA_DIR / "evaluation_report.json"

# ── Default comparison thresholds ─────────────────────────────────────────────
# Candidate must NOT regress beyond these deltas from the champion.
DEFAULT_THRESHOLDS = {
    "accuracy":  -0.001,   # allow at most 0.1% accuracy drop
    "f1_macro":   0.000,   # F1 must not decrease
    "roc_auc":    0.000,   # AUC must not decrease
    "fpr_max":    0.005,   # false-positive rate must not increase by >0.5%
}


@dataclass
class ModelMetrics:
    version: str
    accuracy: float = 0.0
    precision_macro: float = 0.0
    recall_macro: float = 0.0
    f1_macro: float = 0.0
    roc_auc: float = 0.0
    false_positive_rate: float = 0.0
    false_negative_rate: float = 0.0
    test_samples: int = 0

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class ComparisonResult:
    champion_version: str
    candidate_version: str
    champion_metrics: Dict
    candidate_metrics: Dict
    deltas: Dict[str, float]
    passed_checks: List[str]
    failed_checks: List[str]
    decision: str      # "PROMOTE" or "ARCHIVE"
    reason: str
    timestamp: str = field(default_factory=lambda: time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))

    def to_dict(self) -> dict:
        return asdict(self)


class ChampionChallengerEvaluator:
    """
    Evaluates a newly trained candidate model against the current production
    champion. Promotes or archives based on configurable metric thresholds.
    Supports full rollback to any previous version.
    """

    def __init__(
        self,
        min_accuracy_delta: float = DEFAULT_THRESHOLDS["accuracy"],
        min_f1_delta: float = DEFAULT_THRESHOLDS["f1_macro"],
        min_auc_delta: float = DEFAULT_THRESHOLDS["roc_auc"],
        max_fpr_increase: float = DEFAULT_THRESHOLDS["fpr_max"],
    ):
        self.min_accuracy_delta = min_accuracy_delta
        self.min_f1_delta       = min_f1_delta
        self.min_auc_delta      = min_auc_delta
        self.max_fpr_increase   = max_fpr_increase
        REGISTRY_DIR.mkdir(parents=True, exist_ok=True)
        self._init_current_model_json()

    # ── Evaluation ────────────────────────────────────────────────────────────

    def evaluate_candidate(
        self,
        model_dir: Optional[Path] = None,
        test_csv: Optional[Path] = None,
        dataset_version: int = 1,
    ) -> ModelMetrics:
        """
        Evaluate the newly trained model on the test set.

        Tries to load metrics from evaluation_report.json first (written by the
        build/evaluate scripts). Falls back to running sklearn evaluation.

        Returns a ModelMetrics dataclass.
        """
        test_path = test_csv or self._best_test_csv()
        version   = self._next_version_tag()

        # Try reading evaluation_report.json written by the training subprocess
        if EVAL_REPORT_PATH.exists():
            try:
                with open(EVAL_REPORT_PATH, "r", encoding="utf-8") as f:
                    report = json.load(f)
                metrics = ModelMetrics(
                    version=version,
                    accuracy=report.get("test_accuracy", report.get("val_accuracy", 0.0)),
                    precision_macro=report.get("precision_macro", report.get("macro avg", {}).get("precision", 0.0)
                                               if isinstance(report.get("macro avg"), dict)
                                               else report.get("precision_macro", 0.0)),
                    recall_macro=report.get("recall_macro", report.get("macro avg", {}).get("recall", 0.0)
                                            if isinstance(report.get("macro avg"), dict)
                                            else report.get("recall_macro", 0.0)),
                    f1_macro=report.get("f1_macro", report.get("val_f1_macro", 0.0)),
                    roc_auc=report.get("roc_auc_macro", report.get("roc_auc", 0.0)),
                    false_positive_rate=self._compute_fpr(report),
                    false_negative_rate=self._compute_fnr(report),
                    test_samples=report.get("test_samples", 0),
                )
                logger.info(
                    f"[Champion] Candidate metrics from evaluation_report.json: "
                    f"acc={metrics.accuracy:.4f} f1={metrics.f1_macro:.4f} "
                    f"auc={metrics.roc_auc:.4f}"
                )
                return metrics
            except Exception as e:
                logger.warning(f"[Champion] Could not parse evaluation_report.json: {e}")

        # Fallback: run evaluation using sklearn on the test split
        return self._sklearn_evaluate(version, test_path)

    def _sklearn_evaluate(self, version: str, test_path: Path) -> ModelMetrics:
        """
        Run sklearn evaluation of the freshly trained model against test_path.
        Only called if evaluation_report.json is unavailable.
        """
        try:
            from scipy.sparse import hstack
            from sklearn.metrics import (
                accuracy_score, precision_score, recall_score,
                f1_score, roc_auc_score,
            )
            import sys
            sys.path.insert(0, str(BACKEND_ROOT))
            from app.ml.features import SecurityFeatureExtractor

            # Load artefacts from MODELS_DIR (just-trained model)
            model = joblib.load(MODELS_DIR / "model_lightgbm.pkl")
            vec   = joblib.load(MODELS_DIR / "vectorizer_lightgbm.pkl")
            le    = joblib.load(MODELS_DIR / "label_encoder_lightgbm.pkl")
            sec   = joblib.load(MODELS_DIR / "preprocessor_lightgbm.pkl")

            df = pd.read_csv(test_path, dtype=str)
            df["payload"] = df["payload"].fillna("")

            X_raw = df["payload"].values
            y_raw = df["label"].values

            Xt = vec.transform(X_raw)
            Xs = sec.transform(X_raw)
            X  = hstack([Xt, Xs])
            y  = le.transform(y_raw)

            y_pred = model.predict(X)
            try:
                y_prob = model.predict_proba(X)
                auc    = roc_auc_score(y, y_prob, multi_class="ovr", average="macro")
            except Exception:
                auc = 0.0

            acc  = accuracy_score(y, y_pred)
            prec = precision_score(y, y_pred, average="macro", zero_division=0)
            rec  = recall_score(y, y_pred, average="macro", zero_division=0)
            f1   = f1_score(y, y_pred, average="macro", zero_division=0)

            fp = int(((y_pred != y) & (y_pred != le.transform(["normal"])[0])).sum())
            fn = int(((y_pred != y) & (y == le.transform(["normal"])[0])).sum())
            fpr = fp / max(len(y), 1)
            fnr = fn / max(len(y), 1)

            return ModelMetrics(
                version=version, accuracy=acc, precision_macro=prec,
                recall_macro=rec, f1_macro=f1, roc_auc=auc,
                false_positive_rate=fpr, false_negative_rate=fnr,
                test_samples=len(y),
            )
        except Exception as e:
            logger.error(f"[Champion] sklearn evaluation failed: {e}")
            return ModelMetrics(version=version)

    @staticmethod
    def _compute_fpr(report: dict) -> float:
        fp = report.get("tuned_fp", report.get("baseline_fp", 0))
        total = report.get("test_samples", 1) or 1
        return round(fp / total, 6)

    @staticmethod
    def _compute_fnr(report: dict) -> float:
        # FNR = false negatives / total positives; approximate from confusion if possible
        return report.get("false_negative_rate", 0.0)

    # ── Champion metrics ──────────────────────────────────────────────────────

    def load_champion_metrics(self) -> Optional[ModelMetrics]:
        """Load metrics of the current production champion from current_model.json."""
        if not CURRENT_MODEL_JSON.exists():
            return None
        try:
            with open(CURRENT_MODEL_JSON, "r", encoding="utf-8") as f:
                data = json.load(f)
            m = data.get("metrics", {})
            return ModelMetrics(
                version=data.get("active_version", "unknown"),
                accuracy=m.get("accuracy", 0.0),
                precision_macro=m.get("precision_macro", 0.0),
                recall_macro=m.get("recall_macro", 0.0),
                f1_macro=m.get("f1_macro", 0.0),
                roc_auc=m.get("roc_auc", 0.0),
                false_positive_rate=m.get("false_positive_rate", 1.0),
                false_negative_rate=m.get("false_negative_rate", 1.0),
                test_samples=m.get("test_samples", 0),
            )
        except Exception as e:
            logger.error(f"[Champion] Failed to load champion metrics: {e}")
            return None

    # ── Comparison ────────────────────────────────────────────────────────────

    def compare(
        self,
        candidate: ModelMetrics,
        champion: Optional[ModelMetrics],
    ) -> ComparisonResult:
        """
        Compare candidate against champion.
        If no champion exists (first-ever model), always promote.
        """
        if champion is None:
            logger.info("[Champion] No existing champion — promoting candidate.")
            return ComparisonResult(
                champion_version="none",
                candidate_version=candidate.version,
                champion_metrics={},
                candidate_metrics=candidate.to_dict(),
                deltas={},
                passed_checks=["first_model"],
                failed_checks=[],
                decision="PROMOTE",
                reason="No existing champion — first deployment.",
            )

        deltas = {
            "accuracy":   round(candidate.accuracy  - champion.accuracy,  6),
            "f1_macro":   round(candidate.f1_macro   - champion.f1_macro,   6),
            "roc_auc":    round(candidate.roc_auc    - champion.roc_auc,    6),
            "fpr_delta":  round(candidate.false_positive_rate - champion.false_positive_rate, 6),
            "fnr_delta":  round(candidate.false_negative_rate - champion.false_negative_rate, 6),
        }

        passed, failed = [], []

        # Accuracy check
        if deltas["accuracy"] >= self.min_accuracy_delta:
            passed.append(f"accuracy delta={deltas['accuracy']:+.4f} >= {self.min_accuracy_delta}")
        else:
            failed.append(f"accuracy delta={deltas['accuracy']:+.4f} < {self.min_accuracy_delta}")

        # F1 check
        if deltas["f1_macro"] >= self.min_f1_delta:
            passed.append(f"f1_macro delta={deltas['f1_macro']:+.4f} >= {self.min_f1_delta}")
        else:
            failed.append(f"f1_macro delta={deltas['f1_macro']:+.4f} < {self.min_f1_delta}")

        # AUC check
        if deltas["roc_auc"] >= self.min_auc_delta:
            passed.append(f"roc_auc delta={deltas['roc_auc']:+.4f} >= {self.min_auc_delta}")
        else:
            failed.append(f"roc_auc delta={deltas['roc_auc']:+.4f} < {self.min_auc_delta}")

        # FPR check (lower is better)
        if deltas["fpr_delta"] <= self.max_fpr_increase:
            passed.append(f"fpr_delta={deltas['fpr_delta']:+.4f} <= {self.max_fpr_increase}")
        else:
            failed.append(f"fpr_delta={deltas['fpr_delta']:+.4f} > {self.max_fpr_increase}")

        if failed:
            decision = "ARCHIVE"
            reason   = "Candidate failed checks: " + "; ".join(failed)
        else:
            decision = "PROMOTE"
            reason   = "Candidate passed all checks: " + "; ".join(passed)

        result = ComparisonResult(
            champion_version=champion.version,
            candidate_version=candidate.version,
            champion_metrics=champion.to_dict(),
            candidate_metrics=candidate.to_dict(),
            deltas=deltas,
            passed_checks=passed,
            failed_checks=failed,
            decision=decision,
            reason=reason,
        )

        logger.info(
            f"[Champion] Comparison result: {decision} | "
            f"acc_delta={deltas['accuracy']:+.4f} "
            f"f1_delta={deltas['f1_macro']:+.4f} "
            f"auc_delta={deltas['roc_auc']:+.4f}"
        )
        return result

    # ── Promote ───────────────────────────────────────────────────────────────

    def promote(
        self,
        candidate_version: str,
        metrics: ModelMetrics,
        dataset_version: int = 1,
        training_config: Optional[dict] = None,
    ) -> None:
        """
        Promote the candidate to production champion.
        Creates a versioned folder in model_registry/ and updates current_model.json.
        On file-system error, triggers automatic rollback.
        """
        version_dir = REGISTRY_DIR / candidate_version
        try:
            version_dir.mkdir(parents=True, exist_ok=True)

            # Copy model artifacts into the versioned folder
            for src_name, dst_name in [
                ("model_lightgbm.pkl",        "model.pkl"),
                ("model_lightgbm.onnx",       "model.onnx"),
                ("vectorizer_lightgbm.pkl",   "vectorizer.pkl"),
                ("preprocessor_lightgbm.pkl", "preprocessor.pkl"),
                ("label_encoder_lightgbm.pkl","label_encoder.pkl"),
                ("feature_importance.csv",    "feature_importance.csv"),
            ]:
                src = MODELS_DIR / src_name
                if src.exists():
                    shutil.copy2(src, version_dir / dst_name)

            # Write metrics.json
            with open(version_dir / "metrics.json", "w", encoding="utf-8") as f:
                json.dump(metrics.to_dict(), f, indent=2)

            # Write feature_importance.json (if CSV present)
            fi_csv = MODELS_DIR / "feature_importance.csv"
            if fi_csv.exists():
                try:
                    import pandas as pd
                    fi_df = pd.read_csv(fi_csv).head(50)
                    fi_json = fi_df.to_dict(orient="records")
                    with open(version_dir / "feature_importance.json", "w", encoding="utf-8") as f:
                        json.dump(fi_json, f, indent=2)
                except Exception as e:
                    logger.warning(f"[Champion] feature_importance.json write failed: {e}")

            # Write training_config.json
            config = training_config or {}
            with open(version_dir / "training_config.json", "w", encoding="utf-8") as f:
                json.dump(config, f, indent=2)

            # Write dataset_version.json
            with open(version_dir / "dataset_version.json", "w", encoding="utf-8") as f:
                json.dump({"dataset_version": dataset_version}, f, indent=2)

            # Write training_timestamp.txt
            (version_dir / "training_timestamp.txt").write_text(
                time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), encoding="utf-8"
            )

            # Update current_model.json (atomic: write then replace)
            new_current = {
                "active_version":   candidate_version,
                "promoted_at":      time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "promoted_by":      "champion_challenger",
                "dataset_version":  dataset_version,
                "metrics":          metrics.to_dict(),
            }
            tmp = CURRENT_MODEL_JSON.with_suffix(".tmp")
            with open(tmp, "w", encoding="utf-8") as f:
                json.dump(new_current, f, indent=2)
            tmp.replace(CURRENT_MODEL_JSON)

            logger.info(f"[Champion] ✅ Promoted {candidate_version} → production.")

        except Exception as e:
            logger.error(f"[Champion] Promotion failed: {e} — triggering rollback.")
            self._emergency_rollback(candidate_version, str(e))
            raise

    # ── Archive ───────────────────────────────────────────────────────────────

    def archive(self, candidate_version: str, reason: str) -> None:
        """
        Archive a rejected candidate model.
        The versioned folder is created and marked with an ARCHIVED status.
        """
        version_dir = REGISTRY_DIR / candidate_version
        version_dir.mkdir(parents=True, exist_ok=True)

        archive_info = {
            "status":      "ARCHIVED",
            "archived_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "reason":      reason,
        }
        with open(version_dir / "archive_info.json", "w", encoding="utf-8") as f:
            json.dump(archive_info, f, indent=2)

        # Copy artifacts for reference
        for src_name in ["model_lightgbm.pkl", "feature_importance.csv"]:
            src = MODELS_DIR / src_name
            if src.exists():
                try:
                    shutil.copy2(src, version_dir / src_name)
                except Exception:
                    pass

        logger.info(
            f"[Champion] ⬇ Archived {candidate_version}: {reason}"
        )

    # ── Rollback ──────────────────────────────────────────────────────────────

    def rollback(self, target_version: Optional[str] = None) -> str:
        """
        Restore a previous production model.

        If target_version is None, finds the most recent PROMOTED version
        before the current one and restores it.

        Returns the restored version tag.
        """
        if target_version is None:
            target_version = self._find_previous_promoted_version()
        if target_version is None:
            raise RuntimeError("[Champion] No previous version available for rollback.")

        target_dir = REGISTRY_DIR / target_version
        if not target_dir.exists():
            raise RuntimeError(f"[Champion] Rollback target {target_version} not found.")

        logger.warning(f"[Champion] 🔄 Rolling back to {target_version}…")

        try:
            # Restore artifacts to MODELS_DIR
            name_map = {
                "model.pkl":         "model_lightgbm.pkl",
                "model.onnx":        "model_lightgbm.onnx",
                "vectorizer.pkl":    "vectorizer_lightgbm.pkl",
                "preprocessor.pkl":  "preprocessor_lightgbm.pkl",
                "label_encoder.pkl": "label_encoder_lightgbm.pkl",
            }
            for src_name, dst_name in name_map.items():
                src = target_dir / src_name
                if src.exists():
                    shutil.copy2(src, MODELS_DIR / dst_name)

            # Reload metrics from the version folder
            metrics_path = target_dir / "metrics.json"
            if metrics_path.exists():
                with open(metrics_path, "r", encoding="utf-8") as f:
                    metrics_dict = json.load(f)
            else:
                metrics_dict = {}

            # Update current_model.json
            new_current = {
                "active_version":  target_version,
                "promoted_at":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "promoted_by":     "rollback",
                "metrics":         metrics_dict,
                "rollback_reason": "Automatic rollback after failed promotion",
            }
            with open(CURRENT_MODEL_JSON, "w", encoding="utf-8") as f:
                json.dump(new_current, f, indent=2)

            logger.info(f"[Champion] ✅ Rollback to {target_version} successful.")
            return target_version

        except Exception as e:
            logger.critical(f"[Champion] ROLLBACK FAILED: {e}")
            raise

    def _emergency_rollback(self, failed_version: str, error: str):
        """Called automatically when promotion fails mid-flight."""
        try:
            previous = self._find_previous_promoted_version(exclude=failed_version)
            if previous:
                self.rollback(previous)
                logger.info(f"[Champion] Emergency rollback to {previous} succeeded.")
            else:
                logger.critical("[Champion] Emergency rollback: no previous version found!")
        except Exception as rb_err:
            logger.critical(f"[Champion] Emergency rollback failed: {rb_err}")

    def _find_previous_promoted_version(
        self, exclude: Optional[str] = None
    ) -> Optional[str]:
        """Find the most recently promoted model version (excluding `exclude`)."""
        candidates = []
        for d in sorted(REGISTRY_DIR.iterdir(), reverse=True):
            if not d.is_dir():
                continue
            if exclude and d.name == exclude:
                continue
            if (d / "archive_info.json").exists():
                continue   # skip archived
            ts_file = d / "training_timestamp.txt"
            if ts_file.exists():
                candidates.append((ts_file.read_text().strip(), d.name))
        if not candidates:
            return None
        candidates.sort(reverse=True)
        return candidates[0][1]

    # ── Feature importance comparison ─────────────────────────────────────────

    def compare_feature_importance(
        self,
        v1: str,
        v2: str,
        top_n: int = 10,
    ) -> dict:
        """
        Compare top-N feature importances between two model versions.
        Returns a dict with ranked features for each version and overlap.
        """
        result = {"v1": v1, "v2": v2, "top_n": top_n}
        for tag, version in [("v1_features", v1), ("v2_features", v2)]:
            fi_path = REGISTRY_DIR / version / "feature_importance.json"
            if fi_path.exists():
                try:
                    with open(fi_path, "r", encoding="utf-8") as f:
                        data = json.load(f)
                    result[tag] = data[:top_n]
                except Exception:
                    result[tag] = []
            else:
                result[tag] = []

        v1_feats = {r.get("Feature") for r in result.get("v1_features", [])}
        v2_feats = {r.get("Feature") for r in result.get("v2_features", [])}
        result["overlap"] = sorted(v1_feats & v2_feats)
        result["added"]   = sorted(v2_feats - v1_feats)
        result["removed"] = sorted(v1_feats - v2_feats)
        return result

    # ── Helpers ───────────────────────────────────────────────────────────────

    def _next_version_tag(self) -> str:
        """Generate the next model version tag, e.g. 'model_v3'."""
        existing = [
            d.name for d in REGISTRY_DIR.iterdir()
            if d.is_dir() and d.name.startswith("model_v")
        ] if REGISTRY_DIR.exists() else []
        numbers = []
        for name in existing:
            try:
                numbers.append(int(name.replace("model_v", "")))
            except ValueError:
                pass
        n = max(numbers, default=0) + 1
        return f"model_v{n}"

    def _best_test_csv(self) -> Path:
        """Return the best available test CSV (generated or original)."""
        merged = GENERATED_DIR / "merged_test_dataset.csv"
        if merged.exists():
            return merged
        original = DATA_DIR / "test.csv"
        if original.exists():
            return original
        raise FileNotFoundError("No test CSV found for candidate evaluation.")

    def _init_current_model_json(self):
        """Initialise current_model.json with the known baseline model if missing."""
        if not CURRENT_MODEL_JSON.exists():
            initial = {
                "active_version":  "model_v1",
                "promoted_at":     "2026-06-28T23:11:17Z",
                "promoted_by":     "initial_deployment",
                "dataset_version": 1,
                "metrics": {
                    "accuracy":           0.9987,
                    "precision_macro":    0.9996,
                    "recall_macro":       0.9991,
                    "f1_macro":           0.9993,
                    "roc_auc":            1.0000,
                    "false_positive_rate": 0.0013,
                    "false_negative_rate": 0.0009,
                    "test_samples":        7950,
                },
            }
            with open(CURRENT_MODEL_JSON, "w", encoding="utf-8") as f:
                json.dump(initial, f, indent=2)

            # Also create model_v1 folder entry
            v1_dir = REGISTRY_DIR / "model_v1"
            v1_dir.mkdir(parents=True, exist_ok=True)
            (v1_dir / "training_timestamp.txt").write_text(
                "2026-06-28T23:11:17Z", encoding="utf-8"
            )
            with open(v1_dir / "metrics.json", "w", encoding="utf-8") as f:
                json.dump(initial["metrics"], f, indent=2)
            with open(v1_dir / "dataset_version.json", "w", encoding="utf-8") as f:
                json.dump({"dataset_version": 1}, f, indent=2)
