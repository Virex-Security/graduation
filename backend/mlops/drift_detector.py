"""
backend/mlops/drift_detector.py
================================
Virex Security — Drift Detection Module

Monitors incoming traffic distribution against a baseline built from
the training dataset. Supports three drift metrics:

  1. Population Stability Index (PSI)  — industry-standard label drift measure
  2. KL Divergence                     — information-theoretic distribution shift
  3. Feature Distribution Comparison   — z-score on numeric security features

When ANY metric exceeds its configured threshold, writes:
    backend/data/drift_detected.flag

The retrain_scheduler already checks for this flag — no scheduler changes needed.
"""

import json
import logging
import math
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Dict, List, Optional

import numpy as np

logger = logging.getLogger("virex.mlops.drift")

# ── Paths ──────────────────────────────────────────────────────────────────────
BACKEND_ROOT      = Path(__file__).parent.parent
DATA_DIR          = BACKEND_ROOT / "data"
TRAIN_CSV         = DATA_DIR / "train.csv"
ML_FEEDBACK_PATH  = DATA_DIR / "ml_feedback.json"
DRIFT_FLAG_PATH   = DATA_DIR / "drift_detected.flag"
DRIFT_REPORT_PATH = DATA_DIR / "drift_report.json"

# ── Known attack classes ───────────────────────────────────────────────────────
KNOWN_CLASSES = [
    "normal", "sql_injection", "xss", "command_injection",
    "path_traversal", "log4shell", "ssrf", "xxe", "ssti", "brute_force",
]

# ── PSI helpers ───────────────────────────────────────────────────────────────
_PSI_EPSILON = 1e-10   # avoid log(0)


@dataclass
class DriftReport:
    timestamp: str
    window_hours: int
    baseline_total: int
    current_total: int
    psi: float
    kl_divergence: float
    feature_drift_scores: Dict[str, float]
    drift_detected: bool
    metrics_exceeded: List[str]
    baseline_distribution: Dict[str, float] = field(default_factory=dict)
    current_distribution: Dict[str, float] = field(default_factory=dict)
    thresholds: Dict[str, float] = field(default_factory=dict)
    notes: str = ""

    def to_dict(self) -> dict:
        return asdict(self)


class DriftDetector:
    """
    Detects data and concept drift by comparing the distribution of recent
    incoming predictions against the baseline training-set distribution.

    Usage:
        detector = DriftDetector(window_hours=24)
        report   = detector.run_detection()
        if report.drift_detected:
            detector.write_flag(report)
    """

    def __init__(
        self,
        baseline_csv: Optional[Path] = None,
        window_hours: int = 24,
        psi_threshold: float = 0.2,
        kl_threshold: float = 0.5,
        feat_threshold: float = 2.0,
    ):
        self.baseline_csv    = baseline_csv or TRAIN_CSV
        self.window_hours    = window_hours
        self.psi_threshold   = float(psi_threshold)
        self.kl_threshold    = float(kl_threshold)
        self.feat_threshold  = float(feat_threshold)
        self._baseline_dist: Optional[Dict[str, float]] = None

    # ── Baseline ──────────────────────────────────────────────────────────────

    def _build_baseline_distribution(self) -> Dict[str, float]:
        """
        Build the baseline label distribution from the training CSV.
        Falls back to a uniform distribution if the CSV is unavailable.
        """
        if self._baseline_dist is not None:
            return self._baseline_dist

        if not self.baseline_csv.exists():
            logger.warning("[Drift] Training CSV not found — using uniform baseline.")
            n = len(KNOWN_CLASSES)
            self._baseline_dist = {c: 1.0 / n for c in KNOWN_CLASSES}
            return self._baseline_dist

        try:
            import pandas as pd
            df = pd.read_csv(self.baseline_csv, usecols=["label"])
            counts = df["label"].value_counts()
            total  = counts.sum()
            dist   = {cls: counts.get(cls, 0) / total for cls in KNOWN_CLASSES}
        except Exception as e:
            logger.error(f"[Drift] Error reading baseline CSV: {e}")
            n = len(KNOWN_CLASSES)
            dist = {c: 1.0 / n for c in KNOWN_CLASSES}

        self._baseline_dist = dist
        return dist

    # ── Current traffic distribution ──────────────────────────────────────────

    def _get_recent_predictions(self) -> Dict[str, float]:
        """
        Read recent predictions from ml_feedback.json within the time window.
        Returns a normalised label distribution dict.
        """
        if not ML_FEEDBACK_PATH.exists():
            return {}

        cutoff_ts = time.time() - self.window_hours * 3600
        counts: Dict[str, int] = {cls: 0 for cls in KNOWN_CLASSES}
        total = 0

        try:
            with open(ML_FEEDBACK_PATH, "r", encoding="utf-8") as f:
                entries = json.load(f)
        except Exception as e:
            logger.error(f"[Drift] Failed to read ml_feedback.json: {e}")
            return {}

        for entry in entries:
            # Parse timestamp (format: 2026-04-01T22:20:36Z)
            try:
                import datetime as dt
                ts_str  = entry.get("timestamp", "")
                ts_epoch = dt.datetime.strptime(
                    ts_str, "%Y-%m-%dT%H:%M:%SZ"
                ).replace(tzinfo=dt.timezone.utc).timestamp()
            except Exception:
                continue

            if ts_epoch < cutoff_ts:
                continue

            label = entry.get("attack_type", "normal").lower()
            # normalise label names (e.g. "sqli" → "sql_injection")
            label = self._normalise_label(label)
            if label in counts:
                counts[label] += 1
                total += 1

        if total == 0:
            logger.info("[Drift] No recent predictions in window — cannot compare.")
            return {}

        return {cls: counts[cls] / total for cls in KNOWN_CLASSES}

    @staticmethod
    def _normalise_label(label: str) -> str:
        _MAP = {
            "sqli": "sql_injection",
            "sql":  "sql_injection",
            "anomaly": "normal",
            "suspicious": "normal",
            "error": "normal",
            "unknown": "normal",
        }
        return _MAP.get(label, label)

    # ── PSI ───────────────────────────────────────────────────────────────────

    @staticmethod
    def compute_psi(
        baseline: Dict[str, float],
        current: Dict[str, float],
    ) -> float:
        """
        Population Stability Index.
        PSI < 0.1  : no significant change
        PSI < 0.2  : moderate change (monitor)
        PSI >= 0.2 : significant shift (retrain)
        """
        psi = 0.0
        for cls in baseline:
            b = max(baseline.get(cls, 0.0), _PSI_EPSILON)
            c = max(current.get(cls, 0.0), _PSI_EPSILON)
            psi += (c - b) * math.log(c / b)
        return round(psi, 6)

    # ── KL Divergence ─────────────────────────────────────────────────────────

    @staticmethod
    def compute_kl_divergence(
        baseline: Dict[str, float],
        current: Dict[str, float],
    ) -> float:
        """
        KL Divergence D_KL(current || baseline).
        Measures information lost when using baseline to approximate current.
        """
        kl = 0.0
        for cls in baseline:
            p = max(current.get(cls, 0.0), _PSI_EPSILON)
            q = max(baseline.get(cls, 0.0), _PSI_EPSILON)
            kl += p * math.log(p / q)
        return round(kl, 6)

    # ── Feature Distribution ──────────────────────────────────────────────────

    def compare_feature_distributions(
        self,
        baseline_dist: Dict[str, float],
        current_dist: Dict[str, float],
    ) -> Dict[str, float]:
        """
        Compute a per-class z-score: how many std-devs current differs from baseline.
        Uses the baseline proportions as mean and a Poisson-like std estimate.
        """
        scores: Dict[str, float] = {}
        for cls in KNOWN_CLASSES:
            b = baseline_dist.get(cls, 0.0)
            c = current_dist.get(cls, 0.0)
            # std estimate under Poisson: sqrt(p * (1-p))
            std = math.sqrt(max(b * (1 - b), _PSI_EPSILON))
            z   = abs(c - b) / std
            scores[cls] = round(z, 4)
        return scores

    # ── Main entry point ──────────────────────────────────────────────────────

    def run_detection(self) -> DriftReport:
        """
        Run all three drift metrics and return a DriftReport.
        Does NOT write the flag — call write_flag(report) if needed.
        """
        baseline = self._build_baseline_distribution()
        current  = self._get_recent_predictions()

        # Baseline total (approx — read header count if available)
        baseline_total = self._count_baseline_rows()
        current_total  = sum(
            1 for e in self._read_feedback_entries()
            if self._is_recent(e)
        )

        if not current:
            # No data in window — report clean
            report = DriftReport(
                timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                window_hours=self.window_hours,
                baseline_total=baseline_total,
                current_total=0,
                psi=0.0,
                kl_divergence=0.0,
                feature_drift_scores={},
                drift_detected=False,
                metrics_exceeded=[],
                baseline_distribution=baseline,
                current_distribution={},
                thresholds={
                    "psi":  self.psi_threshold,
                    "kl":   self.kl_threshold,
                    "feat": self.feat_threshold,
                },
                notes="Insufficient traffic in detection window.",
            )
            self._save_report(report)
            return report

        psi     = self.compute_psi(baseline, current)
        kl      = self.compute_kl_divergence(baseline, current)
        feat    = self.compare_feature_distributions(baseline, current)
        max_feat_z = max(feat.values(), default=0.0)

        exceeded = []
        if psi >= self.psi_threshold:
            exceeded.append(f"PSI={psi:.4f} >= {self.psi_threshold}")
        if kl >= self.kl_threshold:
            exceeded.append(f"KL={kl:.4f} >= {self.kl_threshold}")
        if max_feat_z >= self.feat_threshold:
            exceeded.append(f"MaxFeatZ={max_feat_z:.4f} >= {self.feat_threshold}")

        drift_detected = len(exceeded) > 0

        report = DriftReport(
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            window_hours=self.window_hours,
            baseline_total=baseline_total,
            current_total=current_total,
            psi=psi,
            kl_divergence=kl,
            feature_drift_scores=feat,
            drift_detected=drift_detected,
            metrics_exceeded=exceeded,
            baseline_distribution=baseline,
            current_distribution=current,
            thresholds={
                "psi":  self.psi_threshold,
                "kl":   self.kl_threshold,
                "feat": self.feat_threshold,
            },
        )

        if drift_detected:
            logger.warning(
                f"[Drift] DRIFT DETECTED — PSI={psi:.4f} KL={kl:.4f} "
                f"MaxFeatZ={max_feat_z:.4f} | exceeded: {exceeded}"
            )
        else:
            logger.info(
                f"[Drift] No drift — PSI={psi:.4f} KL={kl:.4f} "
                f"MaxFeatZ={max_feat_z:.4f}"
            )

        self._save_report(report)
        return report

    # ── Flag management ───────────────────────────────────────────────────────

    def write_flag(self, report: DriftReport) -> Path:
        """
        Write drift_detected.flag with a summary.
        The retrain_scheduler reads this file to decide whether to retrain.
        """
        content = json.dumps({
            "detected_at":     report.timestamp,
            "psi":             report.psi,
            "kl_divergence":   report.kl_divergence,
            "metrics_exceeded": report.metrics_exceeded,
        }, indent=2)
        DRIFT_FLAG_PATH.write_text(content, encoding="utf-8")
        logger.info(f"[Drift] Flag written → {DRIFT_FLAG_PATH}")
        return DRIFT_FLAG_PATH

    def clear_flag(self) -> None:
        """Remove the drift flag after successful retraining."""
        if DRIFT_FLAG_PATH.exists():
            DRIFT_FLAG_PATH.unlink()
            logger.info("[Drift] Drift flag cleared after successful retrain.")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _count_baseline_rows(self) -> int:
        if not self.baseline_csv.exists():
            return 0
        try:
            import pandas as pd
            return len(pd.read_csv(self.baseline_csv, usecols=["label"]))
        except Exception:
            return 0

    def _read_feedback_entries(self) -> list:
        if not ML_FEEDBACK_PATH.exists():
            return []
        try:
            with open(ML_FEEDBACK_PATH, "r", encoding="utf-8") as f:
                return json.load(f)
        except Exception:
            return []

    def _is_recent(self, entry: dict) -> bool:
        import datetime as dt
        cutoff = time.time() - self.window_hours * 3600
        try:
            ts = dt.datetime.strptime(
                entry.get("timestamp", ""), "%Y-%m-%dT%H:%M:%SZ"
            ).replace(tzinfo=dt.timezone.utc).timestamp()
            return ts >= cutoff
        except Exception:
            return False

    def _save_report(self, report: DriftReport):
        try:
            with open(DRIFT_REPORT_PATH, "w", encoding="utf-8") as f:
                json.dump(report.to_dict(), f, indent=2)
        except Exception as e:
            logger.error(f"[Drift] Failed to save report: {e}")
