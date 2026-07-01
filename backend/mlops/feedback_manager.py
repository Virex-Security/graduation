"""
backend/mlops/feedback_manager.py
===================================
Virex Security — Human Feedback Learning Pipeline

Workflow:
  inference.py writes  -->  data/ml_feedback.json  (reviewed=False)
  Analyst reviews      -->  FeedbackManager.submit_verified(hash, label)
  FeedbackManager      -->  data/feedback/verified_feedback.csv
  DatasetMerger reads  -->  verified_feedback.csv  (only human-approved)

SAFETY RULE:
  - The model NEVER trains on its own raw predictions.
  - Only entries explicitly approved by a human reach the training pipeline.
  - submit_verified() validates labels against the canonical class list.
"""

import csv
import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("virex.mlops.feedback")

# ── Paths ──────────────────────────────────────────────────────────────────────
BACKEND_ROOT   = Path(__file__).parent.parent
DATA_DIR       = BACKEND_ROOT / "data"
FEEDBACK_DIR   = DATA_DIR / "feedback"
ML_FEEDBACK_PATH    = DATA_DIR / "ml_feedback.json"
PENDING_CSV_PATH    = FEEDBACK_DIR / "pending_predictions.csv"
VERIFIED_CSV_PATH   = FEEDBACK_DIR / "verified_feedback.csv"
PROMOTED_LOG_PATH   = FEEDBACK_DIR / "promoted_hashes.json"

# ── Canonical class names (from model_metadata.json + evaluation_report.json) ──
VALID_LABELS = frozenset({
    "normal",
    "sql_injection",
    "xss",
    "command_injection",
    "path_traversal",
    "log4shell",
    "ssrf",
    "xxe",
    "ssti",
    "brute_force",
})

# CSV column definitions
PENDING_COLS  = ["timestamp", "text_hash", "text_snippet", "risk_score",
                 "predicted_label", "decision"]
VERIFIED_COLS = ["timestamp", "text_hash", "payload", "correct_label",
                 "verified_by", "verified_at", "promoted"]


class FeedbackManager:
    """
    Human-in-the-loop feedback pipeline.

    All public methods are thread-safe.
    """

    def __init__(self):
        self._lock = threading.Lock()
        FEEDBACK_DIR.mkdir(parents=True, exist_ok=True)
        self._init_csv_files()

    # ── Initialisation ────────────────────────────────────────────────────────

    def _init_csv_files(self):
        """Create CSV files with headers if they don't exist yet."""
        if not PENDING_CSV_PATH.exists():
            self._write_csv_header(PENDING_CSV_PATH, PENDING_COLS)
        if not VERIFIED_CSV_PATH.exists():
            self._write_csv_header(VERIFIED_CSV_PATH, VERIFIED_COLS)

    @staticmethod
    def _write_csv_header(path: Path, cols: List[str]):
        with open(path, "w", newline="", encoding="utf-8") as f:
            csv.DictWriter(f, fieldnames=cols).writeheader()

    # ── Reading pending predictions ───────────────────────────────────────────

    def get_pending(self, limit: int = 200) -> List[dict]:
        """
        Return up to `limit` unreviewed predictions from ml_feedback.json.
        These are candidates for human review — NOT yet approved for training.
        """
        if not ML_FEEDBACK_PATH.exists():
            return []
        try:
            with open(ML_FEEDBACK_PATH, "r", encoding="utf-8") as f:
                all_entries = json.load(f)
        except Exception as e:
            logger.error(f"[Feedback] Failed to read ml_feedback.json: {e}")
            return []

        promoted = self._load_promoted_hashes()
        pending = [
            e for e in all_entries
            if not e.get("reviewed", False)
            and e.get("text_hash") not in promoted
        ]
        return pending[:limit]

    def export_pending_csv(self) -> Path:
        """
        Write a snapshot of pending predictions to pending_predictions.csv.
        This file is for analyst review only — NOT a training input.
        Returns the path to the written file.
        """
        rows = self.get_pending(limit=5000)
        with self._lock:
            with open(PENDING_CSV_PATH, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=PENDING_COLS,
                                       extrasaction="ignore")
                writer.writeheader()
                for e in rows:
                    writer.writerow({
                        "timestamp":       e.get("timestamp", ""),
                        "text_hash":       e.get("text_hash", ""),
                        "text_snippet":    e.get("text_snippet", ""),
                        "risk_score":      round(e.get("risk_score", 0.0), 4),
                        "predicted_label": e.get("attack_type", "unknown"),
                        "decision":        e.get("decision", ""),
                    })
        logger.info(f"[Feedback] Exported {len(rows)} pending rows → {PENDING_CSV_PATH}")
        return PENDING_CSV_PATH

    # ── Submitting verified labels ─────────────────────────────────────────────

    def submit_verified(
        self,
        text_hash: str,
        correct_label: str,
        payload: str = "",
        verified_by: str = "analyst",
    ) -> None:
        """
        Accept a human-approved, corrected label for a pending prediction.

        Raises ValueError if `correct_label` is not in VALID_LABELS.
        The model will NEVER see this entry until it is in verified_feedback.csv.
        """
        correct_label = correct_label.strip().lower()
        if correct_label not in VALID_LABELS:
            raise ValueError(
                f"Unknown label '{correct_label}'. "
                f"Valid labels: {sorted(VALID_LABELS)}"
            )

        row = {
            "timestamp":     time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "text_hash":     text_hash,
            "payload":       payload[:500],   # truncated for safety
            "correct_label": correct_label,
            "verified_by":   verified_by,
            "verified_at":   datetime.now(timezone.utc).isoformat(),
            "promoted":      "false",
        }

        with self._lock:
            file_exists = VERIFIED_CSV_PATH.exists()
            with open(VERIFIED_CSV_PATH, "a", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=VERIFIED_COLS)
                if not file_exists:
                    writer.writeheader()
                writer.writerow(row)

        logger.info(
            f"[Feedback] Verified sample accepted: hash={text_hash[:12]}… "
            f"label={correct_label} by={verified_by}"
        )

    # ── Counting verified samples ─────────────────────────────────────────────

    def count_verified_new(self, since_iso: Optional[str] = None) -> int:
        """
        Count verified samples that have not yet been promoted to training.
        If `since_iso` is provided, only count samples after that timestamp.
        """
        if not VERIFIED_CSV_PATH.exists():
            return 0
        try:
            count = 0
            with open(VERIFIED_CSV_PATH, "r", newline="", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    if row.get("promoted", "false").lower() == "true":
                        continue
                    if since_iso and row.get("verified_at", "") <= since_iso:
                        continue
                    count += 1
            return count
        except Exception as e:
            logger.error(f"[Feedback] count_verified_new error: {e}")
            return 0

    def load_verified_dataframe(self):
        """
        Load verified_feedback.csv as a pandas DataFrame.
        Returns an empty DataFrame if the file is missing or empty.
        """
        import pandas as pd
        if not VERIFIED_CSV_PATH.exists():
            return pd.DataFrame(columns=VERIFIED_COLS)
        try:
            df = pd.read_csv(VERIFIED_CSV_PATH, dtype=str)
            df = df[df["promoted"].str.lower() != "true"]
            return df
        except Exception as e:
            logger.error(f"[Feedback] Failed to load verified CSV: {e}")
            import pandas as pd
            return pd.DataFrame(columns=VERIFIED_COLS)

    # ── Marking promoted ──────────────────────────────────────────────────────

    def mark_promoted(self, hashes: List[str]) -> None:
        """
        Mark a list of text_hashes as promoted (already merged into training).
        Prevents double-counting in future retraining cycles.
        """
        if not hashes:
            return
        hash_set = set(hashes)

        # Update verified_feedback.csv promoted column
        if VERIFIED_CSV_PATH.exists():
            try:
                import pandas as pd
                df = pd.read_csv(VERIFIED_CSV_PATH, dtype=str)
                df.loc[df["text_hash"].isin(hash_set), "promoted"] = "true"
                df.to_csv(VERIFIED_CSV_PATH, index=False)
            except Exception as e:
                logger.error(f"[Feedback] mark_promoted CSV update failed: {e}")

        # Also write to promoted log for cross-reference
        promoted = self._load_promoted_hashes()
        promoted.update(hash_set)
        self._save_promoted_hashes(promoted)
        logger.info(f"[Feedback] Marked {len(hashes)} hashes as promoted.")

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _load_promoted_hashes(self) -> set:
        if PROMOTED_LOG_PATH.exists():
            try:
                with open(PROMOTED_LOG_PATH, "r", encoding="utf-8") as f:
                    return set(json.load(f))
            except Exception:
                pass
        return set()

    def _save_promoted_hashes(self, hashes: set):
        with self._lock:
            with open(PROMOTED_LOG_PATH, "w", encoding="utf-8") as f:
                json.dump(sorted(hashes), f, indent=2)

    # ── Summary ───────────────────────────────────────────────────────────────

    def summary(self) -> dict:
        """Return a quick status summary for logging/reporting."""
        pending_count  = len(self.get_pending())
        verified_new   = self.count_verified_new()
        promoted_total = len(self._load_promoted_hashes())
        return {
            "pending_unreviewed":   pending_count,
            "verified_not_promoted": verified_new,
            "promoted_total":        promoted_total,
        }
