"""
backend/mlops/dataset_merger.py
=================================
Virex Security — Safe Dataset Merge + Versioning

Workflow:
  1. Load backend/data/train.csv  (original baseline)
  2. Load verified_feedback.csv   (human-approved only)
  3. Deduplicate on text_hash / payload
  4. Validate labels (reject unknown classes)
  5. Merge and generate stratified train/val/test splits
  6. Write to backend/data/generated/merged_training_dataset.csv
  7. Bump dataset version in dataset_versions.json

SAFETY:
  - Only rows from verified_feedback.csv enter the merged dataset.
  - Raw ml_feedback.json is NEVER read here.
  - Unknown/invalid labels are dropped with a warning.
"""

import csv
import hashlib
import json
import logging
import time
from dataclasses import dataclass
from pathlib import Path
from typing import List, Optional, Tuple

import numpy as np
import pandas as pd
from sklearn.model_selection import StratifiedShuffleSplit

logger = logging.getLogger("virex.mlops.merger")

# ── Paths ──────────────────────────────────────────────────────────────────────
BACKEND_ROOT         = Path(__file__).parent.parent
DATA_DIR             = BACKEND_ROOT / "data"
MLOPS_DIR            = BACKEND_ROOT / "mlops"
FEEDBACK_DIR         = DATA_DIR / "feedback"
GENERATED_DIR        = DATA_DIR / "generated"
VERSIONS_PATH        = MLOPS_DIR / "dataset_versions.json"

TRAIN_CSV            = DATA_DIR / "train.csv"
VAL_CSV              = DATA_DIR / "validation.csv"
TEST_CSV             = DATA_DIR / "test.csv"
VERIFIED_CSV         = FEEDBACK_DIR / "verified_feedback.csv"
MERGED_CSV           = GENERATED_DIR / "merged_training_dataset.csv"

# ── Valid labels ───────────────────────────────────────────────────────────────
VALID_LABELS = frozenset({
    "normal", "sql_injection", "xss", "command_injection",
    "path_traversal", "log4shell", "ssrf", "xxe", "ssti", "brute_force",
})

# ── Split ratios ───────────────────────────────────────────────────────────────
VAL_RATIO  = 0.10
TEST_RATIO = 0.10


@dataclass
class MergeResult:
    version: int
    timestamp: str
    original_rows: int
    feedback_rows: int
    duplicate_rows_dropped: int
    invalid_label_rows_dropped: int
    total_merged_rows: int
    train_rows: int
    val_rows: int
    test_rows: int
    train_hash: str
    source_files: List[str]
    merged_csv_path: str
    notes: str = ""

    def to_dict(self) -> dict:
        import dataclasses
        return dataclasses.asdict(self)


class DatasetMerger:
    """
    Safely merges the original training dataset with human-verified feedback samples,
    generates new stratified splits, and increments the dataset version.
    """

    def __init__(self, min_feedback_rows: int = 10):
        self.min_feedback_rows = min_feedback_rows
        GENERATED_DIR.mkdir(parents=True, exist_ok=True)
        MLOPS_DIR.mkdir(parents=True, exist_ok=True)
        self._init_versions_file()

    # ── Public entry point ────────────────────────────────────────────────────

    def merge(self) -> Optional[MergeResult]:
        """
        Run the full merge pipeline.
        Returns None if there are not enough verified feedback rows.
        """
        # 1. Load base dataset
        base_df = self._load_base_dataset()
        if base_df is None or len(base_df) == 0:
            logger.error("[Merger] Base training CSV missing or empty — aborting merge.")
            return None

        original_rows = len(base_df)

        # 2. Load verified feedback
        feedback_df = self._load_feedback()
        feedback_rows = len(feedback_df)

        if feedback_rows < self.min_feedback_rows:
            logger.info(
                f"[Merger] Only {feedback_rows} verified feedback rows "
                f"(minimum: {self.min_feedback_rows}) — skipping merge."
            )
            return None

        # 3. Validate labels in feedback
        feedback_df, invalid_dropped = self._validate_labels(feedback_df)
        if len(feedback_df) == 0:
            logger.warning("[Merger] No valid feedback rows after label validation.")
            return None

        # 4. Combine and deduplicate
        combined = pd.concat(
            [
                base_df[["payload", "label"]],
                feedback_df[["payload", "label"]],
            ],
            ignore_index=True,
        )
        before_dedup = len(combined)
        combined, dup_dropped = self._deduplicate(combined)
        logger.info(
            f"[Merger] Combined: {before_dedup} rows | "
            f"After dedup: {len(combined)} | Dropped dups: {dup_dropped}"
        )

        # 5. Stratified split
        train_df, val_df, test_df = self._split(combined)

        # 6. Write outputs
        train_hash = self._write_outputs(train_df, val_df, test_df)

        # 7. Bump version
        current_version = self._bump_version(
            original_rows=original_rows,
            feedback_rows=feedback_rows,
            total_rows=len(combined),
            train_hash=train_hash,
            invalid_dropped=invalid_dropped,
            dup_dropped=dup_dropped,
        )

        result = MergeResult(
            version=current_version,
            timestamp=time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            original_rows=original_rows,
            feedback_rows=feedback_rows,
            duplicate_rows_dropped=dup_dropped,
            invalid_label_rows_dropped=invalid_dropped,
            total_merged_rows=len(combined),
            train_rows=len(train_df),
            val_rows=len(val_df),
            test_rows=len(test_df),
            train_hash=train_hash,
            source_files=[str(TRAIN_CSV), str(VERIFIED_CSV)],
            merged_csv_path=str(MERGED_CSV),
        )

        logger.info(
            f"[Merger] ✅ Dataset v{current_version} created: "
            f"{len(combined)} total rows "
            f"(train={len(train_df)}, val={len(val_df)}, test={len(test_df)})"
        )
        return result

    # ── Load ──────────────────────────────────────────────────────────────────

    def _load_base_dataset(self) -> Optional[pd.DataFrame]:
        """Load the canonical training CSV. Requires 'payload' and 'label' columns."""
        if not TRAIN_CSV.exists():
            logger.error(f"[Merger] Training CSV not found: {TRAIN_CSV}")
            return None
        try:
            df = pd.read_csv(TRAIN_CSV, usecols=["payload", "label"], dtype=str)
            df["payload"] = df["payload"].fillna("").str.strip()
            df["label"]   = df["label"].fillna("").str.strip().str.lower()
            df = df[df["payload"] != ""]
            return df
        except Exception as e:
            logger.error(f"[Merger] Failed to load train.csv: {e}")
            return None

    def _load_feedback(self) -> pd.DataFrame:
        """
        Load verified_feedback.csv.
        Only includes rows where promoted != 'true'.
        Maps 'correct_label' → 'label' for consistency with training data.
        """
        if not VERIFIED_CSV.exists():
            return pd.DataFrame(columns=["payload", "label"])
        try:
            df = pd.read_csv(VERIFIED_CSV, dtype=str)
            if df.empty:
                return pd.DataFrame(columns=["payload", "label"])

            # Filter out already-promoted rows
            df = df[df.get("promoted", pd.Series(["false"] * len(df))).str.lower() != "true"]

            # Rename columns to match training data format
            if "correct_label" in df.columns:
                df = df.rename(columns={"correct_label": "label"})
            if "payload" not in df.columns:
                df["payload"] = ""

            df["payload"] = df["payload"].fillna("").str.strip()
            df["label"]   = df["label"].fillna("").str.strip().str.lower()
            return df[["payload", "label"]]
        except Exception as e:
            logger.error(f"[Merger] Failed to load verified feedback: {e}")
            return pd.DataFrame(columns=["payload", "label"])

    # ── Validate ──────────────────────────────────────────────────────────────

    def _validate_labels(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
        """
        Drop rows with unknown labels.
        Returns (clean_df, n_dropped).
        """
        valid_mask   = df["label"].isin(VALID_LABELS)
        invalid_rows = (~valid_mask).sum()
        if invalid_rows > 0:
            bad_labels = df.loc[~valid_mask, "label"].unique().tolist()
            logger.warning(
                f"[Merger] Dropped {invalid_rows} rows with invalid labels: {bad_labels}"
            )
        return df[valid_mask].copy(), int(invalid_rows)

    # ── Deduplicate ───────────────────────────────────────────────────────────

    def _deduplicate(self, df: pd.DataFrame) -> Tuple[pd.DataFrame, int]:
        """
        Remove duplicate payloads (case-insensitive, whitespace-normalised).
        Returns (dedup_df, n_dropped).
        """
        original = len(df)
        df["_norm"] = df["payload"].str.lower().str.strip()
        df = df.drop_duplicates(subset=["_norm"]).drop(columns=["_norm"])
        dropped = original - len(df)
        return df.reset_index(drop=True), dropped

    # ── Split ─────────────────────────────────────────────────────────────────

    def _split(
        self,
        df: pd.DataFrame,
    ) -> Tuple[pd.DataFrame, pd.DataFrame, pd.DataFrame]:
        """
        Generate stratified train / validation / test splits.
        Falls back to random split if any class has < 2 samples.
        """
        try:
            sss1 = StratifiedShuffleSplit(
                n_splits=1,
                test_size=VAL_RATIO + TEST_RATIO,
                random_state=42,
            )
            train_idx, holdout_idx = next(sss1.split(df, df["label"]))
            train_df   = df.iloc[train_idx].reset_index(drop=True)
            holdout_df = df.iloc[holdout_idx].reset_index(drop=True)

            # Split holdout into val and test
            relative_test = TEST_RATIO / (VAL_RATIO + TEST_RATIO)
            sss2 = StratifiedShuffleSplit(
                n_splits=1, test_size=relative_test, random_state=42
            )
            val_idx, test_idx = next(sss2.split(holdout_df, holdout_df["label"]))
            val_df  = holdout_df.iloc[val_idx].reset_index(drop=True)
            test_df = holdout_df.iloc[test_idx].reset_index(drop=True)

        except Exception as e:
            logger.warning(
                f"[Merger] Stratified split failed ({e}), falling back to random split."
            )
            shuffled   = df.sample(frac=1, random_state=42).reset_index(drop=True)
            n_val      = int(len(shuffled) * VAL_RATIO)
            n_test     = int(len(shuffled) * TEST_RATIO)
            val_df     = shuffled[:n_val]
            test_df    = shuffled[n_val: n_val + n_test]
            train_df   = shuffled[n_val + n_test:]

        return train_df, val_df, test_df

    # ── Write ─────────────────────────────────────────────────────────────────

    def _write_outputs(
        self,
        train_df: pd.DataFrame,
        val_df: pd.DataFrame,
        test_df: pd.DataFrame,
    ) -> str:
        """
        Write merged datasets to generated/ directory.
        Returns the SHA-256 hash of the merged training split.
        """
        GENERATED_DIR.mkdir(parents=True, exist_ok=True)
        train_df.to_csv(MERGED_CSV, index=False)
        val_df.to_csv(GENERATED_DIR / "merged_validation_dataset.csv", index=False)
        test_df.to_csv(GENERATED_DIR / "merged_test_dataset.csv", index=False)

        # Compute hash of training split
        sha256 = hashlib.sha256()
        with open(MERGED_CSV, "rb") as f:
            for chunk in iter(lambda: f.read(65536), b""):
                sha256.update(chunk)
        return sha256.hexdigest()

    # ── Dataset versioning ────────────────────────────────────────────────────

    def _init_versions_file(self):
        if not VERSIONS_PATH.exists():
            initial = {
                "current_version": 1,
                "versions": [
                    {
                        "version": 1,
                        "timestamp": "2026-06-28T23:11:17Z",
                        "train_hash": "baseline",
                        "row_count": 142323,
                        "source_files": ["train.csv"],
                        "feedback_count": 0,
                        "invalid_dropped": 0,
                        "duplicate_dropped": 0,
                        "notes": "Initial baseline — original training dataset",
                    }
                ],
            }
            with open(VERSIONS_PATH, "w", encoding="utf-8") as f:
                json.dump(initial, f, indent=2)

    def _bump_version(
        self,
        original_rows: int,
        feedback_rows: int,
        total_rows: int,
        train_hash: str,
        invalid_dropped: int,
        dup_dropped: int,
    ) -> int:
        """
        Increment the dataset version counter and record the new entry.
        Returns the new version number.
        """
        try:
            with open(VERSIONS_PATH, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception:
            data = {"current_version": 1, "versions": []}

        new_version = data.get("current_version", 1) + 1
        entry = {
            "version":          new_version,
            "timestamp":        time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "train_hash":       train_hash,
            "row_count":        total_rows,
            "original_rows":    original_rows,
            "feedback_count":   feedback_rows,
            "invalid_dropped":  invalid_dropped,
            "duplicate_dropped": dup_dropped,
            "source_files":     ["train.csv", "verified_feedback.csv"],
            "notes":            f"Merged {feedback_rows} verified feedback samples",
        }
        data["current_version"] = new_version
        data.setdefault("versions", []).append(entry)

        with open(VERSIONS_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)

        logger.info(f"[Merger] Dataset version bumped → v{new_version}")
        return new_version

    def get_current_version(self) -> int:
        """Return the current dataset version number."""
        if not VERSIONS_PATH.exists():
            return 1
        try:
            with open(VERSIONS_PATH, "r", encoding="utf-8") as f:
                return json.load(f).get("current_version", 1)
        except Exception:
            return 1
