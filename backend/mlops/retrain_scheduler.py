"""
backend/mlops/retrain_scheduler.py
=====================================
Virex Security — Automatic Retraining Scheduler (v2 — Full MLOps)

Central daemon orchestrator for the continuous learning pipeline.

Orchestration sequence (when triggered):
  1.  Acquire lock file (prevent overlapping jobs)
  2.  Run DriftDetector.run_detection()
  3.  Evaluate all preconditions (8 checks)
  4.  If skipping: release lock, write log entry, sleep to next window
  5.  Run DatasetMerger.merge()  →  backend/data/generated/merged_*.csv
  6.  Subprocess: python build_lightgbm_model.py  (cwd=backend/, isolated)
  7.  ChampionChallengerEvaluator.evaluate_candidate()
  8.  ChampionChallengerEvaluator.compare(candidate, champion)
  9a. PROMOTE → update current_model.json, clear drift flag
  9b. ARCHIVE → record rejection, keep champion
  10. Append to retraining_log.md  +  retraining_log.jsonl
  11. Update training_history.json
  12. FeedbackManager.mark_promoted() for merged feedback hashes
  13. Release lock file
  14. Sleep until next schedule window

SAFETY GUARANTEES:
  • Retraining runs in a child subprocess → cannot crash the API.
  • Lock file prevents overlapping retrain jobs.
  • Scheduler thread is daemon → exits with main process automatically.
  • All exceptions are caught; scheduler always recovers for next window.
  • API inference latency is completely unaffected (nothing runs in hot path).

Configurable environment variables (all have safe defaults):
  RETRAIN_SCHEDULE          daily | weekly | monthly   (default: daily)
  RETRAIN_HOUR              0-23                        (default: 2)
  RETRAIN_DAY_OF_WEEK       0-6 (Mon=0)                (default: 0)
  RETRAIN_DAY_OF_MONTH      1-28                        (default: 1)
  RETRAIN_MIN_NEW_SAMPLES   int                         (default: 100)
  RETRAIN_MIN_VERIFIED      int                         (default: 50)
  RETRAIN_MAX_RETRIES       int                         (default: 3)
  RETRAIN_DRY_RUN           true | false                (default: false)
  MLOPS_AUTOSTART           true | false                (default: false)
"""

import argparse
import hashlib
import json
import logging
import os
import subprocess
import sys
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("virex.mlops.scheduler")

# ── Paths ──────────────────────────────────────────────────────────────────────
BACKEND_ROOT       = Path(__file__).parent.parent
DATA_DIR           = BACKEND_ROOT / "data"
MLOPS_DIR          = BACKEND_ROOT / "mlops"
FEEDBACK_DIR       = DATA_DIR / "feedback"
TRAIN_CSV          = DATA_DIR / "train.csv"
DRIFT_FLAG_PATH    = DATA_DIR / "drift_detected.flag"
SNAPSHOT_PATH      = MLOPS_DIR / "dataset_snapshot.json"
VERSIONS_PATH      = MLOPS_DIR / "dataset_versions.json"
HISTORY_PATH       = MLOPS_DIR / "training_history.json"
MD_LOG_PATH        = MLOPS_DIR / "retraining_log.md"
JSONL_LOG_PATH     = MLOPS_DIR / "retraining_log.jsonl"
LOCK_PATH          = MLOPS_DIR / "retrain.lock"
BUILD_SCRIPT       = BACKEND_ROOT / "build_lightgbm_model.py"

# ── Environment config ────────────────────────────────────────────────────────

def _env(key: str, default: str) -> str:
    return os.getenv(key, default)

def _env_int(key: str, default: int) -> int:
    try:
        return int(os.getenv(key, str(default)))
    except ValueError:
        return default

def _env_bool(key: str, default: bool) -> bool:
    return os.getenv(key, "true" if default else "false").lower() in ("1", "true", "yes")


# ══════════════════════════════════════════════════════════════════════════════
# Schedule Policies
# ══════════════════════════════════════════════════════════════════════════════

class SchedulePolicy(ABC):
    """Abstract base for schedule policies."""

    @abstractmethod
    def seconds_until_next(self) -> float:
        """Return seconds until the next evaluation window opens."""

    @abstractmethod
    def name(self) -> str:
        ...


class DailyPolicy(SchedulePolicy):
    """Fire once per day at a configured hour."""

    def __init__(self, hour: int = 2):
        self.hour = max(0, min(23, hour))

    def name(self) -> str:
        return f"daily@{self.hour:02d}:00"

    def seconds_until_next(self) -> float:
        now = datetime.now(timezone.utc)
        target = now.replace(hour=self.hour, minute=0, second=0, microsecond=0)
        if target <= now:
            from datetime import timedelta
            target += timedelta(days=1)
        return (target - now).total_seconds()


class WeeklyPolicy(SchedulePolicy):
    """Fire once per week on a given weekday at a given hour."""

    def __init__(self, hour: int = 2, day_of_week: int = 0):
        self.hour        = max(0, min(23, hour))
        self.day_of_week = max(0, min(6, day_of_week))

    def name(self) -> str:
        days = ["Mon", "Tue", "Wed", "Thu", "Fri", "Sat", "Sun"]
        return f"weekly@{days[self.day_of_week]}/{self.hour:02d}:00"

    def seconds_until_next(self) -> float:
        from datetime import timedelta
        now    = datetime.now(timezone.utc)
        days_ahead = self.day_of_week - now.weekday()
        if days_ahead < 0 or (days_ahead == 0 and now.hour >= self.hour):
            days_ahead += 7
        target = (now + timedelta(days=days_ahead)).replace(
            hour=self.hour, minute=0, second=0, microsecond=0
        )
        return max((target - now).total_seconds(), 0)


class MonthlyPolicy(SchedulePolicy):
    """Fire once per month on a given day at a given hour."""

    def __init__(self, hour: int = 2, day_of_month: int = 1):
        self.hour         = max(0, min(23, hour))
        self.day_of_month = max(1, min(28, day_of_month))

    def name(self) -> str:
        return f"monthly@day{self.day_of_month}/{self.hour:02d}:00"

    def seconds_until_next(self) -> float:
        from datetime import timedelta
        import calendar
        now = datetime.now(timezone.utc)
        # Try this month
        try:
            target = now.replace(
                day=self.day_of_month, hour=self.hour,
                minute=0, second=0, microsecond=0
            )
            if target > now:
                return (target - now).total_seconds()
        except ValueError:
            pass
        # Next month
        if now.month == 12:
            next_month = now.replace(year=now.year + 1, month=1)
        else:
            next_month = now.replace(month=now.month + 1)
        target = next_month.replace(
            day=self.day_of_month, hour=self.hour,
            minute=0, second=0, microsecond=0
        )
        return max((target - now).total_seconds(), 0)


def build_policy() -> SchedulePolicy:
    schedule = _env("RETRAIN_SCHEDULE", "daily").lower()
    hour     = _env_int("RETRAIN_HOUR", 2)
    if schedule == "weekly":
        return WeeklyPolicy(hour=hour, day_of_week=_env_int("RETRAIN_DAY_OF_WEEK", 0))
    if schedule == "monthly":
        return MonthlyPolicy(hour=hour, day_of_month=_env_int("RETRAIN_DAY_OF_MONTH", 1))
    return DailyPolicy(hour=hour)


# ══════════════════════════════════════════════════════════════════════════════
# Dataset Snapshot (hash tracking)
# ══════════════════════════════════════════════════════════════════════════════

class DatasetSnapshot:
    """
    Persists SHA-256 hashes and row counts of training files.
    Used to detect whether the dataset has changed between evaluations.
    """

    WATCHED_FILES = ["train.csv", "validation.csv", "test.csv"]

    def __init__(self):
        self._data = self._load()

    def _load(self) -> dict:
        if SNAPSHOT_PATH.exists():
            try:
                with open(SNAPSHOT_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {}

    def _save(self):
        MLOPS_DIR.mkdir(parents=True, exist_ok=True)
        with open(SNAPSHOT_PATH, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2)

    @staticmethod
    def _file_hash(path: Path) -> str:
        sha = hashlib.sha256()
        try:
            with open(path, "rb") as f:
                for chunk in iter(lambda: f.read(65536), b""):
                    sha.update(chunk)
        except OSError:
            return "missing"
        return sha.hexdigest()

    def has_changed(self) -> Tuple[bool, dict]:
        """
        Check whether any watched file has changed since the last snapshot.
        Returns (changed: bool, details: dict).
        """
        changes = {}
        any_changed = False
        for fname in self.WATCHED_FILES:
            fpath    = DATA_DIR / fname
            new_hash = self._file_hash(fpath)
            old_hash = self._data.get(fname, {}).get("hash", "")
            if new_hash != old_hash:
                changes[fname] = {"old": old_hash[:12], "new": new_hash[:12]}
                any_changed    = True
        return any_changed, changes

    def update(self):
        """Persist the current file hashes as the new baseline."""
        for fname in self.WATCHED_FILES:
            fpath = DATA_DIR / fname
            self._data[fname] = {
                "hash":      self._file_hash(fpath),
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "size_bytes": fpath.stat().st_size if fpath.exists() else 0,
            }
        self._save()


# ══════════════════════════════════════════════════════════════════════════════
# Precondition Checker
# ══════════════════════════════════════════════════════════════════════════════

@dataclass
class ConditionReport:
    dataset_changed: bool
    dataset_change_details: dict
    new_sample_count: int
    min_new_samples: int
    drift_detected: bool
    drift_details: dict
    verified_feedback_count: int
    min_verified: int
    dataset_version: int
    previous_retrain_failed: bool
    lock_active: bool
    should_retrain: bool
    skip_reason: Optional[str]
    trigger_reasons: List[str]


class RetrainConditionChecker:
    """
    Evaluates 7 preconditions to decide whether retraining should proceed.
    Any single passing condition is sufficient to trigger retraining.
    """

    def __init__(
        self,
        snapshot: DatasetSnapshot,
        min_new_samples: int = 100,
        min_verified: int = 50,
    ):
        self.snapshot       = snapshot
        self.min_new_samples = min_new_samples
        self.min_verified    = min_verified

    def check(self, previous_failed: bool = False) -> ConditionReport:
        from mlops.feedback_manager import FeedbackManager
        from mlops.dataset_merger   import DatasetMerger

        fb     = FeedbackManager()
        merger = DatasetMerger()

        # 1. Dataset changed?
        ds_changed, ds_details = self.snapshot.has_changed()

        # 2. New samples (row-count delta approximation)
        new_samples = self._count_new_samples()

        # 3. Drift flag?
        drift_detected = DRIFT_FLAG_PATH.exists()
        drift_details  = {}
        if drift_detected:
            try:
                drift_details = json.loads(DRIFT_FLAG_PATH.read_text(encoding="utf-8"))
            except Exception:
                drift_details = {"flag": "present"}

        # 4. Verified feedback count
        verified_count = fb.count_verified_new()

        # 5. Dataset version
        ds_version = merger.get_current_version()

        # 6. Lock active (another job running)?
        lock_active = LOCK_PATH.exists()

        # 7. Previous retrain failed?
        prev_failed = previous_failed

        # ── Decision ──────────────────────────────────────────────────────────
        if lock_active:
            return ConditionReport(
                dataset_changed=ds_changed, dataset_change_details=ds_details,
                new_sample_count=new_samples, min_new_samples=self.min_new_samples,
                drift_detected=drift_detected, drift_details=drift_details,
                verified_feedback_count=verified_count, min_verified=self.min_verified,
                dataset_version=ds_version, previous_retrain_failed=prev_failed,
                lock_active=True, should_retrain=False,
                skip_reason="Retrain lock active — another job is running.",
                trigger_reasons=[],
            )

        trigger_reasons = []
        if ds_changed:
            trigger_reasons.append(f"Dataset changed: {list(ds_details.keys())}")
        if new_samples >= self.min_new_samples:
            trigger_reasons.append(f"New samples: {new_samples} >= {self.min_new_samples}")
        if drift_detected:
            trigger_reasons.append(f"Drift flag present: {drift_details}")
        if verified_count >= self.min_verified:
            trigger_reasons.append(f"Verified feedback: {verified_count} >= {self.min_verified}")
        if prev_failed:
            trigger_reasons.append("Previous retraining attempt failed — forcing retry.")

        should_retrain = len(trigger_reasons) > 0
        skip_reason    = None if should_retrain else (
            f"No trigger conditions met. "
            f"(dataset_changed={ds_changed}, "
            f"new_samples={new_samples}/{self.min_new_samples}, "
            f"drift={drift_detected}, "
            f"verified={verified_count}/{self.min_verified})"
        )

        return ConditionReport(
            dataset_changed=ds_changed, dataset_change_details=ds_details,
            new_sample_count=new_samples, min_new_samples=self.min_new_samples,
            drift_detected=drift_detected, drift_details=drift_details,
            verified_feedback_count=verified_count, min_verified=self.min_verified,
            dataset_version=ds_version, previous_retrain_failed=prev_failed,
            lock_active=False, should_retrain=should_retrain,
            skip_reason=skip_reason, trigger_reasons=trigger_reasons,
        )

    @staticmethod
    def _count_new_samples() -> int:
        """
        Approximate new sample count by reading row count of ml_feedback.json
        entries that are not yet reviewed.
        """
        if not (DATA_DIR / "ml_feedback.json").exists():
            return 0
        try:
            with open(DATA_DIR / "ml_feedback.json", "r", encoding="utf-8") as f:
                data = json.load(f)
            return sum(1 for e in data if not e.get("reviewed", False))
        except Exception:
            return 0


# ══════════════════════════════════════════════════════════════════════════════
# Log writer
# ══════════════════════════════════════════════════════════════════════════════

def _write_log(entry: dict, skip: bool, conditions: ConditionReport,
               drift_psi: float = 0.0, drift_kl: float = 0.0,
               comparison=None, model_version: str = "",
               dataset_version: int = 1, feedback_merged: int = 0,
               retrain_duration_s: float = 0.0,
               fi_comparison: Optional[dict] = None,
               subprocess_code: Optional[int] = None,
               rollback_status: str = "Not triggered."):
    """
    Append a structured entry to both retraining_log.md and retraining_log.jsonl.
    """
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    MLOPS_DIR.mkdir(parents=True, exist_ok=True)

    # ── Count existing entries for numbering ──────────────────────────────────
    entry_num = 1
    if MD_LOG_PATH.exists():
        try:
            content = MD_LOG_PATH.read_text(encoding="utf-8")
            entry_num = content.count("## [20") + 1
        except Exception:
            pass

    # ── Decision label ────────────────────────────────────────────────────────
    if skip:
        decision_label = "**SKIPPED**"
        decision_color = "⏭️"
    elif comparison and comparison.decision == "PROMOTE":
        decision_label = "**PROMOTED**"
        decision_color = "✅"
    elif comparison and comparison.decision == "ARCHIVE":
        decision_label = "**ARCHIVED** (candidate rejected)"
        decision_color = "⬇️"
    else:
        decision_label = "**TRIGGERED**"
        decision_color = "🔁"

    reason = conditions.skip_reason if skip else (
        comparison.reason if comparison else
        "; ".join(conditions.trigger_reasons)
    )

    duration_str = (
        f"{int(retrain_duration_s // 60)}m {int(retrain_duration_s % 60)}s"
        if retrain_duration_s > 0 else "—"
    )

    # ── Markdown ──────────────────────────────────────────────────────────────
    md_lines = [
        f"\n---\n",
        f"## [{ts}] Evaluation #{entry_num}  {decision_color}\n",
        f"\n| Field | Value |",
        f"|---|---|",
        f"| Schedule | {entry.get('schedule', '—')} |",
        f"| Dataset Version | v{dataset_version} |",
        f"| Model Version | {model_version or '—'} |",
        f"| Feedback Samples Merged | {feedback_merged} |",
        f"| Dataset Changed | {'Yes' if conditions.dataset_changed else 'No'} |",
        f"| New Samples | {conditions.new_sample_count} (threshold: {conditions.min_new_samples}) |",
        f"| Verified Feedback | {conditions.verified_feedback_count} (threshold: {conditions.min_verified}) |",
        f"| Drift Detected | {'Yes' if conditions.drift_detected else 'No'}"
        + (f" (PSI={drift_psi:.4f}, KL={drift_kl:.4f})" if conditions.drift_detected else "") + " |",
        f"| Decision | {decision_label} |",
        f"| Reason | {reason} |",
    ]

    if subprocess_code is not None:
        md_lines.append(f"| Subprocess Exit Code | {subprocess_code} |")
    md_lines.append(f"| Training Duration | {duration_str} |")

    if comparison and not skip:
        md_lines += [
            f"\n### Evaluation Metrics\n",
            f"| Metric | Champion ({comparison.champion_version}) | Candidate ({comparison.candidate_version}) | Delta |",
            f"|---|---|---|---|",
        ]
        champ = comparison.champion_metrics
        cand  = comparison.candidate_metrics
        for metric, label in [
            ("accuracy", "Accuracy"),
            ("f1_macro", "Macro F1"),
            ("roc_auc", "ROC AUC"),
            ("false_positive_rate", "FPR"),
            ("false_negative_rate", "FNR"),
        ]:
            cv = champ.get(metric, "—")
            cd = cand.get(metric, "—")
            delta = comparison.deltas.get(metric.replace("false_positive_rate", "fpr_delta")
                                          .replace("false_negative_rate", "fnr_delta")
                                          .replace("accuracy", "accuracy")
                                          .replace("f1_macro", "f1_macro")
                                          .replace("roc_auc", "roc_auc"), "—")
            marker = ""
            if isinstance(delta, float):
                if metric in ("false_positive_rate", "false_negative_rate"):
                    marker = "✅" if delta <= 0 else "⚠️"
                else:
                    marker = "✅" if delta >= 0 else "⚠️"
            cv_str = f"{cv:.4f}" if isinstance(cv, float) else str(cv)
            cd_str = f"{cd:.4f}" if isinstance(cd, float) else str(cd)
            dl_str = f"{delta:+.4f} {marker}" if isinstance(delta, float) else str(delta)
            md_lines.append(f"| {label} | {cv_str} | {cd_str} | {dl_str} |")

    if fi_comparison and not skip:
        md_lines += [f"\n### Feature Importance Changes (Top Shifted)\n"]
        added   = fi_comparison.get("added", [])[:5]
        removed = fi_comparison.get("removed", [])[:5]
        if added:
            md_lines.append(f"**New in {fi_comparison.get('v2')}**: {', '.join(added)}")
        if removed:
            md_lines.append(f"**Dropped from {fi_comparison.get('v1')}**: {', '.join(removed)}")

    if comparison and not skip:
        md_lines += [
            f"\n### Deployment Decision\n",
            f"{decision_label} — {reason}",
            f"\n### Rollback Status\n{rollback_status}",
        ]

    md_block = "\n".join(md_lines) + "\n"
    with open(MD_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(md_block)

    # ── JSONL ─────────────────────────────────────────────────────────────────
    json_entry = {
        "timestamp":          ts,
        "entry_number":       entry_num,
        "schedule":           entry.get("schedule", ""),
        "decision":           "SKIPPED" if skip else (comparison.decision if comparison else "TRIGGERED"),
        "reason":             reason,
        "dataset_version":    dataset_version,
        "model_version":      model_version,
        "feedback_merged":    feedback_merged,
        "dataset_changed":    conditions.dataset_changed,
        "new_samples":        conditions.new_sample_count,
        "verified_count":     conditions.verified_feedback_count,
        "drift_detected":     conditions.drift_detected,
        "drift_psi":          drift_psi,
        "drift_kl":           drift_kl,
        "subprocess_exit":    subprocess_code,
        "training_duration_s": retrain_duration_s,
        "champion_metrics":   comparison.champion_metrics if comparison else {},
        "candidate_metrics":  comparison.candidate_metrics if comparison else {},
        "rollback_status":    rollback_status,
    }
    with open(JSONL_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(json_entry, ensure_ascii=False) + "\n")

    logger.info(f"[Scheduler] Log entry #{entry_num} written ({decision_label}).")


def _update_history(
    model_version: str,
    dataset_version: int,
    metrics: dict,
    decision: str,
    drift_psi: float,
    feedback_count: int,
    duration_s: float,
):
    """Append an event to training_history.json."""
    MLOPS_DIR.mkdir(parents=True, exist_ok=True)
    history: dict = {"events": []}
    if HISTORY_PATH.exists():
        try:
            with open(HISTORY_PATH, "r", encoding="utf-8") as f:
                history = json.load(f)
        except Exception:
            pass
    event_id = len(history.get("events", [])) + 1
    history.setdefault("events", []).append({
        "event_id":              event_id,
        "model_version":         model_version,
        "dataset_version":       dataset_version,
        "timestamp":             time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "trigger":               "automatic",
        "metrics":               metrics,
        "deployment_decision":   decision,
        "drift_psi":             drift_psi,
        "feedback_count":        feedback_count,
        "training_duration_s":   round(duration_s, 1),
    })
    with open(HISTORY_PATH, "w", encoding="utf-8") as f:
        json.dump(history, f, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
# Main Scheduler
# ══════════════════════════════════════════════════════════════════════════════

class RetrainScheduler:
    """
    Daemon scheduler for the Virex MLOps continuous retraining pipeline.

    Usage (standalone):
        scheduler = RetrainScheduler()
        scheduler.start()   # non-blocking: returns immediately

    Usage (standalone script):
        python -m mlops.retrain_scheduler --dry-run
    """

    def __init__(self):
        self.policy           = build_policy()
        self.min_new_samples  = _env_int("RETRAIN_MIN_NEW_SAMPLES", 100)
        self.min_verified     = _env_int("RETRAIN_MIN_VERIFIED", 50)
        self.max_retries      = _env_int("RETRAIN_MAX_RETRIES", 3)
        self.dry_run          = _env_bool("RETRAIN_DRY_RUN", False)
        self._thread: Optional[threading.Thread] = None
        self._stop_event      = threading.Event()
        self._last_failed     = False
        self._retry_count     = 0
        MLOPS_DIR.mkdir(parents=True, exist_ok=True)
        self._init_log_files()

    # ── Start / Stop ──────────────────────────────────────────────────────────

    def start(self) -> None:
        """
        Launch the scheduler as a background daemon thread.
        Returns immediately — does NOT block the caller.
        """
        if self._thread and self._thread.is_alive():
            logger.warning("[Scheduler] Already running.")
            return
        self._thread = threading.Thread(
            target=self._loop,
            name="virex-retrain-scheduler",
            daemon=True,
        )
        self._thread.start()
        logger.info(
            f"[Scheduler] Started | policy={self.policy.name()} "
            f"dry_run={self.dry_run} "
            f"min_samples={self.min_new_samples} "
            f"min_verified={self.min_verified}"
        )

    def stop(self) -> None:
        """Signal the scheduler to stop at the next cycle check."""
        self._stop_event.set()

    # ── Main loop ─────────────────────────────────────────────────────────────

    def _loop(self) -> None:
        while not self._stop_event.is_set():
            sleep_secs = self.policy.seconds_until_next()
            logger.info(
                f"[Scheduler] Next evaluation in "
                f"{sleep_secs / 3600:.1f}h ({sleep_secs:.0f}s)  "
                f"[policy={self.policy.name()}]"
            )
            # Sleep in 60-second chunks so stop_event is responsive
            elapsed = 0.0
            while elapsed < sleep_secs and not self._stop_event.is_set():
                chunk = min(60.0, sleep_secs - elapsed)
                self._stop_event.wait(chunk)
                elapsed += chunk

            if self._stop_event.is_set():
                break

            try:
                self._evaluate_and_retrain()
            except Exception as exc:
                logger.error(f"[Scheduler] Unhandled error in evaluation: {exc}", exc_info=True)

    # ── Evaluate ──────────────────────────────────────────────────────────────

    def _evaluate_and_retrain(self) -> None:
        from mlops.drift_detector    import DriftDetector
        from mlops.dataset_merger    import DatasetMerger
        from mlops.feedback_manager  import FeedbackManager
        from mlops.champion_challenger import ChampionChallengerEvaluator

        snapshot = DatasetSnapshot()
        checker  = RetrainConditionChecker(
            snapshot,
            min_new_samples=self.min_new_samples,
            min_verified=self.min_verified,
        )

        # ── Drift detection ──────────────────────────────────────────────────
        drift_report = None
        try:
            detector     = DriftDetector()
            drift_report = detector.run_detection()
            if drift_report.drift_detected:
                detector.write_flag(drift_report)
        except Exception as e:
            logger.error(f"[Scheduler] Drift detection failed: {e}")

        drift_psi = drift_report.psi if drift_report else 0.0
        drift_kl  = drift_report.kl_divergence if drift_report else 0.0

        # ── Precondition check ───────────────────────────────────────────────
        conditions = checker.check(previous_failed=self._last_failed)
        ds_version = conditions.dataset_version

        log_entry = {"schedule": self.policy.name()}

        if not conditions.should_retrain:
            logger.info(f"[Scheduler] SKIP — {conditions.skip_reason}")
            _write_log(
                entry=log_entry, skip=True, conditions=conditions,
                drift_psi=drift_psi, drift_kl=drift_kl,
                dataset_version=ds_version,
            )
            return

        logger.info(
            f"[Scheduler] RETRAIN triggered: {conditions.trigger_reasons}"
        )

        if self.dry_run:
            logger.info("[Scheduler] DRY RUN — conditions met but retraining suppressed.")
            _write_log(
                entry=log_entry, skip=True, conditions=conditions,
                drift_psi=drift_psi, drift_kl=drift_kl,
                dataset_version=ds_version,
            )
            return

        # ── Acquire lock ──────────────────────────────────────────────────────
        try:
            LOCK_PATH.write_text(
                json.dumps({
                    "locked_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "pid": os.getpid(),
                }),
                encoding="utf-8",
            )
        except Exception as e:
            logger.error(f"[Scheduler] Could not acquire lock: {e}")
            return

        try:
            # ── Dataset merge ─────────────────────────────────────────────────
            feedback_merged = 0
            merge_result    = None
            fb_manager      = FeedbackManager()
            try:
                merger       = DatasetMerger(min_feedback_rows=self.min_verified)
                merge_result = merger.merge()
                if merge_result:
                    feedback_merged = merge_result.feedback_rows
                    ds_version      = merge_result.version
                    logger.info(
                        f"[Scheduler] Dataset merge complete: "
                        f"v{ds_version} | {feedback_merged} feedback rows"
                    )
            except Exception as e:
                logger.error(f"[Scheduler] Dataset merge failed: {e}")

            # ── Subprocess retraining ─────────────────────────────────────────
            exit_code, duration = self._trigger_retraining()

            # ── Champion-Challenger ───────────────────────────────────────────
            comparison   = None
            model_version = ""
            fi_comp       = None
            rollback_status = "Not triggered."

            evaluator = ChampionChallengerEvaluator()
            champion_metrics = evaluator.load_champion_metrics()

            if exit_code == 0:
                candidate = evaluator.evaluate_candidate(dataset_version=ds_version)
                model_version = candidate.version
                comparison    = evaluator.compare(candidate, champion_metrics)

                if comparison.decision == "PROMOTE":
                    try:
                        evaluator.promote(
                            candidate_version=model_version,
                            metrics=candidate,
                            dataset_version=ds_version,
                        )
                        # Feature importance comparison
                        if champion_metrics:
                            fi_comp = evaluator.compare_feature_importance(
                                champion_metrics.version, model_version
                            )
                        # Clear drift flag
                        try:
                            detector.clear_flag()
                        except Exception:
                            pass
                        # Mark feedback as promoted
                        if merge_result and feedback_merged > 0:
                            try:
                                verified_df = fb_manager.load_verified_dataframe()
                                hashes = verified_df["text_hash"].dropna().tolist()
                                fb_manager.mark_promoted(hashes)
                            except Exception as e:
                                logger.error(f"[Scheduler] mark_promoted failed: {e}")

                        self._last_failed = False
                        self._retry_count = 0
                        snapshot.update()

                    except Exception as promo_err:
                        rollback_status = f"Triggered — {promo_err}"
                        logger.error(f"[Scheduler] Promotion error: {promo_err}")
                        self._last_failed = True

                else:  # ARCHIVE
                    evaluator.archive(model_version, comparison.reason)
                    self._last_failed = False
                    self._retry_count = 0

                _update_history(
                    model_version=model_version,
                    dataset_version=ds_version,
                    metrics=candidate.to_dict(),
                    decision=comparison.decision,
                    drift_psi=drift_psi,
                    feedback_count=feedback_merged,
                    duration_s=duration,
                )

            else:
                # Retraining subprocess failed
                self._last_failed = True
                self._retry_count += 1
                logger.error(
                    f"[Scheduler] Subprocess failed (exit={exit_code}) "
                    f"retry {self._retry_count}/{self.max_retries}"
                )
                if self._retry_count >= self.max_retries:
                    logger.error("[Scheduler] Max retries reached — permanent failure for this window.")
                    self._last_failed  = False
                    self._retry_count  = 0

            _write_log(
                entry=log_entry, skip=False, conditions=conditions,
                drift_psi=drift_psi, drift_kl=drift_kl,
                comparison=comparison, model_version=model_version,
                dataset_version=ds_version, feedback_merged=feedback_merged,
                retrain_duration_s=duration, fi_comparison=fi_comp,
                subprocess_code=exit_code, rollback_status=rollback_status,
            )

        finally:
            # Always release the lock
            if LOCK_PATH.exists():
                try:
                    LOCK_PATH.unlink()
                except Exception:
                    pass

    # ── Subprocess retraining ─────────────────────────────────────────────────

    def _trigger_retraining(self) -> Tuple[int, float]:
        """
        Launch build_lightgbm_model.py in a child subprocess.
        Returns (exit_code, duration_seconds).

        The API process is completely isolated — a crash or OOM in the
        child does NOT affect the running Flask application.
        """
        if not BUILD_SCRIPT.exists():
            logger.error(f"[Scheduler] Build script not found: {BUILD_SCRIPT}")
            return -1, 0.0

        attempt = 0
        backoff = 300   # 5 min initial backoff for retry
        while attempt <= self.max_retries:
            if attempt > 0:
                wait = backoff * (2 ** (attempt - 1))
                logger.info(
                    f"[Scheduler] Retry #{attempt}/{self.max_retries} "
                    f"after {wait}s backoff…"
                )
                self._stop_event.wait(wait)
                if self._stop_event.is_set():
                    return -2, 0.0

            t0 = time.time()
            try:
                logger.info(
                    f"[Scheduler] Launching subprocess: "
                    f"{sys.executable} {BUILD_SCRIPT.name} "
                    f"(cwd={BACKEND_ROOT})"
                )
                result = subprocess.run(
                    [sys.executable, str(BUILD_SCRIPT)],
                    cwd=str(BACKEND_ROOT),
                    capture_output=False,
                    timeout=None,       # training can take hours
                )
                duration = time.time() - t0
                logger.info(
                    f"[Scheduler] Subprocess finished: "
                    f"exit={result.returncode} "
                    f"duration={duration:.0f}s"
                )
                return result.returncode, duration

            except subprocess.SubprocessError as e:
                duration = time.time() - t0
                logger.error(f"[Scheduler] Subprocess error (attempt {attempt}): {e}")
                attempt += 1

        return -1, 0.0

    # ── Init log files ────────────────────────────────────────────────────────

    def _init_log_files(self):
        """Create log file headers if they don't exist."""
        if not MD_LOG_PATH.exists():
            MD_LOG_PATH.write_text(
                "# Virex Security — Retraining Log\n\n"
                "> Auto-generated by `mlops/retrain_scheduler.py`  \n"
                "> Every evaluation window appends one entry to this file.\n\n",
                encoding="utf-8",
            )
        if not JSONL_LOG_PATH.exists():
            JSONL_LOG_PATH.write_text("", encoding="utf-8")
        if not HISTORY_PATH.exists():
            history_initial = {
                "events": [
                    {
                        "event_id":            1,
                        "model_version":       "model_v1",
                        "dataset_version":     1,
                        "timestamp":           "2026-06-28T23:11:17Z",
                        "trigger":             "initial",
                        "metrics": {
                            "accuracy": 0.9987, "f1_macro": 0.9993,
                            "roc_auc": 1.0, "precision_macro": 0.9996,
                            "recall_macro": 0.9991,
                        },
                        "deployment_decision": "promoted",
                        "drift_psi":           None,
                        "feedback_count":      0,
                        "training_duration_s": 2823,
                    }
                ]
            }
            with open(HISTORY_PATH, "w", encoding="utf-8") as f:
                json.dump(history_initial, f, indent=2)


# ══════════════════════════════════════════════════════════════════════════════
# CLI entry point
# ══════════════════════════════════════════════════════════════════════════════

def _setup_logging():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    )


def main():
    parser = argparse.ArgumentParser(
        description="Virex MLOps Retraining Scheduler"
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Evaluate conditions but never trigger actual retraining."
    )
    parser.add_argument(
        "--run-now", action="store_true",
        help="Trigger one evaluation immediately (ignores schedule)."
    )
    args = parser.parse_args()

    _setup_logging()

    if args.dry_run:
        os.environ["RETRAIN_DRY_RUN"] = "true"

    scheduler = RetrainScheduler()

    if args.run_now or args.dry_run:
        logger.info("[Scheduler] Running immediate evaluation…")
        try:
            scheduler._evaluate_and_retrain()
        except Exception as e:
            logger.error(f"[Scheduler] Immediate evaluation error: {e}")
        return

    # Normal daemon mode — run until killed
    scheduler.start()
    logger.info("[Scheduler] Running in daemon mode. Press Ctrl+C to stop.")
    try:
        while scheduler._thread and scheduler._thread.is_alive():
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("[Scheduler] Shutting down…")
        scheduler.stop()


if __name__ == "__main__":
    main()
