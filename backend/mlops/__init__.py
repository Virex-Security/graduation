"""
backend/mlops/__init__.py
=========================
Virex Security - MLOps Package
Public surface for the production continuous-learning pipeline.
"""

from .retrain_scheduler import RetrainScheduler
from .feedback_manager import FeedbackManager
from .drift_detector import DriftDetector
from .dataset_merger import DatasetMerger
from .champion_challenger import ChampionChallengerEvaluator

__all__ = [
    "RetrainScheduler",
    "FeedbackManager",
    "DriftDetector",
    "DatasetMerger",
    "ChampionChallengerEvaluator",
]

__version__ = "1.0.0"
