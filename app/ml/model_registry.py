"""
Virex Security — Model Registry
=================================
يتتبع إصدارات المودل ومقاييس أدائه
يحفظ في data/model_registry.json
"""

import json
import time
import logging
import threading
from pathlib import Path

logger = logging.getLogger(__name__)

PROJECT_ROOT    = Path(__file__).resolve().parent.parent.parent
DATA_DIR        = PROJECT_ROOT / "data"
REGISTRY_PATH   = DATA_DIR / "model_registry.json"


class ModelRegistry:

    def __init__(self):
        self._lock = threading.Lock()
        self._data = self._load()

    def _load(self) -> dict:
        if REGISTRY_PATH.exists():
            try:
                with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
                    return json.load(f)
            except Exception:
                pass
        return {"active_version": None, "models": {}}

    def _save(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)
        with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
            json.dump(self._data, f, indent=2, ensure_ascii=False)

    # ── public API ───────────────────────────────────────────
    def register_model(self, model_path: str, metrics: dict, version: str = None):
        if version is None:
            version = time.strftime("v%Y%m%d_%H%M%S")
        entry = {
            "version":          version,
            "model_path":       model_path,
            "registered_at":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "metrics":          metrics,
            "active":           False,
        }
        with self._lock:
            self._data["models"][version] = entry
            if self._data["active_version"] is None:
                self._data["active_version"] = version
                entry["active"] = True
            self._save()
        logger.info(f"[Registry] registered {version}")
        return version

    def activate(self, version: str):
        with self._lock:
            if version not in self._data["models"]:
                raise ValueError(f"Version {version} not found")
            # deactivate current
            cur = self._data.get("active_version")
            if cur and cur in self._data["models"]:
                self._data["models"][cur]["active"] = False
            self._data["active_version"] = version
            self._data["models"][version]["active"] = True
            self._save()
        logger.info(f"[Registry] activated {version}")

    def get_active_version(self) -> str:
        return self._data.get("active_version")

    def get_active_model_path(self) -> str:
        v = self.get_active_version()
        if v and v in self._data["models"]:
            return self._data["models"][v]["model_path"]
        return None

    def list_versions(self) -> list:
        return [
            {"version": k, **v}
            for k, v in self._data["models"].items()
        ]

    def compare_versions(self, v1: str, v2: str) -> dict:
        m = self._data["models"]
        if v1 not in m or v2 not in m:
            return {}
        r1 = m[v1].get("metrics", {})
        r2 = m[v2].get("metrics", {})
        result = {}
        for key in set(list(r1.keys()) + list(r2.keys())):
            val1 = r1.get(key, "N/A")
            val2 = r2.get(key, "N/A")
            try:
                diff = round(float(val2) - float(val1), 4)
            except Exception:
                diff = "N/A"
            result[key] = {"v1": val1, "v2": val2, "diff": diff}
        return result

    def rollback(self, version: str):
        self.activate(version)
        logger.info(f"[Registry] rolled back to {version}")

    def to_dict(self) -> dict:
        return dict(self._data)


# ── singleton ─────────────────────────────────────────────────
_registry = None
_reg_lock  = threading.Lock()

def get_registry() -> ModelRegistry:
    global _registry
    if _registry is None:
        with _reg_lock:
            if _registry is None:
                _registry = ModelRegistry()
    return _registry
