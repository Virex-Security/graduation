"""
Persistence Manager
===================
يحفظ الـ state كاملاً في ملفات JSON/JSONL في data/
بحيث مفيش data يضيع بعد restart.

الملفات:
  data/stats.json          ← total_requests, blocked_requests
  data/blocked_ips.json    ← IPs المحجوبة مع وقت الانتهاء
  data/user_attacks.json   ← attack history لكل user/IP
  data/ml_detections.jsonl ← ML feedback log (append-only)
"""

import json
import os
import time
import threading
import tempfile
import shutil
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent.parent
DATA_DIR     = PROJECT_ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

STATS_FILE        = DATA_DIR / "stats.json"
BLOCKED_IPS_FILE  = DATA_DIR / "blocked_ips.json"
USER_ATTACKS_FILE = DATA_DIR / "user_attacks.json"
ML_LOG_FILE       = DATA_DIR / "ml_detections.jsonl"

_lock = threading.Lock()


# ── Atomic write helper ────────────────────────────────────────
def _atomic_write(path: Path, data):
    """Write JSON atomically using temp file + rename."""
    tmp_fd, tmp_path = tempfile.mkstemp(dir=str(DATA_DIR), suffix=".tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        shutil.move(tmp_path, str(path))
    except Exception:
        try:
            os.unlink(tmp_path)
        except Exception:
            pass
        raise


def _read_json(path: Path, default):
    try:
        if path.exists():
            with open(path, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.error(f"[PERSIST] read {path.name} failed: {e}")
    return default


# ══════════════════════════════════════════════════════════════
# 1. Stats  (total_requests, blocked_requests)
# ══════════════════════════════════════════════════════════════
def load_stats() -> dict:
    return _read_json(STATS_FILE, {"total_requests": 0, "blocked_requests": 0})


def save_stats(total: int, blocked: int):
    with _lock:
        _atomic_write(STATS_FILE, {
            "total_requests":   total,
            "blocked_requests": blocked,
            "saved_at":         time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })


# ══════════════════════════════════════════════════════════════
# 2. Blocked IPs  {ip: unblock_timestamp}
# ══════════════════════════════════════════════════════════════
def load_blocked_ips() -> dict:
    raw = _read_json(BLOCKED_IPS_FILE, {})
    now = time.time()
    # حذف الـ IPs اللي انتهى حجبها
    return {ip: ts for ip, ts in raw.items() if ts > now}


def save_blocked_ips(blocked: dict):
    with _lock:
        _atomic_write(BLOCKED_IPS_FILE, blocked)


# ══════════════════════════════════════════════════════════════
# 3. User Attacks History
#    {"user_id_or_ip": [{"type","ip","endpoint","timestamp"}, ...]}
# ══════════════════════════════════════════════════════════════
def load_user_attacks() -> dict:
    return _read_json(USER_ATTACKS_FILE, {})


def append_user_attack(user_key: str, attack_type: str, ip: str,
                       endpoint: str, method: str = "", severity: str = "High"):
    """أضف هجوم واحد لـ user_key (username أو IP)."""
    with _lock:
        data = load_user_attacks()
        if user_key not in data:
            data[user_key] = []
        data[user_key].append({
            "type":      attack_type,
            "ip":        ip,
            "endpoint":  endpoint,
            "method":    method,
            "severity":  severity,
            "timestamp": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        })
        # الاحتفاظ بآخر 500 هجوم لكل user
        if len(data[user_key]) > 500:
            data[user_key] = data[user_key][-500:]
        _atomic_write(USER_ATTACKS_FILE, data)


def get_user_attacks(user_key: str) -> list:
    data = load_user_attacks()
    return data.get(user_key, [])


def clear_user_attacks(user_key: str):
    with _lock:
        data = load_user_attacks()
        if user_key in data:
            del data[user_key]
            _atomic_write(USER_ATTACKS_FILE, data)


def clear_all_attacks():
    with _lock:
        _atomic_write(USER_ATTACKS_FILE, {})


# ══════════════════════════════════════════════════════════════
# 4. ML Detections Log  (append-only JSONL)
# ══════════════════════════════════════════════════════════════
_ml_lock = threading.Lock()


def log_ml_detection(text_snippet: str, risk_score: float,
                     action: str, attack_type: str, ip: str, endpoint: str):
    entry = {
        "timestamp":    time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "ip":           ip,
        "endpoint":     endpoint,
        "attack_type":  attack_type,
        "action":       action,
        "risk_score":   round(risk_score * 100, 1),
        "text_snippet": text_snippet[:120],
        "reviewed":     False,
    }
    try:
        with _ml_lock:
            with open(str(ML_LOG_FILE), "a", encoding="utf-8") as f:
                f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.error(f"[PERSIST] ml log write failed: {e}")


def get_ml_detections(limit: int = 100) -> list:
    results = []
    try:
        if ML_LOG_FILE.exists():
            with open(str(ML_LOG_FILE), "r", encoding="utf-8") as f:
                lines = f.readlines()
            for line in reversed(lines[-limit:]):
                line = line.strip()
                if line:
                    try:
                        results.append(json.loads(line))
                    except Exception:
                        pass
    except Exception as e:
        logger.error(f"[PERSIST] ml log read failed: {e}")
    return results
