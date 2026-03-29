# ── WAF Rules ───────────────────────────────────────────────
def get_rules(active_only=True):
    """Get WAF rules from the database. If active_only=True, return only active rules."""
    db._ensure_rules_table()
    with db.db_cursor() as cur:
        query = "SELECT * FROM rules"
        if active_only:
            query += " WHERE active = 1"
        cur.execute(query)
        return [dict(row) for row in cur.fetchall()]
"""
Persistence Manager (DB-backed)
================================
تم استبدال JSON files بـ SQLite عبر app/database.py
الـ API ظاهر زي ما كان (نفس أسماء الدوال) عشان باقي الكود ميتأثرش.
"""
import time
import threading
import tempfile
import shutil
import logging
from pathlib import Path

logger = logging.getLogger(__name__)

# ── المسارات القديمة محتفظ بيها للـ compatibility ─────────────
PROJECT_ROOT      = Path(__file__).parent.parent.parent
DATA_DIR          = PROJECT_ROOT / "data"
DATA_DIR.mkdir(parents=True, exist_ok=True)

_lock    = threading.Lock()
_ml_lock = threading.Lock()

# ── كل العمليات الحقيقية بتروح للـ DB ─────────────────────────
from app import database as db


# ── Stats ─────────────────────────────────────────────────────
def load_stats() -> dict:
    return db.load_stats()


def save_stats(total: int, blocked: int):
    db.save_stats(total, blocked)


# ── Blocked IPs ───────────────────────────────────────────────
def load_blocked_ips() -> dict:
    return db.load_blocked_ips()


def save_blocked_ips(blocked: dict):
    db.save_blocked_ips(blocked)


# ── Attack History ────────────────────────────────────────────
def load_user_attacks() -> dict:
    return db.load_user_attacks()


def append_user_attack(user_key: str, attack_type: str, ip: str,
                       endpoint: str, method: str = "", severity: str = "High"):
    db.append_user_attack(user_key, attack_type, ip, endpoint, method, severity)


def get_user_attacks(user_key: str) -> list:
    return db.get_user_attacks(user_key)


def clear_user_attacks(user_key: str):
    db.clear_user_attacks(user_key)


def clear_all_attacks():
    db.clear_all_attacks()


# ── ML Detections ─────────────────────────────────────────────
def log_ml_detection(text_snippet: str, risk_score: float,
                     action: str, attack_type: str, ip: str, endpoint: str):
    db.log_ml_detection(text_snippet, risk_score, action, attack_type, ip, endpoint)


def get_ml_detections(limit: int = 100) -> list:
    return db.get_ml_detections(limit)
