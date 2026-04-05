"""
Database Manager - virex.db  (SQLite)
======================================
يتعامل مع الـ 19 table الموجودة في db/virex.db
"""

import sqlite3
import threading
import time
import logging
<<<<<<< HEAD
=======
<<<<<<< HEAD
=======
import re
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
from pathlib import Path
from contextlib import contextmanager

logger = logging.getLogger(__name__)

PROJECT_ROOT = Path(__file__).parent.parent
DB_PATH      = PROJECT_ROOT / "db" / "virex.db"

@contextmanager
def db_cursor():
    """كل عملية بتفتح connection جديدة وبتقفلها — يمنع database is locked."""
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    conn = sqlite3.connect(str(DB_PATH), timeout=10, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=5000")
<<<<<<< HEAD
=======
=======
    conn = sqlite3.connect(str(DB_PATH), timeout=30, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    try:
        conn.execute("PRAGMA journal_mode=WAL")
    except sqlite3.OperationalError:
        pass
    conn.execute("PRAGMA foreign_keys=ON")
    conn.execute("PRAGMA busy_timeout=30000")
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    cur = conn.cursor()
    try:
        yield cur
        conn.commit()
    except Exception as e:
        conn.rollback()
        logger.error(f"[DB] Error: {e}")
        raise
    finally:
        conn.close()


def init_db():
<<<<<<< HEAD
    """Ensure DB is ready: seed roles, users, and create performance indexes."""
=======
<<<<<<< HEAD
    """Ensure DB is ready: seed roles, users, and create performance indexes."""
=======
    """Ensure DB is ready: schema, seed roles, users, and create performance indexes."""
    _ensure_schema()
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    _seed_roles()
    _seed_users()
    ensure_indexes()
    logger.info("[DB] Ready — %s", DB_PATH)


<<<<<<< HEAD
=======
<<<<<<< HEAD
=======
def _add_column_if_missing(cur, table, column, definition):
    """Safely adds a column to a table if it doesn't already exist (idempotent)."""
    cur.execute(f"PRAGMA table_info({table})")
    cols = [r["name"] for r in cur.fetchall()]
    if column not in cols:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
        logger.info("[DB] Added column %s to table %s", column, table)


>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
# ══════════════════════════════════════════════════════════════
# SEED helpers
# ══════════════════════════════════════════════════════════════

def _seed_roles():
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM roles")
        if cur.fetchone()[0] == 0:
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            roles = [
                ("admin",    "Full system access"),
                ("user",     "Standard access"),
                ("analyst",  "Read-only + reports"),
                ("manager",  "Team management"),
            ]
            cur.executemany(
                "INSERT INTO roles (name, description, created_at) VALUES (?,?,?)",
                [(r[0], r[1], now) for r in roles]
            )


def _seed_users():
    """يهجّر الـ users من users.json للـ DB لو مش موجودين."""
    import json
    users_file = PROJECT_ROOT / "data" / "users.json"
    if not users_file.exists():
        return

    with open(users_file, encoding="utf-8") as f:
        users_json = json.load(f)

    with db_cursor() as cur:
        for username, u in users_json.items():
            cur.execute("SELECT user_id FROM users WHERE username = ?", (username,))
            if cur.fetchone():
                continue  # موجود بالفعل

            # جيب الـ role_id
            role_name = u.get("role", "user")
            cur.execute("SELECT role_id FROM roles WHERE name = ?", (role_name,))
            row = cur.fetchone()
            role_id = row[0] if row else 2  # default: user

            now = time.strftime("%Y-%m-%d %H:%M:%S")
            cur.execute(
                """INSERT INTO users
                   (username, password_hash, email, role_id, is_active, created_at, updated_at)
                   VALUES (?,?,?,?,?,?,?)""",
                (
                    username,
                    u.get("password_hash", ""),
                    u.get("email", f"{username}@example.com"),
                    role_id,
                    1,
                    now, now,
                )
            )


# ══════════════════════════════════════════════════════════════
# USERS
# ══════════════════════════════════════════════════════════════

def get_all_users() -> list:
    with db_cursor() as cur:
        cur.execute("""
            SELECT u.*, r.name as role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.role_id
            ORDER BY u.user_id
        """)
        return [dict(r) for r in cur.fetchall()]


def get_user_by_username(username: str) -> dict | None:
    with db_cursor() as cur:
        cur.execute("""
            SELECT u.*, r.name as role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.role_id
            WHERE u.username = ?
        """, (username,))
        row = cur.fetchone()
        return dict(row) if row else None


def get_user_by_id(user_id) -> dict | None:
    with db_cursor() as cur:
        cur.execute("""
            SELECT u.*, r.name as role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.role_id
            WHERE u.user_id = ?
        """, (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None
def get_user_by_email(email: str) -> dict | None:
    with db_cursor() as cur:
        cur.execute("""
            SELECT u.*, r.name as role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.role_id
            WHERE u.email = ?
        """, (email,))
        row = cur.fetchone()
        return dict(row) if row else None



def insert_user(username, password_hash, email=None,
                role="user", department_id=None) -> int:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute("SELECT role_id FROM roles WHERE name = ?", (role,))
        row = cur.fetchone()
        role_id = row[0] if row else 2
        cur.execute(
            """INSERT INTO users
               (username, password_hash, email, role_id, department_id,
                is_active, created_at, updated_at)
               VALUES (?,?,?,?,?,1,?,?)""",
            (username, password_hash,
             email or f"{username}@example.com",
             role_id, department_id, now, now)
        )
        return cur.lastrowid


def update_user(username: str, **kwargs) -> bool:
    allowed = {"email", "password_hash", "role_id", "department_id",
               "is_active", "last_login", "updated_at",
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
               "full_name", "phone", "department"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return False
    fields["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
<<<<<<< HEAD
=======
=======
               "full_name", "phone", "department", "avatar_url"}
    # Strict validation: Every key in kwargs MUST be in allowlist and match regex
    for k in kwargs:
        if k not in allowed:
            raise ValueError(f"[SECURITY] Unauthorized column update: {k}")
        if not re.fullmatch(r"^[a-z0-9_]+$", k):
            raise ValueError(f"[SECURITY] Invalid column format: {k}")

    if not kwargs:
        return False

    fields = kwargs.copy()
    fields["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [username]
    with db_cursor() as cur:
        cur.execute(f"UPDATE users SET {set_clause} WHERE username = ?", values)
        return cur.rowcount > 0


def delete_user(username: str) -> bool:
    with db_cursor() as cur:
        cur.execute("DELETE FROM users WHERE username = ?", (username,))
        return cur.rowcount > 0


# ══════════════════════════════════════════════════════════════
# ROLES
# ══════════════════════════════════════════════════════════════

def get_all_roles() -> list:
    with db_cursor() as cur:
        cur.execute("SELECT * FROM roles ORDER BY role_id")
        return [dict(r) for r in cur.fetchall()]


# ══════════════════════════════════════════════════════════════
# RULES
# ══════════════════════════════════════════════════════════════

<<<<<<< HEAD
def _ensure_rules_table():
    """Create the rules table if it doesn't already exist."""
    with db_cursor() as cur:
=======
<<<<<<< HEAD
def _ensure_rules_table():
    """Create the rules table if it doesn't already exist."""
    with db_cursor() as cur:
=======
def _ensure_schema():
    """Create all required tables and handle schema migrations if they don't already exist."""
    with db_cursor() as cur:
        # Rules Table
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
        cur.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                rule_id      INTEGER PRIMARY KEY AUTOINCREMENT,
                name         TEXT NOT NULL,
                type         TEXT NOT NULL,
                pattern      TEXT,
                severity     TEXT NOT NULL DEFAULT 'medium',
                action       TEXT NOT NULL DEFAULT 'block',
                is_active    INTEGER NOT NULL DEFAULT 1,
                description  TEXT,
                created_at   TEXT
            )
        """)
<<<<<<< HEAD
=======
<<<<<<< HEAD
=======
        # Password Resets Table
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
        cur.execute("""
            CREATE TABLE IF NOT EXISTS password_resets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                otp TEXT NOT NULL,
                otp_expiry TEXT NOT NULL,
<<<<<<< HEAD
                used INTEGER DEFAULT 0
            )
        """)
=======
<<<<<<< HEAD
                used INTEGER DEFAULT 0
            )
        """)
=======
                used INTEGER DEFAULT 0,
                otp_attempts INTEGER DEFAULT 0
            )
        """)
        # Run specific schema updates safely
        _add_column_if_missing(cur, "password_resets", "otp_attempts", "INTEGER DEFAULT 0")
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                audit_log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id      INTEGER,
                action       TEXT NOT NULL,
                resource     TEXT,
                resource_id  TEXT,
                details      TEXT,
                ip_address   TEXT,
                user_agent   TEXT,
                created_at   TEXT
            )
        """)
        cur.execute("""
<<<<<<< HEAD
=======
<<<<<<< HEAD
=======
            CREATE TABLE IF NOT EXISTS otp_requests (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                identifier   TEXT NOT NULL,
                requested_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS rate_limits (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                key          TEXT NOT NULL,
                requested_at TEXT NOT NULL
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS login_attempts (
                login_attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id          INTEGER,
                username         TEXT,
                ip_address       TEXT,
                success          INTEGER DEFAULT 0,
                failure_reason   TEXT,
                attempted_at     TEXT
            )
        """)
        cur.execute("""
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
            CREATE TABLE IF NOT EXISTS threat_logs (
                threat_log_id  INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type    TEXT NOT NULL,
                ip_address     TEXT,
                endpoint       TEXT,
                method         TEXT,
                payload        TEXT,
                severity       TEXT    DEFAULT 'Medium',
                description    TEXT,
                blocked        INTEGER DEFAULT 0,
                ml_detected    INTEGER DEFAULT 0,
                confidence     REAL    DEFAULT 0.0,
                detection_type TEXT,
                created_at     TEXT
            )
        """)
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
                username      TEXT NOT NULL UNIQUE,
                password_hash TEXT NOT NULL,
                email         TEXT,
                role_name     TEXT DEFAULT 'user',
                status        TEXT DEFAULT 'active',
                full_name     TEXT,
                phone         TEXT,
                department    TEXT,
                last_login    TEXT,
<<<<<<< HEAD
=======
<<<<<<< HEAD
=======
                avatar_url    TEXT,
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
                created_at    TEXT
            )
        """)


def _seed_rules_table():
    """Insert default WAF detection rules if the table is empty."""
<<<<<<< HEAD
    _ensure_rules_table()
=======
<<<<<<< HEAD
    _ensure_rules_table()
=======
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM rules")
        if cur.fetchone()[0] > 0:
            return  # already seeded

        now = time.strftime("%Y-%m-%d %H:%M:%S")
        default_rules = [
            ("SQL Injection - UNION",         "sql_injection",    "UNION\\s+SELECT",                               "high",     "block", "Detects UNION-based SQL injection"),
            ("SQL Injection - Keywords",      "sql_injection",    "(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)",       "high",     "block", "Detects SQL keyword abuse"),
            ("SQL Injection - Comment",       "sql_injection",    "(--|#|/\\*|;|@@)",                              "high",     "block", "Detects SQL comment/terminator injection"),
            ("SQL Injection - OR/AND",        "sql_injection",    "(\\bOR\\b|\\bAND\\b).+(=|LIKE|IN)",             "high",     "block", "Detects boolean-based SQL injection"),
            ("XSS - Script Tag",              "xss",              "<script.*?>.*?</script>",                       "high",     "block", "Detects XSS script injection"),
            ("XSS - JavaScript Protocol",    "xss",              "javascript:",                                    "high",     "block", "Detects javascript: URI XSS"),
            ("XSS - Event Handler",          "xss",              "(onerror|onload|onclick)\\s*=",                 "high",     "block", "Detects HTML event handler XSS"),
            ("XSS - Alert",                  "xss",              "alert\\(.*\\)",                                 "medium",   "block", "Detects alert()-based XSS probing"),
            ("Command Injection - Pipe",     "command_injection", "(;|\\|{1,2}|&&|`)\\s*(cat|ls|rm|wget|curl|nc|bash|sh)", "critical","block", "Detects shell command injection"),
            ("Command Injection - Subshell", "command_injection", "\\$\\(.*\\)",                                  "critical", "block", "Detects $() subshell injection"),
            ("Path Traversal - Dotdot",      "path_traversal",   "\\.\\.[/\\\\]",                                "high",     "block", "Detects ../ or ..\\ path traversal"),
            ("Path Traversal - Encoded",     "path_traversal",   "%2e%2e[%2f%5c]",                               "high",     "block", "Detects URL-encoded path traversal"),
            ("Path Traversal - Sensitive",   "path_traversal",   "(etc/passwd|etc/shadow|windows/system32)",     "critical", "block", "Detects access to sensitive system paths"),
        ]
        cur.executemany(
            """INSERT INTO rules (name, type, pattern, severity, action, description, is_active, created_at)
               VALUES (?,?,?,?,?,?,1,?)""",
            [(r[0], r[1], r[2], r[3], r[4], r[5], now) for r in default_rules]
        )
        logger.info("[DB] Seeded %d default rules", len(default_rules))


def get_rules(active_only: bool = True) -> list:
    """
    Return WAF rules from the database as a list of dictionaries.
<<<<<<< HEAD
=======
<<<<<<< HEAD
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    Each dict has keys: rule_id, name, type, pattern, severity, action,
                        is_active, description, created_at.
    Example: {"type": "sql_injection", "severity": "high", ...}
    """
    _ensure_rules_table()
<<<<<<< HEAD
=======
=======
    """
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    with db_cursor() as cur:
        if active_only:
            cur.execute("SELECT * FROM rules WHERE is_active = 1 ORDER BY rule_id")
        else:
            cur.execute("SELECT * FROM rules ORDER BY rule_id")
        rules = [dict(r) for r in cur.fetchall()]
    logger.debug("[DEBUG] get_rules() loaded {len(rules)} rule(s) from DB")
    return rules


# ══════════════════════════════════════════════════════════════
# THREAT LOGS
# ══════════════════════════════════════════════════════════════

def log_threat(attack_type: str, ip_address: str, endpoint: str,
               method: str, payload: str = "", severity: str = "Medium",
               description: str = "", blocked: bool = False,
               ml_detected: bool = False, confidence: float = 0.0,
               detection_type: str = "rule") -> int:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO threat_logs
               (attack_type, ip_address, description, severity,
                endpoint, method, payload, detection_type,
                blocked, ml_detected, confidence, created_at)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (attack_type, ip_address, description, severity,
             endpoint, method, payload[:500] if payload else "",
             detection_type, int(blocked), int(ml_detected),
             round(confidence, 4), now)
        )
        return cur.lastrowid


def get_threat_logs(limit: int = 100, attack_type: str = None,
                    severity: str = None) -> list:
    sql = "SELECT * FROM threat_logs WHERE 1=1"
    params = []
    if attack_type:
        sql += " AND attack_type = ?"
        params.append(attack_type)
    if severity:
        sql += " AND severity = ?"
        params.append(severity)
    sql += " ORDER BY threat_log_id DESC LIMIT ?"
    params.append(limit)
    with db_cursor() as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


# ══════════════════════════════════════════════════════════════
# BLOCKED IPs
# ══════════════════════════════════════════════════════════════

def load_blocked_ips() -> dict:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        # حذف المنتهية
        cur.execute("DELETE FROM blocked_ips WHERE is_permanent = 0 AND unblock_at <= ?", (now,))
        cur.execute("SELECT ip_address, unblock_at FROM blocked_ips")
        result = {}
        for r in cur.fetchall():
            try:
                ts = time.mktime(time.strptime(r["unblock_at"], "%Y-%m-%d %H:%M:%S"))
            except Exception:
                ts = float("inf")
            result[r["ip_address"]] = ts
        return result


def save_blocked_ips(blocked: dict):
    now_ts  = time.time()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute("DELETE FROM blocked_ips WHERE is_permanent = 0")
        for ip, unblock_ts in blocked.items():
            if unblock_ts > now_ts:
                unblock_str = time.strftime("%Y-%m-%d %H:%M:%S",
                                             time.localtime(unblock_ts))
                cur.execute(
                    """INSERT OR REPLACE INTO blocked_ips
                       (ip_address, reason, is_permanent, blocked_at, unblock_at)
                       VALUES (?,?,0,?,?)""",
                    (ip, "auto-block", now_str, unblock_str)
                )


def block_ip(ip: str, unblock_at_ts: float, reason: str = "auto-block",
             blocked_by: int = None, is_permanent: bool = False):
    now_str    = time.strftime("%Y-%m-%d %H:%M:%S")
    unblk_str  = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(unblock_at_ts))
    with db_cursor() as cur:
        cur.execute(
            """INSERT OR REPLACE INTO blocked_ips
               (ip_address, reason, blocked_by, is_permanent, blocked_at, unblock_at)
               VALUES (?,?,?,?,?,?)""",
            (ip, reason, blocked_by, int(is_permanent), now_str, unblk_str)
        )


def unblock_ip(ip: str):
    with db_cursor() as cur:
        cur.execute("DELETE FROM blocked_ips WHERE ip_address = ?", (ip,))


# ══════════════════════════════════════════════════════════════
# BLOCKED EVENTS
# ══════════════════════════════════════════════════════════════

def log_blocked_event(ip_address: str, attack_type: str, severity: str,
                      ml_detected: bool = False, confidence: float = 0.0,
                      threat_log_id: int = None):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO blocked_events
               (threat_log_id, ip_address, attack_type, severity,
                ml_detected, confidence, blocked_at)
               VALUES (?,?,?,?,?,?,?)""",
            (threat_log_id, ip_address, attack_type, severity,
             int(ml_detected), round(confidence, 4), now)
        )


def get_blocked_events(limit: int = 100) -> list:
    with db_cursor() as cur:
        cur.execute(
            "SELECT * FROM blocked_events ORDER BY blocked_event_id DESC LIMIT ?",
            (limit,)
        )
        return [dict(r) for r in cur.fetchall()]


# ══════════════════════════════════════════════════════════════
# INCIDENTS
# ══════════════════════════════════════════════════════════════

def create_incident(category: str, source_ip: str, severity: str,
                    detection_type: str = "rule") -> int:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    import random, string
    code = "INC-" + "".join(random.choices(string.digits, k=6))
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO incidents
               (incident_code, category, source_ip, detection_type,
                status, severity, first_seen, last_seen, created_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (code, category, source_ip, detection_type,
             "open", severity, now, now, now)
        )
        return cur.lastrowid


def get_incidents(status: str = None, limit: int = 100) -> list:
    sql = "SELECT * FROM incidents WHERE 1=1"
    params = []
    if status:
        sql += " AND status = ?"
        params.append(status)
    sql += " ORDER BY incident_id DESC LIMIT ?"
    params.append(limit)
    with db_cursor() as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


def update_incident_status(incident_id: int, new_status: str,
                            actor_id: int = None, comment: str = ""):
    with db_cursor() as cur:
        cur.execute("SELECT status FROM incidents WHERE incident_id = ?", (incident_id,))
        row = cur.fetchone()
        if not row:
            return False
        old_status = row[0]
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        cur.execute("UPDATE incidents SET status = ?, last_seen = ? WHERE incident_id = ?",
                    (new_status, now, incident_id))
        cur.execute(
            """INSERT INTO incident_actions
               (incident_id, actor_id, action, comment,
                previous_status, new_status, created_at)
               VALUES (?,?,?,?,?,?,?)""",
            (incident_id, actor_id, "status_change", comment,
             old_status, new_status, now)
        )
        return True


# ══════════════════════════════════════════════════════════════
# LOGIN ATTEMPTS
# ══════════════════════════════════════════════════════════════

def log_login_attempt(user_id: int, ip_address: str,
                      success: bool, failure_reason: str = None):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO login_attempts
               (user_id, ip_address, success, failure_reason, attempted_at)
               VALUES (?,?,?,?,?)""",
            (user_id, ip_address, int(success), failure_reason, now)
        )


def get_login_attempts(user_id: int = None, limit: int = 50) -> list:
    sql = "SELECT * FROM login_attempts WHERE 1=1"
    params = []
    if user_id:
        sql += " AND user_id = ?"
        params.append(user_id)
    sql += " ORDER BY login_attempt_id DESC LIMIT ?"
    params.append(limit)
    with db_cursor() as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


# ══════════════════════════════════════════════════════════════
# USER SESSIONS
# ══════════════════════════════════════════════════════════════

def create_session(user_id: int, jwt_hash: str, ip_address: str,
                   user_agent: str, expires_at: str) -> int:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO user_sessions
               (user_id, jwt_token_hash, ip_address, user_agent,
                is_active, expires_at, created_at)
               VALUES (?,?,?,?,1,?,?)""",
            (user_id, jwt_hash, ip_address, user_agent, expires_at, now)
        )
        return cur.lastrowid


def invalidate_session(jwt_hash: str):
    with db_cursor() as cur:
        cur.execute(
            "UPDATE user_sessions SET is_active = 0 WHERE jwt_token_hash = ?",
            (jwt_hash,)
        )


# ══════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ══════════════════════════════════════════════════════════════

def create_notification(user_id: int, message: str,
                        notif_type: str = "info",
                        threat_log_id: int = None):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO notifications
               (user_id, threat_log_id, type, message, is_read, created_at)
               VALUES (?,?,?,?,0,?)""",
            (user_id, threat_log_id, notif_type, message, now)
        )


def get_notifications(user_id: int, unread_only: bool = False) -> list:
    sql = "SELECT * FROM notifications WHERE user_id = ?"
    params = [user_id]
    if unread_only:
        sql += " AND is_read = 0"
    sql += " ORDER BY notification_id DESC"
    with db_cursor() as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


def mark_notification_read(notification_id: int):
    with db_cursor() as cur:
        cur.execute(
            "UPDATE notifications SET is_read = 1 WHERE notification_id = ?",
            (notification_id,)
        )


# ══════════════════════════════════════════════════════════════
# AUDIT LOGS
# ══════════════════════════════════════════════════════════════

def log_audit(user_id: int, action: str, resource: str,
              resource_id: str = None, details: str = None,
              ip_address: str = None, user_agent: str = None):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO audit_logs
               (user_id, action, resource, resource_id,
                details, ip_address, user_agent, created_at)
               VALUES (?,?,?,?,?,?,?,?)""",
            (user_id, action, resource, resource_id,
             details, ip_address, user_agent, now)
        )


def get_audit_logs(user_id: int = None, limit: int = 100) -> list:
    sql = "SELECT * FROM audit_logs WHERE 1=1"
    params = []
    if user_id:
        sql += " AND user_id = ?"
        params.append(user_id)
    sql += " ORDER BY audit_log_id DESC LIMIT ?"
    params.append(limit)
    with db_cursor() as cur:
        cur.execute(sql, params)
        return [dict(r) for r in cur.fetchall()]


# ══════════════════════════════════════════════════════════════
# ML
# ══════════════════════════════════════════════════════════════

def log_ml_detection(text_snippet: str, risk_score: float,
                     action: str, attack_type: str,
                     ip: str, endpoint: str):
    """للتوافق مع persistence.py القديم — يسجّل في threat_logs."""
    blocked    = action in ("block", "blocked")
    threat_id  = log_threat(
        attack_type=attack_type,
        ip_address=ip,
        endpoint=endpoint,
        method="",
        payload=text_snippet,
        severity="High" if risk_score >= 0.9 else "Medium",
        description=f"ML detection — score {risk_score:.2f}",
        blocked=blocked,
        ml_detected=True,
        confidence=risk_score,
        detection_type="ml",
    )
    if blocked:
        log_blocked_event(ip, attack_type, "High",
                          ml_detected=True, confidence=risk_score,
                          threat_log_id=threat_id)


def get_ml_detections(limit: int = 100) -> list:
    with db_cursor() as cur:
        cur.execute(
            """SELECT * FROM threat_logs
               WHERE ml_detected = 1
               ORDER BY threat_log_id DESC LIMIT ?""",
            (limit,)
        )
        return [dict(r) for r in cur.fetchall()]


def log_ml_model_run(model_version: str, algorithm: str,
                     dataset_size: int, accuracy: float,
                     precision: float, recall: float,
                     f1: float, roc_auc: float):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO ml_model_runs
               (model_version, algorithm, dataset_size,
                accuracy, precision_score, recall, f1_score,
                roc_auc, trained_at)
               VALUES (?,?,?,?,?,?,?,?,?)""",
            (model_version, algorithm, dataset_size,
             accuracy, precision, recall, f1, roc_auc, now)
        )


# ══════════════════════════════════════════════════════════════
# CHATBOT
# ══════════════════════════════════════════════════════════════

def create_chatbot_session(user_id: int, page_context: str = "") -> int:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO chatbot_sessions (user_id, page_context, started_at)
               VALUES (?,?,?)""",
            (user_id, page_context, now)
        )
        return cur.lastrowid


def save_chatbot_message(session_id: int, role: str, content: str,
                         intent: str = None):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO chatbot_messages
               (session_id, role, content, intent_detected, created_at)
               VALUES (?,?,?,?,?)""",
            (session_id, role, content, intent, now)
        )


def get_chatbot_history(session_id: int) -> list:
    with db_cursor() as cur:
        cur.execute(
            "SELECT * FROM chatbot_messages WHERE session_id = ? ORDER BY chatbot_message_id",
            (session_id,)
        )
        return [dict(r) for r in cur.fetchall()]


# ══════════════════════════════════════════════════════════════
# DEPARTMENTS
# ══════════════════════════════════════════════════════════════

def get_all_departments() -> list:
    with db_cursor() as cur:
        cur.execute("SELECT * FROM departments ORDER BY department_id")
        return [dict(r) for r in cur.fetchall()]


def create_department(name: str, slug: str, description: str = "") -> int:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute(
            "INSERT INTO departments (name, slug, description, created_at) VALUES (?,?,?,?)",
            (name, slug, description, now)
        )
        return cur.lastrowid


# ══════════════════════════════════════════════════════════════
# STATS helpers (للتوافق مع persistence.py القديم)
# ══════════════════════════════════════════════════════════════

def load_stats() -> dict:
<<<<<<< HEAD
    _ensure_rules_table()
=======
<<<<<<< HEAD
    _ensure_rules_table()
=======
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM threat_logs")
        total = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM threat_logs WHERE blocked = 1")
        blocked = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM threat_logs WHERE ml_detected = 1")
        ml = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM threat_logs WHERE attack_type LIKE '%SQL%'")
        sql_inj = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM threat_logs WHERE attack_type LIKE '%XSS%'")
        xss = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM threat_logs WHERE attack_type LIKE '%Brute%'")
        brute = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM threat_logs WHERE attack_type LIKE '%Scan%'")
        scanner = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM threat_logs WHERE attack_type LIKE '%Rate%'")
        rate = cur.fetchone()[0]
        return {
            "total_requests": total,
            "blocked_requests": blocked,
            "ml_detections": ml,
            "sql_injection_attempts": sql_inj,
            "xss_attempts": xss,
            "brute_force_attempts": brute,
            "scanner_attempts": scanner,
            "rate_limit_hits": rate,
        }




def clear_threat_logs():
    """Delete all rows from threat_logs (used by the dashboard reset action)."""
<<<<<<< HEAD
    _ensure_rules_table()
=======
<<<<<<< HEAD
    _ensure_rules_table()
=======
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
    with db_cursor() as cur:
        cur.execute("DELETE FROM threat_logs")


def save_stats(total: int, blocked: int):
    pass  # الـ stats بتتحسب live من threat_logs


# ══════════════════════════════════════════════════════════════
# ATTACK HISTORY (للتوافق مع persistence.py القديم)
# ══════════════════════════════════════════════════════════════

def append_user_attack(user_key: str, attack_type: str, ip: str,
                       endpoint: str, method: str = "", severity: str = "High"):
    # احفظ في threat_logs بدل ملف JSON
    log_threat(
        attack_type=attack_type,
        ip_address=ip,
        endpoint=endpoint,
        method=method,
        severity=severity,
        description=f"user_key={user_key}",
        detection_type="rule",
    )


def get_user_attacks(user_key: str) -> list:
    with db_cursor() as cur:
        cur.execute(
            "SELECT * FROM threat_logs WHERE description LIKE ? ORDER BY threat_log_id DESC LIMIT 500",
            (f"%user_key={user_key}%",)
        )
        return [dict(r) for r in cur.fetchall()]


def load_user_attacks() -> dict:
    rows = get_threat_logs(limit=1000)
    result = {}
    for r in rows:
        desc = r.get("description", "")
        if "user_key=" in desc:
            key = desc.split("user_key=")[-1].strip()
            result.setdefault(key, []).append(r)
    return result


def clear_user_attacks(user_key: str):
    with db_cursor() as cur:
        cur.execute(
            "DELETE FROM threat_logs WHERE description LIKE ?",
            (f"%user_key={user_key}%",)
        )


def clear_all_attacks():
    with db_cursor() as cur:
        cur.execute("DELETE FROM threat_logs")
        cur.execute("DELETE FROM blocked_events")


# ══════════════════════════════════════════════════════════════
# INDEXES (performance)
# ══════════════════════════════════════════════════════════════

def ensure_indexes():
    """Create indexes on high-traffic columns if not yet present."""
    indexes = [
        "CREATE INDEX IF NOT EXISTS idx_threat_logs_ip       ON threat_logs(ip_address)",
        "CREATE INDEX IF NOT EXISTS idx_threat_logs_type     ON threat_logs(attack_type)",
        "CREATE INDEX IF NOT EXISTS idx_threat_logs_created  ON threat_logs(created_at)",
        "CREATE INDEX IF NOT EXISTS idx_threat_logs_blocked  ON threat_logs(blocked)",
        "CREATE INDEX IF NOT EXISTS idx_users_email          ON users(email)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_jti         ON user_sessions(jwt_token_hash)",
        "CREATE INDEX IF NOT EXISTS idx_sessions_active      ON user_sessions(is_active)",
        "CREATE INDEX IF NOT EXISTS idx_login_attempts_user  ON login_attempts(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_audit_logs_user      ON audit_logs(user_id)",
        "CREATE INDEX IF NOT EXISTS idx_notifications_user   ON notifications(user_id)",
    ]
    with db_cursor() as cur:
        for sql in indexes:
            cur.execute(sql)
    logger.info("[DB] Indexes ensured")
<<<<<<< HEAD
=======
<<<<<<< HEAD
=======


# ══════════════════════════════════════════════════════════════
# SECURITY / RATE LIMITING
# ══════════════════════════════════════════════════════════════

def log_otp_request(identifier: str):
    """Log a password reset OTP request for rate limiting."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute("INSERT INTO otp_requests (identifier, requested_at) VALUES (?,?)", (identifier, now))

def get_otp_request_count(identifier: str, window_sec: int) -> int:
    """Get count of OTP requests for this identifier within the window."""
    since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - window_sec))
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM otp_requests WHERE identifier = ? AND requested_at > ?", (identifier, since))
        return cur.fetchone()[0]

def log_api_hit(key: str):
    """Log an API hit for rate limiting."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute("INSERT INTO rate_limits (key, requested_at) VALUES (?,?)", (key, now))

def get_api_hit_count(key: str, window_sec: int) -> int:
    """Get count of API hits for this key within the window."""
    since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - window_sec))
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM rate_limits WHERE key = ? AND requested_at > ?", (key, since))
        return cur.fetchone()[0]

def log_login_attempt(username: str, ip: str, success: bool, reason: str = None, user_id: int = None):
    """Log a login attempt for brute-force tracking."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO login_attempts (user_id, username, ip_address, success, failure_reason, attempted_at)
            VALUES (?,?,?,?,?,?)
        """, (user_id, username, ip, 1 if success else 0, reason, now))

def get_recent_login_failures(username: str, window_sec: int) -> int:
    """Count recent failed login attempts for this username."""
    since = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(time.time() - window_sec))
    with db_cursor() as cur:
        cur.execute("""
            SELECT COUNT(*) FROM login_attempts 
            WHERE username = ? AND success = 0 AND attempted_at > ?
        """, (username, since))
        return cur.fetchone()[0]
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
