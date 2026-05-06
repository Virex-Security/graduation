"""
Database Manager - PostgreSQL via SQLAlchemy
=============================================
All database operations via SQLAlchemy ORM/Engine.
Zero SQLite. Zero Supabase REST client.
Full backward-compatible function signatures.
"""

import os
import time
import random
import string
import logging
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.pool import QueuePool

logger = logging.getLogger(__name__)

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set in .env")

engine = create_engine(
    DATABASE_URL,
    poolclass=QueuePool,
    pool_size=5,
    max_overflow=10,
    pool_pre_ping=True,
)


def _db():
    """Return a connected connection with autocommit off."""
    conn = engine.connect()
    return conn


def _sanitize(row: dict) -> dict:
    """Convert datetime objects to ISO strings for JSON serialization."""
    import datetime
    out = {}
    for k, v in row.items():
        if isinstance(v, (datetime.datetime,)):
            out[k] = v.strftime("%Y-%m-%d %H:%M:%S")
        else:
            out[k] = v
    return out


def _sanitize_list(rows: list) -> list:
    return [_sanitize(r) for r in rows]
# ══════════════════════════════════════════════════════════════

def init_db():
    """Seed roles/users into PostgreSQL."""
    try:
        _seed_roles()
        _seed_admin()
        _seed_users()
        _seed_rules()
        _ensure_password_resets_columns()
        logger.info("[DB] Ready — PostgreSQL: %s", DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else "connected")
    except Exception as e:
        logger.warning(f"[DB] Seeding skipped — {e}")


def _seed_admin():
    """Create default admin if not exists."""
    with _db() as conn:
        exists = conn.execute(
            text("SELECT user_id FROM users WHERE username = :u"), {"u": "admin"}
        ).fetchone()
        if exists:
            return
        from werkzeug.security import generate_password_hash
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(text("""
            INSERT INTO users (username, password_hash, email, role_id, is_active, created_at, updated_at)
            VALUES ('admin', :ph, 'admin@virex.local', 1, TRUE, :now, :now)
        """), {"ph": generate_password_hash("Admin@123"), "now": now})
        conn.commit()


def _ensure_password_resets_columns():
    """Add otp_attempts column if missing."""
    with _db() as conn:
        cols = conn.execute(text("""
            SELECT column_name FROM information_schema.columns
            WHERE table_name = 'password_resets'
        """)).mappings().all()
        col_names = [c["column_name"] for c in cols]
        if "otp_attempts" not in col_names:
            conn.execute(text("ALTER TABLE password_resets ADD COLUMN otp_attempts INTEGER DEFAULT 0"))
            conn.commit()


def _seed_roles():
    with _db() as conn:
        count = conn.execute(text("SELECT COUNT(*) FROM roles")).scalar()
        if count > 0:
            return
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        for name, desc in [
            ("admin",   "Full system access"),
            ("user",    "Standard access"),
            ("analyst", "Read-only + reports"),
            ("manager", "Team management"),
        ]:
            conn.execute(text(
                "INSERT INTO roles (name, description, created_at) VALUES (:name, :desc, :now)"
            ), {"name": name, "desc": desc, "now": now})
        conn.commit()


def _seed_users():
    import json
    users_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "users.json")
    if not os.path.exists(users_file):
        return
    with open(users_file, encoding="utf-8") as f:
        users_json = json.load(f)
    with _db() as conn:
        for username, u in users_json.items():
            exists = conn.execute(
                text("SELECT user_id FROM users WHERE username = :u"), {"u": username}
            ).fetchone()
            if exists:
                continue
            role_name = u.get("role", "user")
            role_row = conn.execute(
                text("SELECT role_id FROM roles WHERE name = :n"), {"n": role_name}
            ).fetchone()
            role_id = role_row[0] if role_row else 2
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            conn.execute(text("""
                INSERT INTO users
                    (username, password_hash, email, role_id, is_active, created_at, updated_at)
                VALUES (:username, :ph, :email, :role_id, TRUE, :now, :now)
            """), {
                "username": username,
                "ph": u.get("password_hash", ""),
                "email": u.get("email", f"{username}@example.com"),
                "role_id": role_id,
                "now": now,
            })
        conn.commit()


def _seed_rules():
    with _db() as conn:
        count = conn.execute(text("SELECT COUNT(*) FROM rules")).scalar()
        if count > 0:
            return
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        default_rules = [
            ("SQL Injection - UNION",       "sql_injection",    r"UNION\s+SELECT",                              "high",     "block"),
            ("SQL Injection - Keywords",    "sql_injection",    r"(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)",    "high",     "block"),
            ("SQL Injection - Comment",     "sql_injection",    r"(--|#|/\*|;|@@)",                             "high",     "block"),
            ("SQL Injection - OR/AND",      "sql_injection",    r"(\bOR\b|\bAND\b).+(=|LIKE|IN)",              "high",     "block"),
            ("XSS - Script Tag",            "xss",              r"<script.*?>.*?</script>",                     "high",     "block"),
            ("XSS - JavaScript Protocol",   "xss",              r"javascript:",                                 "high",     "block"),
            ("XSS - Event Handler",         "xss",              r"(onerror|onload|onclick)\s*=",                "high",     "block"),
            ("XSS - Alert",                 "xss",              r"alert\(.*\)",                                 "medium",   "block"),
            ("Command Injection - Pipe",    "command_injection", r"(;|\|{1,2}|&&|`)[\s\S]*(cat|ls|rm|wget|curl|nc|bash|sh)", "critical","block"),
            ("Command Injection - Subshell","command_injection", r"\$\(.*\)",                                   "critical", "block"),
            ("Path Traversal - Dotdot",     "path_traversal",   r"\.\.[/\\]",                                  "high",     "block"),
            ("Path Traversal - Encoded",    "path_traversal",   r"%2e%2e[%2f%5c]",                             "high",     "block"),
            ("Path Traversal - Sensitive",  "path_traversal",   r"(etc/passwd|etc/shadow|windows/system32)",   "critical", "block"),
        ]
        for name, rtype, pattern, severity, action in default_rules:
            conn.execute(text("""
                INSERT INTO rules (name, type, pattern, severity, action, is_active, created_at)
                VALUES (:name, :type, :pattern, :severity, :action, TRUE, :now)
            """), {"name": name, "type": rtype, "pattern": pattern, "severity": severity, "action": action, "now": now})
        conn.commit()


_seed_rules_table = _seed_rules


# ══════════════════════════════════════════════════════════════
# USERS
# ══════════════════════════════════════════════════════════════

def get_all_users() -> list:
    with _db() as conn:
        rows = conn.execute(text("""
            SELECT u.*, r.name AS role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.role_id
            ORDER BY u.user_id
        """)).mappings().all()
        return _sanitize_list(rows)


def get_user_by_username(username: str) -> dict | None:
    with _db() as conn:
        row = conn.execute(text("""
            SELECT u.*, r.name AS role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.role_id
            WHERE u.username = :username
        """), {"username": username}).mappings().fetchone()
        return _sanitize(dict(row)) if row else None


def get_user_by_id(user_id) -> dict | None:
    with _db() as conn:
        row = conn.execute(text("""
            SELECT u.*, r.name AS role_name
            FROM users u
            LEFT JOIN roles r ON u.role_id = r.role_id
            WHERE u.user_id = :user_id
        """), {"user_id": user_id}).mappings().fetchone()
        return _sanitize(dict(row)) if row else None


def get_user_by_email(email: str) -> dict | None:
    with _db() as conn:
        row = conn.execute(text("SELECT * FROM users WHERE email = :email"), {"email": email}).mappings().fetchone()
        return _sanitize(dict(row)) if row else None


def insert_user(username, password_hash, email=None,
                role="user", department_id=None) -> int:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        role_row = conn.execute(
            text("SELECT role_id FROM roles WHERE name = :role"), {"role": role}
        ).mappings().fetchone()
        role_id = role_row["role_id"] if role_row else 2
        result = conn.execute(text("""
            INSERT INTO users
                (username, password_hash, email, role_id, department_id, is_active, created_at, updated_at)
            VALUES (:username, :ph, :email, :role_id, :dept, TRUE, :now, :now)
            RETURNING user_id
        """), {
            "username": username,
            "ph": password_hash,
            "email": email or f"{username}@example.com",
            "role_id": role_id,
            "dept": department_id,
            "now": now,
        })
        conn.commit()
        return result.scalar()


def update_user(username: str, **kwargs) -> bool:
    allowed = {"email", "password_hash", "role_id", "department_id",
               "is_active", "last_login", "updated_at",
               "reset_token", "reset_token_expiry"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return False
    fields["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    sets = ", ".join(f"{k} = :{k}" for k in fields)
    params = dict(fields, username=username)
    with _db() as conn:
        result = conn.execute(text(
            f"UPDATE users SET {sets} WHERE username = :username"
        ), params)
        conn.commit()
        return result.rowcount > 0


def delete_user(username: str) -> bool:
    with _db() as conn:
        result = conn.execute(text("DELETE FROM users WHERE username = :username"), {"username": username})
        conn.commit()
        return result.rowcount > 0


# ══════════════════════════════════════════════════════════════
# ROLES
# ══════════════════════════════════════════════════════════════

def get_all_roles() -> list:
    with _db() as conn:
        rows = conn.execute(text("SELECT * FROM roles ORDER BY role_id")).mappings().all()
        return _sanitize_list(rows)


# ══════════════════════════════════════════════════════════════
# DEPARTMENTS
# ══════════════════════════════════════════════════════════════

def get_all_departments() -> list:
    with _db() as conn:
        rows = conn.execute(text("SELECT * FROM departments ORDER BY department_id")).mappings().all()
        return _sanitize_list(rows)


def create_department(name: str, slug: str, description: str = "") -> int:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        result = conn.execute(text("""
            INSERT INTO departments (name, slug, description, created_at)
            VALUES (:name, :slug, :desc, :now)
            RETURNING department_id
        """), {"name": name, "slug": slug, "desc": description, "now": now})
        conn.commit()
        return result.scalar()


# ══════════════════════════════════════════════════════════════
# THREAT LOGS
# ══════════════════════════════════════════════════════════════

def log_threat(attack_type: str, ip_address: str, endpoint: str,
               method: str = "", payload: str = "",
               severity: str = "Medium", description: str = "",
               blocked: bool = False, ml_detected: bool = False,
               confidence: float = 0.0, detection_type: str = "rule") -> int:
    _invalidate_caches()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        result = conn.execute(text("""
            INSERT INTO threat_logs
                (attack_type, ip_address, endpoint, method, payload, severity,
                 description, blocked, ml_detected, confidence, detection_type, created_at)
            VALUES (:at, :ip, :ep, :method, :payload, :sev,
                    :desc, :blocked, :ml, :conf, :dt, :now)
            RETURNING threat_log_id
        """), {
            "at": attack_type, "ip": ip_address, "ep": endpoint,
            "method": method, "payload": (payload or "")[:500],
            "sev": severity, "desc": description,
            "blocked": bool(blocked), "ml": bool(ml_detected),
            "conf": round(confidence, 4), "dt": detection_type, "now": now,
        })
        conn.commit()
        return result.scalar()


def get_threat_logs(limit: int = 100, attack_type: str = None,
                    severity: str = None) -> list:
    sql = "SELECT * FROM threat_logs WHERE 1=1"
    params = {}
    if attack_type:
        sql += " AND attack_type = :attack_type"
        params["attack_type"] = attack_type
    if severity:
        sql += " AND severity = :severity"
        params["severity"] = severity
    sql += " ORDER BY threat_log_id DESC LIMIT :lim"
    params["lim"] = limit
    with _db() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
        return _sanitize_list(rows)


def clear_threat_logs():
    with _db() as conn:
        conn.execute(text("DELETE FROM threat_logs"))
        conn.commit()


# ══════════════════════════════════════════════════════════════
# BLOCKED IPS
# ══════════════════════════════════════════════════════════════

def load_blocked_ips() -> dict:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        conn.execute(text("DELETE FROM blocked_ips WHERE is_permanent = FALSE AND unblock_at <= :now"), {"now": now})
        conn.commit()
        rows = conn.execute(text("SELECT ip_address, unblock_at FROM blocked_ips")).mappings().all()
    result = {}
    for r in rows:
        unblock = r.get("unblock_at", "")
        if unblock:
            try:
                ts = time.mktime(time.strptime(unblock, "%Y-%m-%d %H:%M:%S"))
            except Exception:
                ts = float("inf")
        else:
            ts = float("inf")
        result[r["ip_address"]] = ts
    return result


def save_blocked_ips(blocked: dict):
    now_ts = time.time()
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        conn.execute(text("DELETE FROM blocked_ips WHERE is_permanent = FALSE"))
        for ip, unblock_ts in blocked.items():
            if unblock_ts > now_ts:
                unblock_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(unblock_ts))
                conn.execute(text("""
                    INSERT INTO blocked_ips (ip_address, reason, is_permanent, blocked_at, unblock_at)
                    VALUES (:ip, 'auto-block', FALSE, :now, :unblock)
                    ON CONFLICT (ip_address) DO UPDATE SET
                        reason = EXCLUDED.reason, is_permanent = EXCLUDED.is_permanent,
                        blocked_at = EXCLUDED.blocked_at, unblock_at = EXCLUDED.unblock_at
                """), {"ip": ip, "now": now_str, "unblock": unblock_str})
        conn.commit()


def block_ip(ip: str, unblock_at: str = None, reason: str = "auto-block",
             blocked_by: int = None, is_permanent: bool = False):
    now_str = time.strftime("%Y-%m-%d %H:%M:%S")
    if isinstance(unblock_at, (int, float)):
        unblock_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(unblock_at))
    else:
        unblock_str = unblock_at or now_str
    with _db() as conn:
        conn.execute(text("""
            INSERT INTO blocked_ips (ip_address, reason, blocked_by, is_permanent, blocked_at, unblock_at)
            VALUES (:ip, :reason, :by, :perm, :now, :unblock)
            ON CONFLICT (ip_address) DO UPDATE SET
                reason = EXCLUDED.reason, blocked_by = EXCLUDED.blocked_by,
                is_permanent = EXCLUDED.is_permanent, blocked_at = EXCLUDED.blocked_at,
                unblock_at = EXCLUDED.unblock_at
        """), {
            "ip": ip, "reason": reason, "by": blocked_by,
            "perm": bool(is_permanent), "now": now_str, "unblock": unblock_str,
        })
        conn.commit()


def unblock_ip(ip: str):
    with _db() as conn:
        conn.execute(text("DELETE FROM blocked_ips WHERE ip_address = :ip"), {"ip": ip})
        conn.commit()


# ══════════════════════════════════════════════════════════════
# BLOCKED EVENTS
# ══════════════════════════════════════════════════════════════

def log_blocked_event(ip_address: str, attack_type: str, severity: str,
                      ml_detected: bool = False, confidence: float = 0.0,
                      threat_log_id: int = None):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        conn.execute(text("""
            INSERT INTO blocked_events
                (threat_log_id, ip_address, attack_type, severity, ml_detected, confidence, blocked_at)
            VALUES (:tl, :ip, :at, :sev, :ml, :conf, :now)
        """), {
            "tl": threat_log_id, "ip": ip_address, "at": attack_type,
            "sev": severity, "ml": bool(ml_detected),
            "conf": round(confidence, 4), "now": now,
        })
        conn.commit()


def get_blocked_events(limit: int = 100) -> list:
    with _db() as conn:
        rows = conn.execute(text(
            "SELECT * FROM blocked_events ORDER BY blocked_event_id DESC LIMIT :lim"
        ), {"lim": limit}).mappings().all()
        return _sanitize_list(rows)


# ══════════════════════════════════════════════════════════════
# INCIDENTS
# ══════════════════════════════════════════════════════════════

def create_incident(category: str, source_ip: str, severity: str,
                    detection_type: str = "rule") -> int:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    code = "INC-" + "".join(random.choices(string.digits, k=6))
    with _db() as conn:
        result = conn.execute(text("""
            INSERT INTO incidents
                (incident_code, category, source_ip, detection_type, status, severity,
                 first_seen, last_seen, created_at)
            VALUES (:code, :cat, :ip, :dt, 'open', :sev, :now, :now, :now)
            RETURNING incident_id
        """), {
            "code": code, "cat": category, "ip": source_ip,
            "dt": detection_type, "sev": severity, "now": now,
        })
        conn.commit()
        return result.scalar()


def get_incidents(status: str = None, limit: int = 100) -> list:
    sql = "SELECT * FROM incidents WHERE 1=1"
    params = {}
    if status:
        sql += " AND status = :status"
        params["status"] = status
    sql += " ORDER BY incident_id DESC LIMIT :lim"
    params["lim"] = limit
    with _db() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
        return _sanitize_list(rows)


def update_incident_status(incident_id: int, new_status: str,
                           actor_id: int = None, comment: str = ""):
    with _db() as conn:
        old = conn.execute(
            text("SELECT status FROM incidents WHERE incident_id = :id"), {"id": incident_id}
        ).mappings().fetchone()
        if not old:
            return False
        old_status = old["status"]
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        conn.execute(text("""
            UPDATE incidents SET status = :ns, last_seen = :now WHERE incident_id = :id
        """), {"ns": new_status, "now": now, "id": incident_id})
        conn.execute(text("""
            INSERT INTO incident_actions
                (incident_id, actor_id, action, comment, previous_status, new_status, created_at)
            VALUES (:id, :actor, 'status_change', :comment, :old, :new, :now)
        """), {
            "id": incident_id, "actor": actor_id, "comment": comment,
            "old": old_status, "new": new_status, "now": now,
        })
        conn.commit()
        return True


# ══════════════════════════════════════════════════════════════
# LOGIN ATTEMPTS
# ══════════════════════════════════════════════════════════════

def log_login_attempt(user_id: int, ip_address: str,
                      success: bool, failure_reason: str = None):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        conn.execute(text("""
            INSERT INTO login_attempts (user_id, ip_address, success, failure_reason, attempted_at)
            VALUES (:uid, :ip, :succ, :fr, :now)
        """), {
            "uid": user_id, "ip": ip_address, "succ": bool(success),
            "fr": failure_reason, "now": now,
        })
        conn.commit()


def get_login_attempts(user_id: int = None, limit: int = 50) -> list:
    sql = "SELECT * FROM login_attempts WHERE 1=1"
    params = {}
    if user_id:
        sql += " AND user_id = :uid"
        params["uid"] = user_id
    sql += " ORDER BY login_attempt_id DESC LIMIT :lim"
    params["lim"] = limit
    with _db() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
        return _sanitize_list(rows)


# ══════════════════════════════════════════════════════════════
# USER SESSIONS
# ══════════════════════════════════════════════════════════════

def create_session(user_id: int, jwt_hash: str, ip_address: str,
                   user_agent: str, expires_at: str) -> int:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        result = conn.execute(text("""
            INSERT INTO user_sessions
                (user_id, jwt_token_hash, ip_address, user_agent, is_active, expires_at, created_at)
            VALUES (:uid, :jti, :ip, :ua, TRUE, :exp, :now)
            RETURNING session_id
        """), {
            "uid": user_id, "jti": jwt_hash, "ip": ip_address,
            "ua": user_agent, "exp": expires_at, "now": now,
        })
        conn.commit()
        return result.scalar()


def invalidate_session(jwt_hash: str):
    with _db() as conn:
        conn.execute(text(
            "UPDATE user_sessions SET is_active = FALSE WHERE jwt_token_hash = :jti"
        ), {"jti": jwt_hash})
        conn.commit()


def is_session_active(jwt_hash: str) -> bool:
    with _db() as conn:
        row = conn.execute(text(
            "SELECT is_active FROM user_sessions WHERE jwt_token_hash = :jti LIMIT 1"
        ), {"jti": jwt_hash}).mappings().fetchone()
        if not row:
            return False
        return bool(row["is_active"])


# ══════════════════════════════════════════════════════════════
# NOTIFICATIONS
# ══════════════════════════════════════════════════════════════

def create_notification(user_id: int, message: str,
                        notif_type: str = "info",
                        threat_log_id: int = None):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        conn.execute(text("""
            INSERT INTO notifications (user_id, threat_log_id, type, message, is_read, created_at)
            VALUES (:uid, :tl, :nt, :msg, FALSE, :now)
        """), {
            "uid": user_id, "tl": threat_log_id, "nt": notif_type,
            "msg": message, "now": now,
        })
        conn.commit()


def get_notifications(user_id: int, unread_only: bool = False) -> list:
    sql = "SELECT * FROM notifications WHERE user_id = :uid"
    params = {"uid": user_id}
    if unread_only:
        sql += " AND is_read = FALSE"
    sql += " ORDER BY notification_id DESC"
    with _db() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
        return _sanitize_list(rows)


def mark_notification_read(notification_id: int):
    with _db() as conn:
        conn.execute(text(
            "UPDATE notifications SET is_read = TRUE WHERE notification_id = :id"
        ), {"id": notification_id})
        conn.commit()


# ══════════════════════════════════════════════════════════════
# AUDIT LOGS
# ══════════════════════════════════════════════════════════════

def log_audit(user_id: int, action: str, resource: str,
              resource_id: str = None, details: str = None,
              ip_address: str = None, user_agent: str = None):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        conn.execute(text("""
            INSERT INTO audit_logs
                (user_id, action, resource, resource_id, details, ip_address, user_agent, created_at)
            VALUES (:uid, :act, :res, :rid, :det, :ip, :ua, :now)
        """), {
            "uid": user_id, "act": action, "res": resource,
            "rid": resource_id, "det": details,
            "ip": ip_address, "ua": user_agent, "now": now,
        })
        conn.commit()


def get_audit_logs(user_id: int = None, limit: int = 100) -> list:
    sql = "SELECT * FROM audit_logs WHERE 1=1"
    params = {}
    if user_id:
        sql += " AND user_id = :uid"
        params["uid"] = user_id
    sql += " ORDER BY audit_log_id DESC LIMIT :lim"
    params["lim"] = limit
    with _db() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
        return _sanitize_list(rows)


# ══════════════════════════════════════════════════════════════
# ML
# ══════════════════════════════════════════════════════════════

def log_ml_detection(text_snippet: str, risk_score: float,
                     action: str, attack_type: str,
                     ip: str, endpoint: str):
    blocked = action in ("block", "blocked")
    threat_id = log_threat(
        attack_type=attack_type, ip_address=ip, endpoint=endpoint,
        method="", payload=text_snippet,
        severity="High" if risk_score >= 0.9 else "Medium",
        description=f"ML detection — score {risk_score:.2f}",
        blocked=blocked, ml_detected=True, confidence=risk_score,
        detection_type="ml",
    )
    if blocked:
        log_blocked_event(ip, attack_type, "High",
                          ml_detected=True, confidence=risk_score,
                          threat_log_id=threat_id)


def get_ml_detections(limit: int = 100) -> list:
    with _db() as conn:
        rows = conn.execute(text("""
            SELECT * FROM threat_logs WHERE ml_detected = TRUE
            ORDER BY threat_log_id DESC LIMIT :lim
        """), {"lim": limit}).mappings().all()
        return _sanitize_list(rows)


def log_ml_model_run(model_version: str, algorithm: str,
                     dataset_size: int, accuracy: float,
                     precision: float, recall: float,
                     f1: float, roc_auc: float):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        conn.execute(text("""
            INSERT INTO ml_model_runs
                (model_version, algorithm, dataset_size, accuracy,
                 precision_score, recall, f1_score, roc_auc, trained_at)
            VALUES (:mv, :alg, :ds, :acc, :prec, :rec, :f1, :roc, :now)
        """), {
            "mv": model_version, "alg": algorithm, "ds": dataset_size,
            "acc": accuracy, "prec": precision, "rec": recall,
            "f1": f1, "roc": roc_auc, "now": now,
        })
        conn.commit()


# ══════════════════════════════════════════════════════════════
# CHATBOT
# ══════════════════════════════════════════════════════════════

def create_chatbot_session(user_id: int, page_context: str = "") -> int:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        result = conn.execute(text("""
            INSERT INTO chatbot_sessions (user_id, page_context, started_at)
            VALUES (:uid, :pc, :now)
            RETURNING chatbot_session_id
        """), {"uid": user_id, "pc": page_context, "now": now})
        conn.commit()
        return result.scalar()


def save_chatbot_message(session_id: int, role: str, content: str,
                         intent: str = None):
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        conn.execute(text("""
            INSERT INTO chatbot_messages (session_id, role, content, intent_detected, created_at)
            VALUES (:sid, :role, :content, :intent, :now)
        """), {
            "sid": session_id, "role": role, "content": content,
            "intent": intent, "now": now,
        })
        conn.commit()


def get_chatbot_history(session_id: int) -> list:
    with _db() as conn:
        rows = conn.execute(text("""
            SELECT * FROM chatbot_messages WHERE session_id = :sid
            ORDER BY chatbot_message_id
        """), {"sid": session_id}).mappings().all()
        return _sanitize_list(rows)


# ══════════════════════════════════════════════════════════════
# RULES / WAF
# ══════════════════════════════════════════════════════════════

def get_rules(active_only: bool = True) -> list:
    sql = "SELECT * FROM rules"
    if active_only:
        sql += " WHERE is_active = TRUE"
    sql += " ORDER BY rule_id"
    with _db() as conn:
        rows = conn.execute(text(sql)).mappings().all()
        return _sanitize_list(rows)


# ══════════════════════════════════════════════════════════════
# ORDERS & PRODUCTS
# ══════════════════════════════════════════════════════════════

def get_orders(user_filter=None) -> list:
    sql = "SELECT * FROM orders WHERE 1=1"
    params = {}
    if user_filter:
        sql += " AND username = :user"
        params["user"] = user_filter
    sql += " ORDER BY created_at DESC LIMIT 500"
    with _db() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
        return _sanitize_list(rows)


def create_order(user, product, price) -> dict:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        result = conn.execute(text("""
            INSERT INTO orders (username, product, price, created_at)
            VALUES (:user, :product, :price, :now)
            RETURNING *
        """), {"user": user, "product": product, "price": price, "now": now})
        conn.commit()
        row = result.mappings().fetchone()
        return _sanitize(dict(row)) if row else {}


def get_products(category=None, search=None) -> list:
    sql = "SELECT * FROM products WHERE 1=1"
    params = {}
    if category:
        sql += " AND category = :cat"
        params["cat"] = category
    sql += " ORDER BY created_at DESC LIMIT 500"
    with _db() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
        results = _sanitize_list(rows)
    if search:
        q = search.lower()
        results = [p for p in results
                   if q in p.get("name", "").lower()
                   or q in p.get("description", "").lower()]
    return results


# ══════════════════════════════════════════════════════════════
# STATS
# ══════════════════════════════════════════════════════════════

_stats_cache = None
_stats_cache_time = 0
_stats_cache_ttl = 10

def _invalidate_caches():
    global _stats_cache, _stats_cache_time
    _stats_cache = None
    _stats_cache_time = 0

def load_stats() -> dict:
    global _stats_cache, _stats_cache_time
    now = time.time()
    if _stats_cache and (now - _stats_cache_time) < _stats_cache_ttl:
        return _stats_cache
    with _db() as conn:
        row = conn.execute(text("""
            SELECT
                COUNT(*) AS total,
                SUM(CASE WHEN blocked = TRUE THEN 1 ELSE 0 END) AS blocked,
                SUM(CASE WHEN ml_detected = TRUE THEN 1 ELSE 0 END) AS ml,
                SUM(CASE WHEN attack_type ILIKE '%sql%' THEN 1 ELSE 0 END) AS sqli,
                SUM(CASE WHEN attack_type ILIKE '%xss%' THEN 1 ELSE 0 END) AS xss,
                SUM(CASE WHEN attack_type ILIKE '%brute%' THEN 1 ELSE 0 END) AS brute,
                SUM(CASE WHEN attack_type ILIKE '%scanner%' OR attack_type = 'Scanner' THEN 1 ELSE 0 END) AS scanner,
                SUM(CASE WHEN attack_type ILIKE '%rate%' OR attack_type = 'Rate Limit Exceeded' THEN 1 ELSE 0 END) AS rate_limit,
                SUM(CASE WHEN attack_type ILIKE '%csrf%' OR attack_type = 'CSRF' THEN 1 ELSE 0 END) AS csrf,
                SUM(CASE WHEN attack_type ILIKE '%ssrf%' OR attack_type = 'SSRF' THEN 1 ELSE 0 END) AS ssrf,
                SUM(CASE WHEN attack_type ILIKE '%command%' OR attack_type ILIKE '%cmd%' THEN 1 ELSE 0 END) AS cmd_injection,
                SUM(CASE WHEN attack_type ILIKE '%path%' OR attack_type ILIKE '%traversal%' THEN 1 ELSE 0 END) AS path_traversal,
                SUM(CASE WHEN attack_type ILIKE '%xxe%' THEN 1 ELSE 0 END) AS xxe,
                SUM(CASE WHEN attack_type ILIKE '%ssti%' THEN 1 ELSE 0 END) AS ssti,
                SUM(CASE WHEN attack_type ILIKE '%log4shell%' OR attack_type ILIKE '%jndi%' THEN 1 ELSE 0 END) AS log4shell
            FROM threat_logs
        """)).fetchone()
    result = {
        "total_requests": row[0] or 0, "blocked_requests": row[1] or 0,
        "ml_detections": row[2] or 0, "sql_injection_attempts": row[3] or 0,
        "xss_attempts": row[4] or 0, "brute_force_attempts": row[5] or 0,
        "scanner_attempts": row[6] or 0, "rate_limit_hits": row[7] or 0,
        "csrf_attempts": row[8] or 0, "ssrf_attempts": row[9] or 0,
        "cmd_injection_attempts": row[10] or 0, "path_traversal_attempts": row[11] or 0,
        "xxe_attempts": row[12] or 0, "ssti_attempts": row[13] or 0,
        "log4shell_attempts": row[14] or 0,
    }
    _stats_cache = result
    _stats_cache_time = now
    return result


def save_stats(total: int, blocked: int):
    pass


# ══════════════════════════════════════════════════════════════
# ATTACK HISTORY
# ══════════════════════════════════════════════════════════════

def append_user_attack(user_key: str, attack_type: str, ip: str,
                       endpoint: str, method: str = "", severity: str = "High"):
    _invalidate_caches()
    log_threat(
        attack_type=attack_type, ip_address=ip, endpoint=endpoint,
        method=method, severity=severity,
        description=f"user_key={user_key}", detection_type="rule",
    )


def get_user_attacks(user_key: str) -> list:
    with _db() as conn:
        rows = conn.execute(text("""
            SELECT * FROM threat_logs
            WHERE description LIKE :pattern
            ORDER BY threat_log_id DESC LIMIT 500
        """), {"pattern": f"%user_key={user_key}%"}).mappings().all()
        return _sanitize_list(rows)


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
    with _db() as conn:
        conn.execute(text(
            "DELETE FROM threat_logs WHERE description LIKE :pattern"
        ), {"pattern": f"%user_key={user_key}%"})
        conn.commit()


def clear_all_attacks():
    with _db() as conn:
        conn.execute(text("DELETE FROM threat_logs"))
        conn.execute(text("DELETE FROM blocked_events"))
        conn.commit()


# ══════════════════════════════════════════════════════════════
# PASSWORD RESETS (OTP)
# ══════════════════════════════════════════════════════════════

def create_password_reset(user_id: int, otp_hash: str, otp_expiry: str):
    with _db() as conn:
        conn.execute(text("DELETE FROM password_resets WHERE user_id = :uid"), {"uid": user_id})
        conn.execute(text("""
            INSERT INTO password_resets (user_id, otp, otp_expiry, used, otp_attempts)
            VALUES (:uid, :otp, :exp, FALSE, 0)
        """), {"uid": user_id, "otp": otp_hash, "exp": otp_expiry})
        conn.commit()


def get_active_password_reset(user_id: int) -> dict | None:
    with _db() as conn:
        row = conn.execute(text("""
            SELECT * FROM password_resets WHERE user_id = :uid AND used = FALSE LIMIT 1
        """), {"uid": user_id}).mappings().fetchone()
        return _sanitize(dict(row)) if row else None


def increment_otp_attempts(user_id: int):
    with _db() as conn:
        conn.execute(text("""
            UPDATE password_resets SET otp_attempts = COALESCE(otp_attempts, 0) + 1
            WHERE user_id = :uid AND used = FALSE
        """), {"uid": user_id})
        conn.commit()


def reset_otp_attempts(user_id: int):
    with _db() as conn:
        conn.execute(text("""
            UPDATE password_resets SET otp_attempts = 0
            WHERE user_id = :uid AND used = FALSE
        """), {"uid": user_id})
        conn.commit()


def mark_password_reset_used(user_id: int):
    with _db() as conn:
        conn.execute(text("""
            UPDATE password_resets SET used = TRUE, otp_attempts = 0
            WHERE user_id = :uid
        """), {"uid": user_id})
        conn.commit()
