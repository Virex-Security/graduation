"""
Database Manager — SQLite + PostgreSQL via SQLAlchemy
======================================================
Supports both SQLite (development / benchmark) and PostgreSQL (production).
Dialect is detected automatically from DATABASE_URL.

All database operations use SQLAlchemy core (text() queries).
Zero Supabase REST client dependency.
Full backward-compatible function signatures.

SQLite notes
------------
* RETURNING is emulated via cursor.lastrowid (see _insert_returning).
* ILIKE replaced with LIKE (SQLite LIKE is case-insensitive for ASCII).
* information_schema replaced with PRAGMA table_info().
* ON CONFLICT … DO UPDATE requires PRIMARY KEY / UNIQUE on the column —
  which is satisfied by the schema (metric_name is PK in system_stats,
  ip_address is PK in blocked_ips).
* Pool: NullPool is used for SQLite (no multi-threaded pooling needed).
"""

import os
import time
import random
import string
import logging
from dotenv import load_dotenv
from sqlalchemy import create_engine, text
from sqlalchemy.pool import QueuePool, NullPool

logger = logging.getLogger(__name__)

load_dotenv()

DATABASE_URL = os.getenv("DATABASE_URL")
if not DATABASE_URL:
    raise RuntimeError("DATABASE_URL not set in .env")

# ── Dialect detection ──────────────────────────────────────────
_IS_SQLITE = DATABASE_URL.startswith("sqlite")

# ── Engine ────────────────────────────────────────────────────
if _IS_SQLITE:
    # SQLite: use NullPool; check_same_thread=False for Flask multi-thread
    engine = create_engine(
        DATABASE_URL,
        poolclass=NullPool,
        connect_args={"check_same_thread": False},
    )
else:
    engine = create_engine(
        DATABASE_URL,
        poolclass=QueuePool,
        pool_size=5,
        max_overflow=10,
        pool_pre_ping=True,
    )


def _db():
    """Return a connected SQLAlchemy connection."""
    return engine.connect()


# ── SQL helpers ────────────────────────────────────────────────

def _insert_returning(conn, sql: str, params: dict, pk_col: str = "id"):
    """
    Execute an INSERT and return the new primary-key value.

    * PostgreSQL: use RETURNING clause natively.
    * SQLite:     strip RETURNING clause; return cursor.lastrowid.

    The SQL string must end with:
        RETURNING <pk_col>
    """
    if _IS_SQLITE:
        # Strip the RETURNING clause (case-insensitive, trailing whitespace)
        import re
        clean_sql = re.sub(
            r"\s+RETURNING\s+\S+\s*$", "", sql.strip(), flags=re.IGNORECASE
        )
        result = conn.execute(text(clean_sql), params)
        return result.lastrowid
    else:
        result = conn.execute(text(sql), params)
        return result.scalar()


def _like(col: str) -> str:
    """
    Return the correct LIKE operator for the dialect.
    PostgreSQL supports ILIKE for case-insensitive matching.
    SQLite's LIKE is case-insensitive for ASCII by default.
    """
    return "LIKE" if _IS_SQLITE else "ILIKE"


def _bool(val: bool) -> object:
    """Return the correct boolean literal for the dialect."""
    if _IS_SQLITE:
        return 1 if val else 0
    return val


def _sanitize(row: dict) -> dict:
    """Convert datetime objects to ISO strings for JSON serialization."""
    import datetime
    out = {}
    for k, v in row.items():
        if isinstance(v, datetime.datetime):
            out[k] = v.strftime("%Y-%m-%d %H:%M:%S")
        else:
            out[k] = v
    return out


def _sanitize_list(rows: list) -> list:
    return [_sanitize(r) for r in rows]


# ══════════════════════════════════════════════════════════════
# SCHEMA CREATION (idempotent — safe to run multiple times)
# ══════════════════════════════════════════════════════════════

# Full DDL — compatible with both SQLite and PostgreSQL.
# PostgreSQL ignores the INTEGER autoincrement style but SQLAlchemy
# handles the type affinity correctly through the ORM layer.
# For fresh PostgreSQL deployments use db_init/init.sql instead.

_CREATE_TABLES_SQL = [
    # roles (must be created before users)
    """
    CREATE TABLE IF NOT EXISTS roles (
        role_id INTEGER PRIMARY KEY,
        name VARCHAR(50) UNIQUE NOT NULL,
        description TEXT,
        created_at VARCHAR(50)
    )
    """,
    # departments (must be created before users)
    """
    CREATE TABLE IF NOT EXISTS departments (
        department_id INTEGER PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        slug VARCHAR(100) UNIQUE NOT NULL,
        description TEXT,
        created_at VARCHAR(50)
    )
    """,
    # users
    """
    CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY,
        username VARCHAR(50) UNIQUE NOT NULL,
        password_hash VARCHAR(255) NOT NULL,
        email VARCHAR(100) UNIQUE,
        role_id INTEGER REFERENCES roles(role_id),
        department_id INTEGER REFERENCES departments(department_id),
        is_active INTEGER DEFAULT 1,
        created_at VARCHAR(50),
        updated_at VARCHAR(50),
        last_login VARCHAR(50),
        reset_token VARCHAR(255),
        reset_token_expiry VARCHAR(50)
    )
    """,
    # rate_limits
    """
    CREATE TABLE IF NOT EXISTS rate_limits (
        id INTEGER PRIMARY KEY,
        ip_address VARCHAR(45) NOT NULL,
        timestamp REAL NOT NULL
    )
    """,
    # system_stats — metric_name is PK → enables ON CONFLICT upsert
    """
    CREATE TABLE IF NOT EXISTS system_stats (
        metric_name VARCHAR(100) PRIMARY KEY,
        metric_value INTEGER NOT NULL,
        updated_at VARCHAR(50) DEFAULT CURRENT_TIMESTAMP
    )
    """,
    # rules
    """
    CREATE TABLE IF NOT EXISTS rules (
        rule_id INTEGER PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        type VARCHAR(50) NOT NULL,
        pattern TEXT NOT NULL,
        severity VARCHAR(20) NOT NULL,
        action VARCHAR(20) NOT NULL,
        is_active INTEGER DEFAULT 1,
        created_at VARCHAR(50),
        updated_at VARCHAR(50)
    )
    """,
    # threat_logs
    """
    CREATE TABLE IF NOT EXISTS threat_logs (
        threat_log_id INTEGER PRIMARY KEY,
        attack_type VARCHAR(100) NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        endpoint VARCHAR(255) NOT NULL,
        method VARCHAR(10) NOT NULL,
        payload TEXT,
        severity VARCHAR(20) NOT NULL,
        description TEXT,
        blocked INTEGER NOT NULL,
        ml_detected INTEGER DEFAULT 0,
        confidence REAL DEFAULT 0.0,
        detection_type VARCHAR(50) DEFAULT 'rule',
        created_at VARCHAR(50)
    )
    """,
    # blocked_ips — ip_address is PK → enables ON CONFLICT upsert
    """
    CREATE TABLE IF NOT EXISTS blocked_ips (
        ip_address VARCHAR(45) PRIMARY KEY,
        reason TEXT,
        blocked_by INTEGER REFERENCES users(user_id),
        is_permanent INTEGER DEFAULT 0,
        blocked_at VARCHAR(50),
        unblock_at VARCHAR(50)
    )
    """,
    # blocked_events
    """
    CREATE TABLE IF NOT EXISTS blocked_events (
        blocked_event_id INTEGER PRIMARY KEY,
        threat_log_id INTEGER REFERENCES threat_logs(threat_log_id) ON DELETE CASCADE,
        ip_address VARCHAR(45) NOT NULL,
        attack_type VARCHAR(100) NOT NULL,
        severity VARCHAR(20) NOT NULL,
        ml_detected INTEGER DEFAULT 0,
        confidence REAL DEFAULT 0.0,
        blocked_at VARCHAR(50)
    )
    """,
    # incidents
    """
    CREATE TABLE IF NOT EXISTS incidents (
        incident_id INTEGER PRIMARY KEY,
        incident_code VARCHAR(20) UNIQUE NOT NULL,
        category VARCHAR(50) NOT NULL,
        source_ip VARCHAR(45) NOT NULL,
        detection_type VARCHAR(50) NOT NULL,
        status VARCHAR(20) NOT NULL DEFAULT 'open',
        severity VARCHAR(20) NOT NULL,
        first_seen VARCHAR(50),
        last_seen VARCHAR(50),
        created_at VARCHAR(50)
    )
    """,
    # incident_events
    """
    CREATE TABLE IF NOT EXISTS incident_events (
        incident_event_id INTEGER PRIMARY KEY,
        incident_id INTEGER REFERENCES incidents(incident_id) ON DELETE CASCADE,
        threat_log_id INTEGER REFERENCES threat_logs(threat_log_id) ON DELETE CASCADE,
        created_at VARCHAR(50)
    )
    """,
    # incident_actions
    """
    CREATE TABLE IF NOT EXISTS incident_actions (
        action_id INTEGER PRIMARY KEY,
        incident_id INTEGER REFERENCES incidents(incident_id) ON DELETE CASCADE,
        actor_id INTEGER REFERENCES users(user_id),
        action VARCHAR(50) NOT NULL,
        comment TEXT,
        previous_status VARCHAR(20),
        new_status VARCHAR(20),
        created_at VARCHAR(50)
    )
    """,
    # login_attempts
    """
    CREATE TABLE IF NOT EXISTS login_attempts (
        login_attempt_id INTEGER PRIMARY KEY,
        user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
        ip_address VARCHAR(45) NOT NULL,
        success INTEGER NOT NULL,
        failure_reason TEXT,
        attempted_at VARCHAR(50)
    )
    """,
    # user_sessions
    """
    CREATE TABLE IF NOT EXISTS user_sessions (
        session_id INTEGER PRIMARY KEY,
        user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
        jwt_token_hash VARCHAR(64) UNIQUE NOT NULL,
        ip_address VARCHAR(45) NOT NULL,
        user_agent TEXT,
        is_active INTEGER DEFAULT 1,
        expires_at VARCHAR(50),
        created_at VARCHAR(50)
    )
    """,
    # notifications
    """
    CREATE TABLE IF NOT EXISTS notifications (
        notification_id INTEGER PRIMARY KEY,
        user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
        threat_log_id INTEGER REFERENCES threat_logs(threat_log_id) ON DELETE SET NULL,
        type VARCHAR(50) DEFAULT 'info',
        message TEXT NOT NULL,
        is_read INTEGER DEFAULT 0,
        created_at VARCHAR(50)
    )
    """,
    # password_resets
    """
    CREATE TABLE IF NOT EXISTS password_resets (
        id INTEGER PRIMARY KEY,
        user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
        otp VARCHAR(255) NOT NULL,
        otp_expiry VARCHAR(50) NOT NULL,
        otp_attempts INTEGER DEFAULT 0,
        used INTEGER DEFAULT 0
    )
    """,
    # orders
    """
    CREATE TABLE IF NOT EXISTS orders (
        order_id INTEGER PRIMARY KEY,
        username VARCHAR(50) NOT NULL,
        product VARCHAR(100) NOT NULL,
        price REAL NOT NULL,
        created_at VARCHAR(50)
    )
    """,
    # products
    """
    CREATE TABLE IF NOT EXISTS products (
        product_id INTEGER PRIMARY KEY,
        name VARCHAR(100) NOT NULL,
        category VARCHAR(50) NOT NULL,
        description TEXT,
        price REAL NOT NULL,
        created_at VARCHAR(50)
    )
    """,
    # ml_model_runs
    """
    CREATE TABLE IF NOT EXISTS ml_model_runs (
        run_id INTEGER PRIMARY KEY,
        model_version VARCHAR(50) NOT NULL,
        algorithm VARCHAR(100) NOT NULL,
        dataset_size INTEGER NOT NULL,
        accuracy REAL NOT NULL,
        precision_score REAL NOT NULL,
        recall REAL NOT NULL,
        f1_score REAL NOT NULL,
        roc_auc REAL NOT NULL,
        trained_at VARCHAR(50)
    )
    """,
    # chatbot_sessions
    """
    CREATE TABLE IF NOT EXISTS chatbot_sessions (
        chatbot_session_id INTEGER PRIMARY KEY,
        user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
        page_context TEXT,
        started_at VARCHAR(50)
    )
    """,
    # chatbot_messages
    """
    CREATE TABLE IF NOT EXISTS chatbot_messages (
        chatbot_message_id INTEGER PRIMARY KEY,
        session_id INTEGER REFERENCES chatbot_sessions(chatbot_session_id) ON DELETE CASCADE,
        role VARCHAR(20) NOT NULL,
        content TEXT NOT NULL,
        intent_detected VARCHAR(100),
        created_at VARCHAR(50)
    )
    """,
]

_CREATE_INDEXES_SQL = [
    "CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_ts ON rate_limits(ip_address, timestamp)",
]


def _create_all_tables():
    """
    Create all tables and indexes idempotently (CREATE IF NOT EXISTS).
    Safe to call multiple times — never raises on existing tables.
    """
    with _db() as conn:
        for ddl in _CREATE_TABLES_SQL:
            conn.execute(text(ddl.strip()))
        for idx in _CREATE_INDEXES_SQL:
            conn.execute(text(idx))
        conn.commit()
    logger.info("[DB] All tables ensured")


# ══════════════════════════════════════════════════════════════
# INIT
# ══════════════════════════════════════════════════════════════

def init_db():
    """
    Idempotent database initialisation.
    1. Create all tables (if not already present).
    2. Seed roles, admin user, sample users, WAF rules.
    Safe to call multiple times.
    """
    try:
        _create_all_tables()
        _seed_roles()
        _seed_admin()
        _seed_users()
        _seed_rules()
        _ensure_password_resets_columns()
        backend = DATABASE_URL.split("@")[-1] if "@" in DATABASE_URL else DATABASE_URL
        logger.info("[DB] Ready — %s: %s", "SQLite" if _IS_SQLITE else "PostgreSQL", backend)
    except Exception as e:
        logger.warning("[DB] Seeding skipped — %s", e)


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
        admin_password = os.getenv("ADMIN_DEFAULT_PASSWORD")
        if admin_password:
            logger.warning("[DB] Creating default admin — change password immediately after first login")
        else:
            import secrets
            admin_password = secrets.token_urlsafe(16)
            logger.info("[DB] Auto-generated admin password: %s", admin_password)
        _insert_returning(conn, """
            INSERT INTO users (username, password_hash, email, role_id, is_active, created_at, updated_at)
            VALUES ('admin', :ph, 'admin@virex.local', 1, :active, :now, :now)
            RETURNING user_id
        """, {"ph": generate_password_hash(admin_password), "active": _bool(True), "now": now}, "user_id")
        conn.commit()


def _ensure_password_resets_columns():
    """Add otp_attempts column if missing — dialect-aware schema inspection."""
    with _db() as conn:
        if _IS_SQLITE:
            rows = conn.execute(text("PRAGMA table_info(password_resets)")).fetchall()
            col_names = [r[1] for r in rows]  # column at index 1 is 'name'
        else:
            rows = conn.execute(text("""
                SELECT column_name FROM information_schema.columns
                WHERE table_name = 'password_resets'
            """)).mappings().all()
            col_names = [c["column_name"] for c in rows]

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
    """Seed users from users.json or create default admin from environment."""
    import json
    from werkzeug.security import generate_password_hash

    users_file = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "users.json")

    with _db() as conn:
        admin_exists = conn.execute(
            text("SELECT user_id FROM users WHERE username = 'admin'")
        ).fetchone()

        if not admin_exists:
            admin_password = os.getenv("ADMIN_PASSWORD", "AdminPassword123")
            now = time.strftime("%Y-%m-%d %H:%M:%S")
            _insert_returning(conn, """
                INSERT INTO users (username, password_hash, email, role_id, is_active, created_at, updated_at)
                VALUES ('admin', :ph, 'admin@virex.local', 1, :active, :now, :now)
                RETURNING user_id
            """, {"ph": generate_password_hash(admin_password), "active": _bool(True), "now": now}, "user_id")
            conn.commit()

        if os.path.exists(users_file):
            with open(users_file, encoding="utf-8") as f:
                users_json = json.load(f)

            for username, u in users_json.items():
                if username == "admin":
                    continue
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
                _insert_returning(conn, """
                    INSERT INTO users
                        (username, password_hash, email, role_id, is_active, created_at, updated_at)
                    VALUES (:username, :ph, :email, :role_id, :active, :now, :now)
                    RETURNING user_id
                """, {
                    "username": username,
                    "ph": u.get("password_hash", ""),
                    "email": u.get("email", f"{username}@example.com"),
                    "role_id": role_id,
                    "active": _bool(True),
                    "now": now,
                }, "user_id")
            conn.commit()


def _seed_rules():
    with _db() as conn:
        count = conn.execute(text("SELECT COUNT(*) FROM rules")).scalar()
        if count > 0:
            return
        now = time.strftime("%Y-%m-%d %H:%M:%S")
        default_rules = [
            # SQL Injection
            ("SQL Injection - UNION",        "sql_injection",    r"UNION\s+ALL?\s+SELECT",                         "critical", "block"),
            ("SQL Injection - OR 1=1",       "sql_injection",    r"'\s+OR\s+['\d]+\s*=\s*['\d]+",                 "critical", "block"),
            ("SQL Injection - Sleep",        "sql_injection",    r"SLEEP\s*\(",                                     "high",     "block"),
            ("SQL Injection - Exec/CMDSHELL","sql_injection",    r"(EXEC\s+|xp_cmdshell|exec\s*\(|\bWAITFOR\b)",  "critical", "block"),
            ("SQL Injection - Drop/Alter",   "sql_injection",    r"\b(DROP\s+TABLE|ALTER\s+TABLE)\s",              "critical", "block"),
            # XSS
            ("XSS - Full Script Tag",        "xss",              r"<script[\s>][\s\S]*?</script>",                 "high",     "block"),
            ("XSS - JavaScript Protocol",    "xss",              r"(href|src)=[\"']?\s*javascript:",               "high",     "block"),
            ("XSS - Event Handler",          "xss",              r"\b(onerror|onload|onclick)\s*=\s*['\"]*[\"'()]","high",     "block"),
            ("XSS - Cookie Steal",           "xss",              r"document\.cookie",                              "high",     "block"),
            # Command Injection
            ("Command Injection - Pipe+CMD", "command_injection", r"(;|\||`)  \s*(cat|rm|wget|curl|nc|bash|sh|python)\s","critical","block"),
            ("Command Injection - Subshell", "command_injection", r"\$\(.*\)\s*",                                  "critical", "block"),
            # Path Traversal
            ("Path Traversal - Dotdot",      "path_traversal",   r"\.\.[/\\]|%2e%2e[/\\%]",                       "high",     "block"),
            ("Path Traversal - Sensitive",   "path_traversal",   r"(etc/passwd|etc/shadow|windows/system32)",      "critical", "block"),
            # Log4Shell
            ("Log4Shell - JNDI",             "log4shell",        r"\$\{jndi:(ldap|rmi|dns|http)",                  "critical", "block"),
            # SSRF
            ("SSRF - Cloud Metadata",        "ssrf",             r"169\.254\.169\.254",                             "high",     "block"),
            ("SSRF - Localhost Bypass",      "ssrf",             r"(localhost|127\.0\.0\.1|0\.0\.0\.0|::1)",       "high",     "monitor"),
            ("SSRF - Internal IP",           "ssrf",             r"(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)", "medium", "monitor"),
            # CSRF
            ("CSRF - Missing Origin",        "csrf",             r"^POST|PUT|DELETE|PATCH",                         "medium",   "monitor"),
            ("CSRF - Suspicious Referer",    "csrf",             r"Referer:\s*(https?://[^/]+)",                   "medium",   "monitor"),
            ("XXE - External Entity",        "xxe",              r"<!ENTITY\s+\w+\s+SYSTEM\s+[\"'](file|http)",    "high",     "block"),
        ]
        for name, rtype, pattern, severity, action in default_rules:
            conn.execute(text("""
                INSERT INTO rules (name, type, pattern, severity, action, is_active, created_at)
                VALUES (:name, :type, :pattern, :severity, :action, :active, :now)
            """), {"name": name, "type": rtype, "pattern": pattern,
                   "severity": severity, "action": action, "active": _bool(True), "now": now})
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
        new_id = _insert_returning(conn, """
            INSERT INTO users
                (username, password_hash, email, role_id, department_id, is_active, created_at, updated_at)
            VALUES (:username, :ph, :email, :role_id, :dept, :active, :now, :now)
            RETURNING user_id
        """, {
            "username": username,
            "ph": password_hash,
            "email": email or f"{username}@example.com",
            "role_id": role_id,
            "dept": department_id,
            "active": _bool(True),
            "now": now,
        }, "user_id")
        conn.commit()
        return new_id


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
        new_id = _insert_returning(conn, """
            INSERT INTO departments (name, slug, description, created_at)
            VALUES (:name, :slug, :desc, :now)
            RETURNING department_id
        """, {"name": name, "slug": slug, "desc": description, "now": now}, "department_id")
        conn.commit()
        return new_id


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
        new_id = _insert_returning(conn, """
            INSERT INTO threat_logs
                (attack_type, ip_address, endpoint, method, payload, severity,
                 description, blocked, ml_detected, confidence, detection_type, created_at)
            VALUES (:at, :ip, :ep, :method, :payload, :sev,
                    :desc, :blocked, :ml, :conf, :dt, :now)
            RETURNING threat_log_id
        """, {
            "at": attack_type, "ip": ip_address, "ep": endpoint,
            "method": method, "payload": (payload or "")[:500],
            "sev": severity, "desc": description,
            "blocked": _bool(blocked), "ml": _bool(ml_detected),
            "conf": round(confidence, 4), "dt": detection_type, "now": now,
        }, "threat_log_id")
        conn.commit()
        return new_id


def log_normal_request(ip_address: str, endpoint: str, method: str = "") -> int | None:
    """Log a normal/clean request to system_stats and threat_logs."""
    _invalidate_caches()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    try:
        with _db() as conn:
            # Upsert normal_requests_count
            conn.execute(text("""
                INSERT INTO system_stats (metric_name, metric_value, updated_at)
                VALUES ('normal_requests_count', 1, :now)
                ON CONFLICT (metric_name)
                DO UPDATE SET metric_value = system_stats.metric_value + 1, updated_at = :now
            """), {"now": now})

            # Upsert total_requests
            conn.execute(text("""
                INSERT INTO system_stats (metric_name, metric_value, updated_at)
                VALUES ('total_requests', 1, :now)
                ON CONFLICT (metric_name)
                DO UPDATE SET metric_value = system_stats.metric_value + 1, updated_at = :now
            """), {"now": now})

            # Log to threat_logs
            new_id = _insert_returning(conn, """
                INSERT INTO threat_logs
                    (attack_type, ip_address, endpoint, method, payload, severity,
                     description, blocked, ml_detected, confidence, detection_type, created_at)
                VALUES ('Clean', :ip, :ep, :method, '', 'Low',
                        'Normal Request validated', :blocked, :ml, 0.0, 'clean', :now)
                RETURNING threat_log_id
            """, {
                "ip": ip_address, "ep": endpoint, "method": method,
                "blocked": _bool(False), "ml": _bool(False), "now": now,
            }, "threat_log_id")
            conn.commit()
            return new_id
    except Exception as e:
        logger.error("Failed to log normal request: %s", e)
        return None


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
        conn.execute(text("DELETE FROM incident_actions"))
        conn.execute(text("DELETE FROM incident_events"))
        conn.execute(text("DELETE FROM blocked_events"))
        conn.execute(text("DELETE FROM incidents"))
        conn.execute(text("DELETE FROM notifications"))
        conn.execute(text("DELETE FROM threat_logs"))
        conn.execute(text("DELETE FROM system_stats"))
        conn.commit()


# ══════════════════════════════════════════════════════════════
# BLOCKED IPS
# ══════════════════════════════════════════════════════════════

def load_blocked_ips() -> dict:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        conn.execute(text(
            "DELETE FROM blocked_ips WHERE is_permanent = :perm AND unblock_at <= :now"
        ), {"perm": _bool(False), "now": now})
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
        conn.execute(text("DELETE FROM blocked_ips WHERE is_permanent = :perm"), {"perm": _bool(False)})
        for ip, unblock_ts in blocked.items():
            if unblock_ts > now_ts:
                unblock_str = time.strftime("%Y-%m-%d %H:%M:%S", time.localtime(unblock_ts))
                conn.execute(text("""
                    INSERT INTO blocked_ips (ip_address, reason, is_permanent, blocked_at, unblock_at)
                    VALUES (:ip, 'auto-block', :perm, :now, :unblock)
                    ON CONFLICT (ip_address) DO UPDATE SET
                        reason = 'auto-block', is_permanent = :perm,
                        blocked_at = :now, unblock_at = :unblock
                """), {"ip": ip, "perm": _bool(False), "now": now_str, "unblock": unblock_str})
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
                reason = :reason, blocked_by = :by,
                is_permanent = :perm, blocked_at = :now,
                unblock_at = :unblock
        """), {
            "ip": ip, "reason": reason, "by": blocked_by,
            "perm": _bool(is_permanent), "now": now_str, "unblock": unblock_str,
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
            "sev": severity, "ml": _bool(ml_detected),
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
        new_id = _insert_returning(conn, """
            INSERT INTO incidents
                (incident_code, category, source_ip, detection_type, status, severity,
                 first_seen, last_seen, created_at)
            VALUES (:code, :cat, :ip, :dt, 'open', :sev, :now, :now, :now)
            RETURNING incident_id
        """, {
            "code": code, "cat": category, "ip": source_ip,
            "dt": detection_type, "sev": severity, "now": now,
        }, "incident_id")
        conn.commit()
        return new_id


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
            "uid": user_id, "ip": ip_address, "succ": _bool(success),
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
        new_id = _insert_returning(conn, """
            INSERT INTO user_sessions
                (user_id, jwt_token_hash, ip_address, user_agent, is_active, expires_at, created_at)
            VALUES (:uid, :jti, :ip, :ua, :active, :exp, :now)
            RETURNING session_id
        """, {
            "uid": user_id, "jti": jwt_hash, "ip": ip_address,
            "ua": user_agent, "active": _bool(True), "exp": expires_at, "now": now,
        }, "session_id")
        conn.commit()
        return new_id


def invalidate_session(jwt_hash: str):
    with _db() as conn:
        conn.execute(text(
            "UPDATE user_sessions SET is_active = :inactive WHERE jwt_token_hash = :jti"
        ), {"inactive": _bool(False), "jti": jwt_hash})
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
            VALUES (:uid, :tl, :nt, :msg, :unread, :now)
        """), {
            "uid": user_id, "tl": threat_log_id, "nt": notif_type,
            "msg": message, "unread": _bool(False), "now": now,
        })
        conn.commit()


def get_notifications(user_id: int, unread_only: bool = False) -> list:
    sql = "SELECT * FROM notifications WHERE user_id = :uid"
    params = {"uid": user_id}
    if unread_only:
        sql += " AND is_read = :unread"
        params["unread"] = _bool(False)
    sql += " ORDER BY notification_id DESC"
    with _db() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
        return _sanitize_list(rows)


def mark_notification_read(notification_id: int):
    with _db() as conn:
        conn.execute(text(
            "UPDATE notifications SET is_read = :read WHERE notification_id = :id"
        ), {"read": _bool(True), "id": notification_id})
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
            SELECT * FROM threat_logs WHERE ml_detected = :ml
            ORDER BY threat_log_id DESC LIMIT :lim
        """), {"ml": _bool(True), "lim": limit}).mappings().all()
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
        new_id = _insert_returning(conn, """
            INSERT INTO chatbot_sessions (user_id, page_context, started_at)
            VALUES (:uid, :pc, :now)
            RETURNING chatbot_session_id
        """, {"uid": user_id, "pc": page_context, "now": now}, "chatbot_session_id")
        conn.commit()
        return new_id


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
        sql += " WHERE is_active = :active"
    sql += " ORDER BY rule_id"
    params = {"active": _bool(True)} if active_only else {}
    with _db() as conn:
        rows = conn.execute(text(sql), params).mappings().all()
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
        new_id = _insert_returning(conn, """
            INSERT INTO orders (username, product, price, created_at)
            VALUES (:user, :product, :price, :now)
            RETURNING order_id
        """, {"user": user, "product": product, "price": price, "now": now}, "order_id")
        conn.commit()
        # Return a minimal dict matching what callers expect
        return {"order_id": new_id, "username": user, "product": product,
                "price": price, "created_at": now}


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
        # Fetch values from system_stats
        sys_rows = conn.execute(text("SELECT metric_name, metric_value FROM system_stats")).fetchall()
        sys_stats = {r[0]: r[1] for r in sys_rows} if sys_rows else {}

        # Use LIKE instead of ILIKE for SQLite compatibility
        # (SQLite LIKE is case-insensitive for ASCII)
        like = _like("attack_type")
        row = conn.execute(text(f"""
            SELECT
                COUNT(*) AS total_threats,
                SUM(CASE WHEN blocked = :btrue THEN 1 ELSE 0 END) AS blocked,
                SUM(CASE WHEN ml_detected = :btrue OR detection_type {like} 'ml%' OR attack_type = 'ML Detection' THEN 1 ELSE 0 END) AS ml,
                SUM(CASE WHEN attack_type {like} '%sql%' THEN 1 ELSE 0 END) AS sqli,
                SUM(CASE WHEN attack_type {like} '%xss%' THEN 1 ELSE 0 END) AS xss,
                SUM(CASE WHEN attack_type {like} '%brute%' OR attack_type {like} '%auth%' THEN 1 ELSE 0 END) AS brute,
                SUM(CASE WHEN attack_type {like} '%scanner%' OR attack_type {like} '%recon%' OR attack_type = 'Scanner' THEN 1 ELSE 0 END) AS scanner,
                SUM(CASE WHEN attack_type {like} '%rate%' OR attack_type {like} '%limit%' OR attack_type = 'Rate Limit Exceeded' THEN 1 ELSE 0 END) AS rate_limit,
                SUM(CASE WHEN attack_type {like} '%csrf%' OR attack_type {like} '%cross%site%request%' OR attack_type = 'CSRF' THEN 1 ELSE 0 END) AS csrf,
                SUM(CASE WHEN attack_type {like} '%ssrf%' OR attack_type {like} '%server%side%' OR attack_type = 'SSRF' THEN 1 ELSE 0 END) AS ssrf,
                SUM(CASE WHEN attack_type {like} '%command%' OR attack_type {like} '%cmd%' OR (attack_type {like} '%injection%' AND attack_type NOT {like} '%sql%') THEN 1 ELSE 0 END) AS cmd_injection,
                SUM(CASE WHEN attack_type {like} '%path%' OR attack_type {like} '%traversal%' THEN 1 ELSE 0 END) AS path_traversal,
                SUM(CASE WHEN attack_type {like} '%xxe%' THEN 1 ELSE 0 END) AS xxe,
                SUM(CASE WHEN attack_type {like} '%ssti%' THEN 1 ELSE 0 END) AS ssti,
                SUM(CASE WHEN attack_type {like} '%log4shell%' OR attack_type {like} '%jndi%' THEN 1 ELSE 0 END) AS log4shell,
                SUM(CASE WHEN UPPER(severity) = 'CRITICAL' THEN 1 ELSE 0 END) AS critical_count,
                SUM(CASE WHEN UPPER(severity) = 'HIGH' THEN 1 ELSE 0 END) AS high_count,
                SUM(CASE WHEN UPPER(severity) = 'MEDIUM' THEN 1 ELSE 0 END) AS medium_count,
                SUM(CASE WHEN UPPER(severity) = 'LOW' THEN 1 ELSE 0 END) AS low_count
            FROM threat_logs
            WHERE attack_type != 'Clean' AND attack_type != 'Normal'
        """), {"btrue": _bool(True)}).fetchone()

    total_reqs = sys_stats.get("total_requests")
    if total_reqs is None:
        total_reqs = row[0] or 0

    blocked_reqs = sys_stats.get("blocked_requests")
    if blocked_reqs is None:
        blocked_reqs = row[1] or 0

    normal_reqs = sys_stats.get("normal_requests_count")
    if normal_reqs is None:
        normal_reqs = max(0, total_reqs - blocked_reqs)

    result = {
        "total_requests": total_reqs,
        "blocked_requests": blocked_reqs,
        "normal_requests_count": normal_reqs,
        "ml_detections": row[2] or 0,
        "sql_injection_attempts": row[3] or 0,
        "xss_attempts": row[4] or 0,
        "brute_force_attempts": row[5] or 0,
        "scanner_attempts": row[6] or 0,
        "rate_limit_hits": row[7] or 0,
        "csrf_attempts": row[8] or 0,
        "ssrf_attempts": row[9] or 0,
        "cmd_injection_attempts": row[10] or 0,
        "path_traversal_attempts": row[11] or 0,
        "xxe_attempts": row[12] or 0,
        "ssti_attempts": row[13] or 0,
        "log4shell_attempts": row[14] or 0,
        "critical_count": row[15] or 0,
        "high_count": row[16] or 0,
        "medium_count": row[17] or 0,
        "low_count": row[18] or 0,
    }
    _stats_cache = result
    _stats_cache_time = now
    return result


def save_stats(stats_data=None, *args, **kwargs):
    """
    Save stats/metrics persistently using an SQL UPSERT (ON CONFLICT DO UPDATE).
    Supports stats_data as a dictionary of metrics, or positional args (total, blocked).
    """
    metrics = {}
    if isinstance(stats_data, dict):
        metrics = stats_data
    elif len(args) >= 1 or (stats_data is not None and not isinstance(stats_data, dict)):
        total = stats_data
        blocked = args[0] if args else kwargs.get("blocked", 0)
        metrics = {
            "total_requests": total,
            "blocked_requests": blocked,
        }

    for k, v in kwargs.items():
        if isinstance(v, (int, float)):
            metrics[k] = v

    if not metrics:
        return

    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with _db() as conn:
        for name, value in sorted(metrics.items()):
            conn.execute(text("""
                INSERT INTO system_stats (metric_name, metric_value, updated_at)
                VALUES (:name, :val, :now)
                ON CONFLICT (metric_name)
                DO UPDATE SET metric_value = :val, updated_at = :now
            """), {"name": name, "val": int(value), "now": now})
        conn.commit()


# ══════════════════════════════════════════════════════════════
# ATTACK HISTORY
# ══════════════════════════════════════════════════════════════

def append_user_attack(user_key: str, attack_type: str, ip: str,
                       endpoint: str, method: str = "", severity: str = "High",
                       blocked: bool = True, description: str = None,
                       ml_detected: bool = False, confidence: float = 0.0, detection_type: str = "rule",
                       payload: str = "") -> int | None:
    _invalidate_caches()
    return log_threat(
        attack_type=attack_type, ip_address=ip, endpoint=endpoint,
        method=method, severity=severity, blocked=blocked,
        description=description or f"user_key={user_key}",
        detection_type=detection_type,
        ml_detected=ml_detected, confidence=confidence,
        payload=payload
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
            VALUES (:uid, :otp, :exp, :unused, 0)
        """), {"uid": user_id, "otp": otp_hash, "exp": otp_expiry, "unused": _bool(False)})
        conn.commit()


def get_active_password_reset(user_id: int) -> dict | None:
    with _db() as conn:
        row = conn.execute(text("""
            SELECT * FROM password_resets WHERE user_id = :uid AND used = :unused LIMIT 1
        """), {"uid": user_id, "unused": _bool(False)}).mappings().fetchone()
        return _sanitize(dict(row)) if row else None


def increment_otp_attempts(user_id: int):
    with _db() as conn:
        conn.execute(text("""
            UPDATE password_resets SET otp_attempts = COALESCE(otp_attempts, 0) + 1
            WHERE user_id = :uid AND used = :unused
        """), {"uid": user_id, "unused": _bool(False)})
        conn.commit()


def reset_otp_attempts(user_id: int):
    with _db() as conn:
        conn.execute(text("""
            UPDATE password_resets SET otp_attempts = 0
            WHERE user_id = :uid AND used = :unused
        """), {"uid": user_id, "unused": _bool(False)})
        conn.commit()


def mark_password_reset_used(user_id: int):
    with _db() as conn:
        conn.execute(text("""
            UPDATE password_resets SET used = :used, otp_attempts = 0
            WHERE user_id = :uid
        """), {"uid": user_id, "used": _bool(True)})
        conn.commit()
