"""
Virex Security System — Database Setup Script
==============================================
Run this ONCE before starting the app for the first time.
Creates all required tables and seeds initial data.

Usage:
    python setup_db.py
"""
import sqlite3
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).parent
DB_DIR  = PROJECT_ROOT / "db"
DB_PATH = DB_DIR / "virex.db"

DB_DIR.mkdir(exist_ok=True)

print("=" * 50)
print("  Virex DB Setup")
print("=" * 50)
print(f"\n  Database: {DB_PATH}\n")

conn = sqlite3.connect(str(DB_PATH))
conn.execute("PRAGMA journal_mode=WAL")
conn.execute("PRAGMA foreign_keys=ON")
cur = conn.cursor()

SCHEMA = """
CREATE TABLE IF NOT EXISTS roles (
    role_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL UNIQUE,
    description TEXT,
    created_at  TEXT
);

CREATE TABLE IF NOT EXISTS departments (
    department_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name          TEXT NOT NULL,
    slug          TEXT,
    description   TEXT,
    created_at    TEXT
);

CREATE TABLE IF NOT EXISTS users (
    user_id       INTEGER PRIMARY KEY AUTOINCREMENT,
    username      TEXT NOT NULL UNIQUE,
    password_hash TEXT NOT NULL,
    email         TEXT,
    role_id       INTEGER DEFAULT 2 REFERENCES roles(role_id),
    department_id INTEGER REFERENCES departments(department_id),
    full_name     TEXT,
    phone         TEXT,
    department    TEXT,
    is_active     INTEGER DEFAULT 1,
    last_login    TEXT,
    reset_token   TEXT,
    reset_token_expiry TEXT,
    avatar_url    TEXT,
    subscription  TEXT DEFAULT 'Free',
    created_at    TEXT,
    updated_at    TEXT
);

CREATE TABLE IF NOT EXISTS user_sessions (
    session_id      INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES users(user_id),
    jwt_token_hash  TEXT NOT NULL,
    ip_address      TEXT,
    user_agent      TEXT,
    is_active       INTEGER DEFAULT 1,
    expires_at      TEXT,
    created_at      TEXT
);

CREATE TABLE IF NOT EXISTS login_attempts (
    login_attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id          INTEGER,
    ip_address       TEXT,
    success          INTEGER DEFAULT 0,
    failure_reason   TEXT,
    attempted_at     TEXT
);

CREATE TABLE IF NOT EXISTS blocked_ips (
    blocked_ip_id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address    TEXT NOT NULL UNIQUE,
    reason        TEXT,
    blocked_by    INTEGER,
    is_permanent  INTEGER DEFAULT 0,
    blocked_at    TEXT,
    unblock_at    TEXT
);

CREATE TABLE IF NOT EXISTS rules (
    rule_id     INTEGER PRIMARY KEY AUTOINCREMENT,
    name        TEXT NOT NULL,
    type        TEXT NOT NULL,
    pattern     TEXT,
    severity    TEXT NOT NULL DEFAULT 'medium',
    action      TEXT NOT NULL DEFAULT 'block',
    is_active   INTEGER NOT NULL DEFAULT 1,
    description TEXT,
    created_at  TEXT
);

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
);

CREATE TABLE IF NOT EXISTS blocked_events (
    blocked_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_log_id    INTEGER,
    ip_address       TEXT,
    attack_type      TEXT,
    severity         TEXT,
    ml_detected      INTEGER DEFAULT 0,
    confidence       REAL    DEFAULT 0.0,
    blocked_at       TEXT
);

CREATE TABLE IF NOT EXISTS incidents (
    incident_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_code  TEXT,
    category       TEXT NOT NULL,
    source_ip      TEXT,
    detection_type TEXT,
    status         TEXT DEFAULT 'open',
    severity       TEXT DEFAULT 'Medium',
    first_seen     TEXT,
    last_seen      TEXT,
    created_at     TEXT
);

CREATE TABLE IF NOT EXISTS incident_events (
    incident_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id       INTEGER REFERENCES incidents(incident_id),
    threat_log_id     INTEGER,
    created_at        TEXT
);

CREATE TABLE IF NOT EXISTS incident_actions (
    incident_action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id        INTEGER REFERENCES incidents(incident_id),
    actor_id           INTEGER,
    action             TEXT,
    comment            TEXT,
    previous_status    TEXT,
    new_status         TEXT,
    created_at         TEXT
);

CREATE TABLE IF NOT EXISTS notifications (
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id         INTEGER REFERENCES users(user_id),
    threat_log_id   INTEGER,
    type            TEXT DEFAULT 'info',
    message         TEXT NOT NULL,
    is_read         INTEGER DEFAULT 0,
    created_at      TEXT
);

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
);

CREATE TABLE IF NOT EXISTS ml_model_runs (
    model_run_id    INTEGER PRIMARY KEY AUTOINCREMENT,
    model_version   TEXT,
    algorithm       TEXT,
    dataset_size    INTEGER,
    accuracy        REAL,
    precision_score REAL,
    recall          REAL,
    f1_score        REAL,
    roc_auc         REAL,
    trained_at      TEXT
);

CREATE TABLE IF NOT EXISTS ml_feature_importance (
    feature_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    model_run_id INTEGER,
    feature_name TEXT,
    importance   REAL
);

CREATE TABLE IF NOT EXISTS ml_training_data (
    training_id INTEGER PRIMARY KEY AUTOINCREMENT,
    text        TEXT,
    label       INTEGER,
    source      TEXT,
    added_at    TEXT
);

CREATE TABLE IF NOT EXISTS chatbot_sessions (
    chatbot_session_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id            INTEGER,
    page_context       TEXT,
    started_at         TEXT
);

CREATE TABLE IF NOT EXISTS chatbot_messages (
    chatbot_message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id         INTEGER,
    role               TEXT,
    content            TEXT,
    intent_detected    TEXT,
    created_at         TEXT
);

CREATE TABLE IF NOT EXISTS blacklist (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    type       TEXT,
    value      TEXT,
    reason     TEXT,
    status     TEXT DEFAULT 'active',
    added_by   TEXT,
    date_added TEXT
);

CREATE TABLE IF NOT EXISTS password_resets (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id    INTEGER NOT NULL,
    otp        TEXT NOT NULL,
    otp_expiry TEXT NOT NULL,
<<<<<<< HEAD
    used       INTEGER DEFAULT 0
=======
<<<<<<< HEAD
    used       INTEGER DEFAULT 0
=======
    used       INTEGER DEFAULT 0,
    otp_attempts INTEGER DEFAULT 0
>>>>>>> 4c5ae8566bbeb2af6ffddd6da0dc25f97d5a40fa
>>>>>>> 29c1406ff0d33cca29bb3c738f3c070c695be578
);

-- Indexes for performance
CREATE INDEX IF NOT EXISTS idx_threat_logs_ip      ON threat_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_threat_logs_type    ON threat_logs(attack_type);
CREATE INDEX IF NOT EXISTS idx_threat_logs_created ON threat_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_threat_logs_blocked ON threat_logs(blocked);
CREATE INDEX IF NOT EXISTS idx_users_email         ON users(email);
CREATE INDEX IF NOT EXISTS idx_sessions_jti        ON user_sessions(jwt_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_active     ON user_sessions(is_active);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user     ON audit_logs(user_id);
CREATE INDEX IF NOT EXISTS idx_notifications_user  ON notifications(user_id);
"""

# Execute schema
for stmt in SCHEMA.strip().split(";"):
    stmt = stmt.strip()
    if stmt:
        cur.execute(stmt)

print("  ✅ Tables created")

# Seed roles
cur.execute("SELECT COUNT(*) FROM roles")
if cur.fetchone()[0] == 0:
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    cur.executemany(
        "INSERT INTO roles (name, description, created_at) VALUES (?,?,?)",
        [
            ("admin",   "Full system access", now),
            ("user",    "Standard access",    now),
            ("analyst", "Read-only + reports",now),
            ("manager", "Team management",    now),
        ]
    )
    print("  ✅ Roles seeded")

# Seed default admin user
cur.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
if cur.fetchone()[0] == 0:
    from werkzeug.security import generate_password_hash
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    cur.execute("""
        INSERT INTO users
            (username, password_hash, email, role_id, is_active, created_at, updated_at)
        VALUES (?, ?, ?, 1, 1, ?, ?)
    """, (
        "admin",
        generate_password_hash("Admin@123"),
        "admin@virex.local",
        now, now
    ))
    print("  ✅ Admin user created  (username: admin  |  password: Admin@123)")
    print("  ⚠️  Change the password after first login!")

# Seed WAF rules
cur.execute("SELECT COUNT(*) FROM rules")
if cur.fetchone()[0] == 0:
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
    cur.executemany(
        "INSERT INTO rules (name,type,pattern,severity,action,is_active,created_at) VALUES (?,?,?,?,?,1,?)",
        [(r[0],r[1],r[2],r[3],r[4],now) for r in default_rules]
    )
    print(f"  ✅ {len(default_rules)} WAF rules seeded")

conn.commit()
conn.close()

print("\n" + "=" * 50)
print("  Setup complete! Now run:")
print("    python run_api.py")
print("    python run_dashboard.py")
print("=" * 50)
