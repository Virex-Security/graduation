# ── WAF Rules Table ─────────────────────────────────────────
def _ensure_rules_table():
    """Ensure the 'rules' table exists in the database."""
    with db_cursor() as cur:
        cur.execute("""
            CREATE TABLE IF NOT EXISTS rules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                type TEXT NOT NULL,
                pattern TEXT NOT NULL,
                severity TEXT DEFAULT 'High',
                action TEXT DEFAULT 'block',
                description TEXT,
                active INTEGER DEFAULT 1,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
"""
Database operations for VIREX Security System
SQLite-based data persistence layer
"""
import sqlite3
import time
import os
from contextlib import contextmanager
from datetime import datetime

# Database path
DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), 'db', 'virex.db')

@contextmanager
def db_cursor():
    """Context manager for database operations."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    try:
        yield conn.cursor()
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()

def init_db():
    """Initialize database with all required tables."""
    with db_cursor() as cur:
        # Users table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS users (
                user_id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT UNIQUE NOT NULL,
                password_hash TEXT NOT NULL,
                email TEXT,
                role_id INTEGER DEFAULT 2,
                department_id INTEGER,
                is_active INTEGER DEFAULT 1,
                last_login TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP,
                reset_token TEXT,
                reset_token_expiry TEXT,
                full_name TEXT,
                phone TEXT,
                subscription TEXT DEFAULT 'FREE',
                department TEXT
            )
        """)
        
        # Roles table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS roles (
                role_id INTEGER PRIMARY KEY AUTOINCREMENT,
                role_name TEXT UNIQUE NOT NULL,
                description TEXT
            )
        """)
        
        # Threat logs table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS threat_logs (
                log_id INTEGER PRIMARY KEY AUTOINCREMENT,
                attack_type TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                endpoint TEXT,
                method TEXT,
                payload TEXT,
                severity TEXT DEFAULT 'Medium',
                description TEXT,
                blocked INTEGER DEFAULT 0,
                ml_detected INTEGER DEFAULT 0,
                confidence REAL DEFAULT 0.0,
                detection_type TEXT DEFAULT 'rule',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Blocked events table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS blocked_events (
                event_id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip_address TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                severity TEXT DEFAULT 'Medium',
                ml_detected INTEGER DEFAULT 0,
                confidence REAL DEFAULT 0.0,
                threat_log_id INTEGER,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (threat_log_id) REFERENCES threat_logs (log_id)
            )
        """)
        
        # Incidents table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS incidents (
                incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
                incident_code TEXT UNIQUE NOT NULL,
                category TEXT NOT NULL,
                source_ip TEXT NOT NULL,
                detection_type TEXT DEFAULT 'rule',
                status TEXT DEFAULT 'open',
                severity TEXT DEFAULT 'Medium',
                first_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                last_seen TEXT DEFAULT CURRENT_TIMESTAMP,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                actor_id INTEGER,
                comment TEXT,
                FOREIGN KEY (actor_id) REFERENCES users (user_id)
            )
        """)
        
        # ML detections table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS ml_detections (
                detection_id INTEGER PRIMARY KEY AUTOINCREMENT,
                text_snippet TEXT NOT NULL,
                risk_score REAL NOT NULL,
                prediction TEXT NOT NULL,
                severity TEXT DEFAULT 'Medium',
                ip_address TEXT,
                endpoint TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Audit logs table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS audit_logs (
                audit_id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER,
                action TEXT NOT NULL,
                resource TEXT NOT NULL,
                resource_id TEXT,
                details TEXT,
                ip_address TEXT,
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (user_id) REFERENCES users (user_id)
            )
        """)
        
        # Blacklist table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS blacklist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                type TEXT NOT NULL,
                value TEXT NOT NULL,
                reason TEXT,
                created_by TEXT,
                status TEXT DEFAULT 'active',
                created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # Stats table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS stats (
                id INTEGER PRIMARY KEY,
                total_requests INTEGER DEFAULT 0,
                blocked_requests INTEGER DEFAULT 0,
                updated_at TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
        
        # User attacks table
        cur.execute("""
            CREATE TABLE IF NOT EXISTS user_attacks (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_key TEXT NOT NULL,
                attack_type TEXT NOT NULL,
                ip_address TEXT NOT NULL,
                endpoint TEXT,
                timestamp TEXT DEFAULT CURRENT_TIMESTAMP
            )
        """)
    
    _seed_roles()
    _seed_users()

def _seed_roles():
    """Seed initial roles."""
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM roles")
        if cur.fetchone()[0] == 0:
            cur.execute("INSERT INTO roles (role_id, name, description) VALUES (1, 'admin', 'Administrator')")
            cur.execute("INSERT INTO roles (role_id, name, description) VALUES (2, 'user', 'Regular User')")

def _seed_users():
    """Seed initial admin user."""
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM users WHERE username = 'admin'")
        if cur.fetchone()[0] == 0:
            from werkzeug.security import generate_password_hash
            admin_hash = generate_password_hash('admin123')
            cur.execute("""
                INSERT INTO users (username, password_hash, email, role_id, subscription)
                VALUES ('admin', ?, 'admin@example.com', 1, 'ENTERPRISE')
            """, (admin_hash,))

# User operations
def get_all_users():
    """Get all users with role information."""
    with db_cursor() as cur:
        cur.execute("""
            SELECT u.*, r.name as role_name 
            FROM users u 
            LEFT JOIN roles r ON u.role_id = r.role_id
            ORDER BY u.created_at DESC
        """)
        return [dict(row) for row in cur.fetchall()]

def get_user_by_username(username):
    """Get user by username."""
    with db_cursor() as cur:
        cur.execute("""
            SELECT u.*, r.name as role_name 
            FROM users u 
            LEFT JOIN roles r ON u.role_id = r.role_id
            WHERE u.username = ?
        """, (username,))
        row = cur.fetchone()
        return dict(row) if row else None

def get_user_by_id(user_id):
    """Get user by ID."""
    with db_cursor() as cur:
        cur.execute("""
            SELECT u.*, r.name as role_name 
            FROM users u 
            LEFT JOIN roles r ON u.role_id = r.role_id
            WHERE u.user_id = ?
        """, (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None

def insert_user(username, password_hash, email=None, role='user'):
    """Insert new user."""
    role_id = 1 if role == 'admin' else 2
    now = datetime.now().isoformat()
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO users (username, password_hash, email, role_id, created_at, updated_at)
            VALUES (?, ?, ?, ?, ?, ?)
        """, (username, password_hash, email, role_id, now, now))
        return cur.lastrowid

def update_user(username, **kwargs):
    """Update user information."""
    if not kwargs:
        return False
    
    kwargs['updated_at'] = datetime.now().isoformat()
    fields = ', '.join(f"{k} = ?" for k in kwargs.keys())
    values = list(kwargs.values()) + [username]
    
    with db_cursor() as cur:
        cur.execute(f"UPDATE users SET {fields} WHERE username = ?", values)
        return cur.rowcount > 0

def delete_user(username):
    """Delete user."""
    with db_cursor() as cur:
        cur.execute("DELETE FROM users WHERE username = ?", (username,))
        return cur.rowcount > 0

# Threat logging
def log_threat(attack_type, ip_address, endpoint='', method='GET', payload='', 
               severity='Medium', description='', blocked=False, ml_detected=False,
               confidence=0.0, detection_type='rule'):
    """Log a threat event."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO threat_logs 
            (attack_type, ip_address, endpoint, method, payload, severity, 
             description, blocked, ml_detected, confidence, detection_type, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (attack_type, ip_address, endpoint, method, payload, severity,
              description, int(blocked), int(ml_detected), confidence, detection_type, now))
        return cur.lastrowid

def get_threat_logs(limit=100, attack_type=None, severity=None):
    """Get threat logs with optional filtering."""
    query = "SELECT * FROM threat_logs"
    params = []
    conditions = []
    
    if attack_type:
        conditions.append("attack_type = ?")
        params.append(attack_type)
    if severity:
        conditions.append("severity = ?")
        params.append(severity)
    
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    
    with db_cursor() as cur:
        cur.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

# Blocked events
def log_blocked_event(ip_address, attack_type, severity='Medium', 
                     ml_detected=False, confidence=0.0, threat_log_id=None):
    """Log a blocked event."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO blocked_events 
            (ip_address, attack_type, severity, ml_detected, confidence, threat_log_id, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (ip_address, attack_type, severity, int(ml_detected), confidence, threat_log_id, now))
        return cur.lastrowid

def get_blocked_events(limit=100):
    """Get blocked events."""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM blocked_events ORDER BY created_at DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]

# Incidents
def create_incident(category, source_ip, severity, detection_type='rule'):
    """Create a new incident."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    import random, string
    code = "INC-" + "".join(random.choices(string.digits, k=6))
    
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO incidents
            (incident_code, category, source_ip, detection_type, status, severity, 
             first_seen, last_seen, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """, (code, category, source_ip, detection_type, 'open', severity, now, now, now))
        return cur.lastrowid

def get_incidents(status=None, limit=100):
    """Get incidents with optional status filtering."""
    query = "SELECT * FROM incidents"
    params = []
    
    if status:
        query += " WHERE status = ?"
        params.append(status)
    
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    
    with db_cursor() as cur:
        cur.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

def update_incident_status(incident_id, new_status, actor_id=None, comment=''):
    """Update incident status."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute("""
            UPDATE incidents 
            SET status = ?, last_seen = ?, actor_id = ?, comment = ?
            WHERE incident_id = ?
        """, (new_status, now, actor_id, comment, incident_id))
        return cur.rowcount > 0

# ML detections
def log_ml_detection(text_snippet, risk_score, prediction, severity='Medium', 
                    ip_address='', endpoint=''):
    """Log ML detection."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO ml_detections 
            (text_snippet, risk_score, prediction, severity, ip_address, endpoint, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (text_snippet, risk_score, prediction, severity, ip_address, endpoint, now))
        return cur.lastrowid

def get_ml_detections(limit=100):
    """Get ML detections."""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM ml_detections ORDER BY created_at DESC LIMIT ?", (limit,))
        return [dict(row) for row in cur.fetchall()]

# Audit logs
def log_audit(user_id, action, resource, resource_id='', details='', ip_address=''):
    """Log audit event."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO audit_logs 
            (user_id, action, resource, resource_id, details, ip_address, created_at)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (user_id, action, resource, resource_id, details, ip_address, now))
        return cur.lastrowid

def get_audit_logs(user_id=None, limit=100):
    """Get audit logs."""
    query = "SELECT * FROM audit_logs"
    params = []
    
    if user_id:
        query += " WHERE user_id = ?"
        params.append(user_id)
    
    query += " ORDER BY created_at DESC LIMIT ?"
    params.append(limit)
    
    with db_cursor() as cur:
        cur.execute(query, params)
        return [dict(row) for row in cur.fetchall()]

# Blacklist operations
def create_blacklist_table():
    """Create blacklist table if it doesn't exist."""
    with db_cursor() as cur:
        # Check if table exists and has the correct schema
        cur.execute("PRAGMA table_info(blacklist)")
        columns = [row[1] for row in cur.fetchall()]
        
        if not columns:
            # Table doesn't exist, create it
            cur.execute("""
                CREATE TABLE blacklist (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    type TEXT NOT NULL,
                    value TEXT NOT NULL,
                    reason TEXT,
                    created_by TEXT,
                    status TEXT DEFAULT 'active',
                    created_at TEXT DEFAULT CURRENT_TIMESTAMP,
                    updated_at TEXT DEFAULT CURRENT_TIMESTAMP
                )
            """)
        else:
            # Table exists, check if it has the required columns
            required_columns = ['created_at', 'updated_at']
            for col in required_columns:
                if col not in columns:
                    cur.execute(f"ALTER TABLE blacklist ADD COLUMN {col} TEXT DEFAULT CURRENT_TIMESTAMP")
            
            # Ensure created_by column exists
            if 'created_by' not in columns:
                cur.execute("ALTER TABLE blacklist ADD COLUMN created_by TEXT")

def get_all_blacklist_entries():
    """Get all blacklist entries."""
    create_blacklist_table()
    with db_cursor() as cur:
        cur.execute("SELECT * FROM blacklist ORDER BY created_at DESC")
        return [dict(r) for r in cur.fetchall()]

def add_blacklist_entry(entry_type, value, reason="", created_by="", status="active"):
    """Add new blacklist entry."""
    create_blacklist_table()
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute(
            """INSERT INTO blacklist (type, value, reason, created_by, status, created_at, updated_at)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (entry_type, value, reason, created_by, status, now, now)
        )
        return cur.lastrowid

def update_blacklist_entry(entry_id, created_by="", **kwargs):
    """Update blacklist entry."""
    allowed = {"type", "value", "reason", "status"}
    fields = {k: v for k, v in kwargs.items() if k in allowed}
    if not fields:
        return False
    fields["updated_at"] = time.strftime("%Y-%m-%d %H:%M:%S")
    set_clause = ", ".join(f"{k} = ?" for k in fields)
    values = list(fields.values()) + [entry_id]
    with db_cursor() as cur:
        cur.execute(f"UPDATE blacklist SET {set_clause} WHERE id = ?", values)
        return cur.rowcount > 0

def delete_blacklist_entry(entry_id):
    """Delete blacklist entry."""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM blacklist WHERE id = ?", (entry_id,))
        entry = cur.fetchone()
        if entry:
            cur.execute("DELETE FROM blacklist WHERE id = ?", (entry_id,))
            return dict(entry)
        return None

def get_blacklist_stats():
    """Get blacklist statistics."""
    create_blacklist_table()
    with db_cursor() as cur:
        cur.execute("SELECT COUNT(*) as total FROM blacklist")
        total = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) as ips FROM blacklist WHERE type = 'ip'")
        ips = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) as domains FROM blacklist WHERE type = 'domain'")
        domains = cur.fetchone()[0]
        
        cur.execute("SELECT COUNT(*) as user_agents FROM blacklist WHERE type = 'user_agent'")
        user_agents = cur.fetchone()[0]
        
        return {
            'total': total,
            'blocked_ips': ips,
            'blocked_domains': domains,
            'blocked_user_agents': user_agents
        }

# Stats operations
def load_stats():
    """Load statistics."""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM stats WHERE id = 1")
        row = cur.fetchone()
        if row:
            return {'total_requests': row['total_requests'], 'blocked_requests': row['blocked_requests']}
        return {'total_requests': 0, 'blocked_requests': 0}

def save_stats(total, blocked):
    """Save statistics."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute("""
            INSERT OR REPLACE INTO stats (id, total_requests, blocked_requests, updated_at)
            VALUES (1, ?, ?, ?)
        """, (total, blocked, now))

# User attacks operations
def append_user_attack(user_key, attack_type, ip, endpoint=''):
    """Append user attack."""
    now = time.strftime("%Y-%m-%d %H:%M:%S")
    with db_cursor() as cur:
        cur.execute("""
            INSERT INTO user_attacks (user_key, attack_type, ip_address, endpoint, timestamp)
            VALUES (?, ?, ?, ?, ?)
        """, (user_key, attack_type, ip, endpoint, now))
        return cur.lastrowid

def get_user_attacks(user_key):
    """Get user attacks."""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM user_attacks WHERE user_key = ? ORDER BY timestamp DESC", (user_key,))
        return [dict(row) for row in cur.fetchall()]

def load_user_attacks():
    """Load all user attacks."""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM user_attacks ORDER BY timestamp DESC")
        attacks = {}
        for row in cur.fetchall():
            user_key = row['user_key']
            if user_key not in attacks:
                attacks[user_key] = []
            attacks[user_key].append(dict(row))
        return attacks

def clear_user_attacks(user_key):
    """Clear attacks for specific user."""
    with db_cursor() as cur:
        cur.execute("DELETE FROM user_attacks WHERE user_key = ?", (user_key,))
        return cur.rowcount

def clear_all_attacks():
    """Clear all attacks."""
    with db_cursor() as cur:
        cur.execute("DELETE FROM threat_logs")
        cur.execute("DELETE FROM blocked_events")
        cur.execute("DELETE FROM user_attacks")
        cur.execute("DELETE FROM ml_detections")
        return True

# Blocked IPs operations (for compatibility)
def load_blocked_ips():
    """Load blocked IPs (compatibility function)."""
    return {}

def save_blocked_ips(blocked):
    """Save blocked IPs (compatibility function)."""
    pass

def block_ip(ip, unblock_at_ts, reason="auto-block", blocked_by="system"):
    """Block IP (logs as threat)."""
    log_threat('IP Block', ip, '', 'POST', '', 'High', reason, True, False, 0.0, 'rule')

def unblock_ip(ip):
    """Unblock IP (compatibility function)."""
    pass

def get_all_roles():
    """Get all roles."""
    with db_cursor() as cur:
        cur.execute("SELECT * FROM roles ORDER BY role_name")
        return [dict(row) for row in cur.fetchall()]