-- =============================================================
-- Virex Security — Schema DDL
-- Compatible with: SQLite 3.24+ AND PostgreSQL 12+
--
-- PostgreSQL note: replace INTEGER PRIMARY KEY AUTOINCREMENT
--   with SERIAL PRIMARY KEY when running directly on Postgres.
--   In practice the Python code (database.py) creates all
--   tables programmatically and handles dialect differences.
-- =============================================================

-- Create roles table
CREATE TABLE IF NOT EXISTS roles (
    role_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at VARCHAR(50)
);

-- Create departments table
CREATE TABLE IF NOT EXISTS departments (
    department_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at VARCHAR(50)
);

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    user_id INTEGER PRIMARY KEY AUTOINCREMENT,
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
);

-- Create rate_limits table
CREATE TABLE IF NOT EXISTS rate_limits (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ip_address VARCHAR(45) NOT NULL,
    timestamp REAL NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_ts ON rate_limits(ip_address, timestamp);

-- Create system_stats table
-- ON CONFLICT (metric_name) upsert requires metric_name to be a PRIMARY KEY
CREATE TABLE IF NOT EXISTS system_stats (
    metric_name VARCHAR(100) PRIMARY KEY,
    metric_value INTEGER NOT NULL,
    updated_at VARCHAR(50) DEFAULT CURRENT_TIMESTAMP
);

-- Create rules table
CREATE TABLE IF NOT EXISTS rules (
    rule_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL,
    pattern TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    action VARCHAR(20) NOT NULL,
    is_active INTEGER DEFAULT 1,
    created_at VARCHAR(50),
    updated_at VARCHAR(50)
);

-- Create threat_logs table
CREATE TABLE IF NOT EXISTS threat_logs (
    threat_log_id INTEGER PRIMARY KEY AUTOINCREMENT,
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
);

-- Create blocked_ips table
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip_address VARCHAR(45) PRIMARY KEY,
    reason TEXT,
    blocked_by INTEGER REFERENCES users(user_id),
    is_permanent INTEGER DEFAULT 0,
    blocked_at VARCHAR(50),
    unblock_at VARCHAR(50)
);

-- Create blocked_events table
CREATE TABLE IF NOT EXISTS blocked_events (
    blocked_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    threat_log_id INTEGER REFERENCES threat_logs(threat_log_id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    attack_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    ml_detected INTEGER DEFAULT 0,
    confidence REAL DEFAULT 0.0,
    blocked_at VARCHAR(50)
);

-- Create incidents table
CREATE TABLE IF NOT EXISTS incidents (
    incident_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_code VARCHAR(20) UNIQUE NOT NULL,
    category VARCHAR(50) NOT NULL,
    source_ip VARCHAR(45) NOT NULL,
    detection_type VARCHAR(50) NOT NULL,
    status VARCHAR(20) NOT NULL DEFAULT 'open',
    severity VARCHAR(20) NOT NULL,
    first_seen VARCHAR(50),
    last_seen VARCHAR(50),
    created_at VARCHAR(50)
);

-- Create incident_events table
CREATE TABLE IF NOT EXISTS incident_events (
    incident_event_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(incident_id) ON DELETE CASCADE,
    threat_log_id INTEGER REFERENCES threat_logs(threat_log_id) ON DELETE CASCADE,
    created_at VARCHAR(50)
);

-- Create incident_actions table
CREATE TABLE IF NOT EXISTS incident_actions (
    action_id INTEGER PRIMARY KEY AUTOINCREMENT,
    incident_id INTEGER REFERENCES incidents(incident_id) ON DELETE CASCADE,
    actor_id INTEGER REFERENCES users(user_id),
    action VARCHAR(50) NOT NULL,
    comment TEXT,
    previous_status VARCHAR(20),
    new_status VARCHAR(20),
    created_at VARCHAR(50)
);

-- Create login_attempts table
CREATE TABLE IF NOT EXISTS login_attempts (
    login_attempt_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    success INTEGER NOT NULL,
    failure_reason TEXT,
    attempted_at VARCHAR(50)
);

-- Create user_sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    jwt_token_hash VARCHAR(64) UNIQUE NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    is_active INTEGER DEFAULT 1,
    expires_at VARCHAR(50),
    created_at VARCHAR(50)
);

-- Create notifications table
CREATE TABLE IF NOT EXISTS notifications (
    notification_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    threat_log_id INTEGER REFERENCES threat_logs(threat_log_id) ON DELETE SET NULL,
    type VARCHAR(50) DEFAULT 'info',
    message TEXT NOT NULL,
    is_read INTEGER DEFAULT 0,
    created_at VARCHAR(50)
);

-- Create password_resets table
CREATE TABLE IF NOT EXISTS password_resets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    otp VARCHAR(255) NOT NULL,
    otp_expiry VARCHAR(50) NOT NULL,
    otp_attempts INTEGER DEFAULT 0,
    used INTEGER DEFAULT 0
);

-- Create orders table
CREATE TABLE IF NOT EXISTS orders (
    order_id INTEGER PRIMARY KEY AUTOINCREMENT,
    username VARCHAR(50) NOT NULL,
    product VARCHAR(100) NOT NULL,
    price REAL NOT NULL,
    created_at VARCHAR(50)
);

-- Create products table
CREATE TABLE IF NOT EXISTS products (
    product_id INTEGER PRIMARY KEY AUTOINCREMENT,
    name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    description TEXT,
    price REAL NOT NULL,
    created_at VARCHAR(50)
);

-- Create ml_model_runs table
CREATE TABLE IF NOT EXISTS ml_model_runs (
    run_id INTEGER PRIMARY KEY AUTOINCREMENT,
    model_version VARCHAR(50) NOT NULL,
    algorithm VARCHAR(100) NOT NULL,
    dataset_size INTEGER NOT NULL,
    accuracy REAL NOT NULL,
    precision_score REAL NOT NULL,
    recall REAL NOT NULL,
    f1_score REAL NOT NULL,
    roc_auc REAL NOT NULL,
    trained_at VARCHAR(50)
);

-- Create chatbot_sessions table
CREATE TABLE IF NOT EXISTS chatbot_sessions (
    chatbot_session_id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    page_context TEXT,
    started_at VARCHAR(50)
);

-- Create chatbot_messages table
CREATE TABLE IF NOT EXISTS chatbot_messages (
    chatbot_message_id INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id INTEGER REFERENCES chatbot_sessions(chatbot_session_id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL,
    content TEXT NOT NULL,
    intent_detected VARCHAR(100),
    created_at VARCHAR(50)
);
