-- ══════════════════════════════════════════════════════════════
-- Virex Security System — Supabase Schema
-- Run this in Supabase SQL Editor to create all tables
-- ══════════════════════════════════════════════════════════════

-- ROLES
CREATE TABLE IF NOT EXISTS roles (
    role_id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- DEPARTMENTS
CREATE TABLE IF NOT EXISTS departments (
    department_id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE,
    slug VARCHAR(100),
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- USERS
CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    email VARCHAR(100) UNIQUE,
    role_name VARCHAR(50) DEFAULT 'user',
    role_id INT REFERENCES roles(role_id) DEFAULT 2,
    department_id INT REFERENCES departments(department_id),
    full_name VARCHAR(100),
    phone VARCHAR(20),
    department VARCHAR(100),
    status VARCHAR(20) DEFAULT 'active',
    is_active BOOLEAN DEFAULT TRUE,
    last_login TIMESTAMP,
    reset_token TEXT,
    reset_token_expiry TIMESTAMP,
    avatar_url TEXT,
    subscription VARCHAR(50) DEFAULT 'Free',
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_users_email ON users(email);

-- USER SESSIONS
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
    jwt_token_hash VARCHAR(128) NOT NULL,
    ip_address VARCHAR(45),
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_sessions_jti ON user_sessions(jwt_token_hash);
CREATE INDEX IF NOT EXISTS idx_sessions_active ON user_sessions(is_active);

-- LOGIN ATTEMPTS
CREATE TABLE IF NOT EXISTS login_attempts (
    login_attempt_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    ip_address VARCHAR(45),
    success BOOLEAN DEFAULT FALSE,
    failure_reason TEXT,
    attempted_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_login_attempts_user ON login_attempts(user_id);

-- BLOCKED IPS
CREATE TABLE IF NOT EXISTS blocked_ips (
    blocked_ip_id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL UNIQUE,
    reason TEXT,
    blocked_by INT,
    is_permanent BOOLEAN DEFAULT FALSE,
    blocked_at TIMESTAMP DEFAULT NOW(),
    unblock_at TIMESTAMP
);

-- WAF RULES
CREATE TABLE IF NOT EXISTS rules (
    rule_id SERIAL PRIMARY KEY,
    name VARCHAR(150) NOT NULL,
    type VARCHAR(50) NOT NULL,
    pattern TEXT,
    severity VARCHAR(20) NOT NULL DEFAULT 'medium',
    action VARCHAR(20) NOT NULL DEFAULT 'block',
    is_active BOOLEAN DEFAULT TRUE,
    description TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);

-- THREAT LOGS
CREATE TABLE IF NOT EXISTS threat_logs (
    threat_log_id SERIAL PRIMARY KEY,
    attack_type VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45),
    endpoint VARCHAR(255),
    method VARCHAR(10),
    payload TEXT,
    severity VARCHAR(20) DEFAULT 'Medium',
    description TEXT,
    blocked BOOLEAN DEFAULT FALSE,
    ml_detected BOOLEAN DEFAULT FALSE,
    confidence NUMERIC(5,2) DEFAULT 0.0,
    detection_type VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_threat_logs_ip ON threat_logs(ip_address);
CREATE INDEX IF NOT EXISTS idx_threat_logs_type ON threat_logs(attack_type);
CREATE INDEX IF NOT EXISTS idx_threat_logs_created ON threat_logs(created_at);
CREATE INDEX IF NOT EXISTS idx_threat_logs_blocked ON threat_logs(blocked);

-- BLOCKED EVENTS
CREATE TABLE IF NOT EXISTS blocked_events (
    blocked_event_id SERIAL PRIMARY KEY,
    threat_log_id INT REFERENCES threat_logs(threat_log_id),
    ip_address VARCHAR(45),
    attack_type VARCHAR(100),
    severity VARCHAR(20),
    ml_detected BOOLEAN DEFAULT FALSE,
    confidence NUMERIC(5,2) DEFAULT 0.0,
    blocked_at TIMESTAMP DEFAULT NOW()
);

-- INCIDENTS
CREATE TABLE IF NOT EXISTS incidents (
    incident_id SERIAL PRIMARY KEY,
    incident_code VARCHAR(50),
    category VARCHAR(100) NOT NULL,
    source_ip VARCHAR(45),
    detection_type VARCHAR(50),
    status VARCHAR(50) DEFAULT 'open',
    severity VARCHAR(20) DEFAULT 'Medium',
    first_seen TIMESTAMP,
    last_seen TIMESTAMP,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_incidents_status ON incidents(status);

-- INCIDENT EVENTS
CREATE TABLE IF NOT EXISTS incident_events (
    incident_event_id SERIAL PRIMARY KEY,
    incident_id INT REFERENCES incidents(incident_id) ON DELETE CASCADE,
    threat_log_id INT REFERENCES threat_logs(threat_log_id),
    created_at TIMESTAMP DEFAULT NOW()
);

-- INCIDENT ACTIONS
CREATE TABLE IF NOT EXISTS incident_actions (
    incident_action_id SERIAL PRIMARY KEY,
    incident_id INT REFERENCES incidents(incident_id) ON DELETE CASCADE,
    actor_id INT,
    action VARCHAR(100),
    comment TEXT,
    previous_status VARCHAR(50),
    new_status VARCHAR(50),
    created_at TIMESTAMP DEFAULT NOW()
);

-- NOTIFICATIONS
CREATE TABLE IF NOT EXISTS notifications (
    notification_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id) ON DELETE CASCADE,
    threat_log_id INT,
    type VARCHAR(20) DEFAULT 'info',
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_notifications_user ON notifications(user_id);

-- AUDIT LOGS
CREATE TABLE IF NOT EXISTS audit_logs (
    audit_log_id SERIAL PRIMARY KEY,
    user_id INT,
    action VARCHAR(100) NOT NULL,
    resource VARCHAR(100),
    resource_id VARCHAR(100),
    details TEXT,
    ip_address VARCHAR(45),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX IF NOT EXISTS idx_audit_logs_user ON audit_logs(user_id);

-- ML MODEL RUNS
CREATE TABLE IF NOT EXISTS ml_model_runs (
    model_run_id SERIAL PRIMARY KEY,
    model_version VARCHAR(50),
    algorithm VARCHAR(100),
    dataset_size INT,
    accuracy NUMERIC(5,4),
    precision_score NUMERIC(5,4),
    recall NUMERIC(5,4),
    f1_score NUMERIC(5,4),
    roc_auc NUMERIC(5,4),
    trained_at TIMESTAMP DEFAULT NOW()
);

-- ML FEATURE IMPORTANCE
CREATE TABLE IF NOT EXISTS ml_feature_importance (
    feature_id SERIAL PRIMARY KEY,
    model_run_id INT REFERENCES ml_model_runs(model_run_id),
    feature_name VARCHAR(255),
    importance NUMERIC(7,4)
);

-- ML TRAINING DATA
CREATE TABLE IF NOT EXISTS ml_training_data (
    training_id SERIAL PRIMARY KEY,
    text TEXT,
    label INT,
    source VARCHAR(100),
    added_at TIMESTAMP DEFAULT NOW()
);

-- CHATBOT SESSIONS
CREATE TABLE IF NOT EXISTS chatbot_sessions (
    chatbot_session_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    page_context VARCHAR(100),
    started_at TIMESTAMP DEFAULT NOW()
);

-- CHATBOT MESSAGES
CREATE TABLE IF NOT EXISTS chatbot_messages (
    chatbot_message_id SERIAL PRIMARY KEY,
    session_id INT REFERENCES chatbot_sessions(chatbot_session_id),
    role VARCHAR(20),
    content TEXT,
    intent_detected VARCHAR(100),
    created_at TIMESTAMP DEFAULT NOW()
);

-- BLACKLIST
CREATE TABLE IF NOT EXISTS blacklist (
    id SERIAL PRIMARY KEY,
    type VARCHAR(50),
    value TEXT,
    reason TEXT,
    status VARCHAR(20) DEFAULT 'active',
    added_by VARCHAR(50),
    date_added TIMESTAMP DEFAULT NOW()
);

-- PASSWORD RESETS
CREATE TABLE IF NOT EXISTS password_resets (
    id SERIAL PRIMARY KEY,
    user_id INT NOT NULL REFERENCES users(user_id),
    otp VARCHAR(10) NOT NULL,
    otp_expiry TIMESTAMP NOT NULL,
    used BOOLEAN DEFAULT FALSE
);

-- ══════════════════════════════════════════════════════════════
-- SEED DATA
-- ══════════════════════════════════════════════════════════════

-- Roles
INSERT INTO roles (name, description) VALUES
    ('admin',   'Full system access'),
    ('user',    'Standard access'),
    ('analyst', 'Read-only + reports'),
    ('manager', 'Team management')
ON CONFLICT (name) DO NOTHING;

-- WAF Rules
INSERT INTO rules (name, type, pattern, severity, action, is_active) VALUES
    ('SQL Injection - UNION',        'sql_injection',     'UNION\s+SELECT',                              'high',     'block', TRUE),
    ('SQL Injection - Keywords',     'sql_injection',     '(SELECT|INSERT|UPDATE|DELETE|DROP|ALTER)',     'high',     'block', TRUE),
    ('SQL Injection - Comment',      'sql_injection',     '(--|#|/\*|;|@@)',                             'high',     'block', TRUE),
    ('SQL Injection - OR/AND',       'sql_injection',     '(\bOR\b|\bAND\b).+(=|LIKE|IN)',              'high',     'block', TRUE),
    ('XSS - Script Tag',            'xss',               '<script.*?>.*?</script>',                     'high',     'block', TRUE),
    ('XSS - JavaScript Protocol',   'xss',               'javascript:',                                 'high',     'block', TRUE),
    ('XSS - Event Handler',         'xss',               '(onerror|onload|onclick)\s*=',                'high',     'block', TRUE),
    ('XSS - Alert',                 'xss',               'alert\(.*\)',                                 'medium',   'block', TRUE),
    ('Command Injection - Pipe',    'command_injection',  '(;|\|{1,2}|&&|`)[\s\S]*(cat|ls|rm|wget|curl|nc|bash|sh)', 'critical','block', TRUE),
    ('Command Injection - Subshell','command_injection',  '\$\(.*\)',                                   'critical', 'block', TRUE),
    ('Path Traversal - Dotdot',     'path_traversal',    '\.\.[/\\]',                                  'high',     'block', TRUE),
    ('Path Traversal - Encoded',    'path_traversal',    '%2e%2e[%2f%5c]',                             'high',     'block', TRUE),
    ('Path Traversal - Sensitive',  'path_traversal',    '(etc/passwd|etc/shadow|windows/system32)',    'critical', 'block', TRUE)
ON CONFLICT DO NOTHING;

-- ══════════════════════════════════════════════════════════════
-- ENABLE ROW LEVEL SECURITY (optional, recommended)
-- ══════════════════════════════════════════════════════════════

-- ALTER TABLE users ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE threat_logs ENABLE ROW LEVEL SECURITY;
-- ALTER TABLE notifications ENABLE ROW LEVEL SECURITY;
