-- Create roles table
CREATE TABLE IF NOT EXISTS roles (
    role_id SERIAL PRIMARY KEY,
    name VARCHAR(50) UNIQUE NOT NULL,
    description TEXT,
    created_at VARCHAR(50)
);

-- Create departments table
CREATE TABLE IF NOT EXISTS departments (
    department_id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    slug VARCHAR(100) UNIQUE NOT NULL,
    description TEXT,
    created_at VARCHAR(50)
);

-- Create users table
CREATE TABLE IF NOT EXISTS users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    email VARCHAR(100) UNIQUE,
    role_id INTEGER REFERENCES roles(role_id),
    department_id INTEGER REFERENCES departments(department_id),
    is_active BOOLEAN DEFAULT TRUE,
    created_at VARCHAR(50),
    updated_at VARCHAR(50),
    last_login VARCHAR(50),
    reset_token VARCHAR(255),
    reset_token_expiry VARCHAR(50)
);

-- Create rate_limits table
CREATE TABLE IF NOT EXISTS rate_limits (
    id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    timestamp DOUBLE PRECISION NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_rate_limits_ip_ts ON rate_limits(ip_address, timestamp);

-- Create system_stats table
CREATE TABLE IF NOT EXISTS system_stats (
    metric_name VARCHAR(100) PRIMARY KEY,
    metric_value BIGINT NOT NULL,
    updated_at TIMESTAMP DEFAULT NOW()
);

-- Create rules table
CREATE TABLE IF NOT EXISTS rules (
    rule_id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    type VARCHAR(50) NOT NULL,
    pattern TEXT NOT NULL,
    severity VARCHAR(20) NOT NULL,
    action VARCHAR(20) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at VARCHAR(50),
    updated_at VARCHAR(50)
);

-- Create threat_logs table
CREATE TABLE IF NOT EXISTS threat_logs (
    threat_log_id SERIAL PRIMARY KEY,
    attack_type VARCHAR(100) NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    endpoint VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    payload TEXT,
    severity VARCHAR(20) NOT NULL,
    description TEXT,
    blocked BOOLEAN NOT NULL,
    ml_detected BOOLEAN DEFAULT FALSE,
    confidence DOUBLE PRECISION DEFAULT 0.0,
    detection_type VARCHAR(50) DEFAULT 'rule',
    created_at VARCHAR(50)
);

-- Create blocked_ips table
CREATE TABLE IF NOT EXISTS blocked_ips (
    ip_address VARCHAR(45) PRIMARY KEY,
    reason TEXT,
    blocked_by INTEGER REFERENCES users(user_id),
    is_permanent BOOLEAN DEFAULT FALSE,
    blocked_at VARCHAR(50),
    unblock_at VARCHAR(50)
);

-- Create blocked_events table
CREATE TABLE IF NOT EXISTS blocked_events (
    blocked_event_id SERIAL PRIMARY KEY,
    threat_log_id INTEGER REFERENCES threat_logs(threat_log_id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    attack_type VARCHAR(100) NOT NULL,
    severity VARCHAR(20) NOT NULL,
    ml_detected BOOLEAN DEFAULT FALSE,
    confidence DOUBLE PRECISION DEFAULT 0.0,
    blocked_at VARCHAR(50)
);

-- Create incidents table
CREATE TABLE IF NOT EXISTS incidents (
    incident_id SERIAL PRIMARY KEY,
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
    incident_event_id SERIAL PRIMARY KEY,
    incident_id INTEGER REFERENCES incidents(incident_id) ON DELETE CASCADE,
    threat_log_id INTEGER REFERENCES threat_logs(threat_log_id) ON DELETE CASCADE,
    created_at VARCHAR(50)
);

-- Create incident_actions table
CREATE TABLE IF NOT EXISTS incident_actions (
    action_id SERIAL PRIMARY KEY,
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
    login_attempt_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    ip_address VARCHAR(45) NOT NULL,
    success BOOLEAN NOT NULL,
    failure_reason TEXT,
    attempted_at VARCHAR(50)
);

-- Create user_sessions table
CREATE TABLE IF NOT EXISTS user_sessions (
    session_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    jwt_token_hash VARCHAR(64) UNIQUE NOT NULL,
    ip_address VARCHAR(45) NOT NULL,
    user_agent TEXT,
    is_active BOOLEAN DEFAULT TRUE,
    expires_at VARCHAR(50),
    created_at VARCHAR(50)
);

-- Create notifications table
CREATE TABLE IF NOT EXISTS notifications (
    notification_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    threat_log_id INTEGER REFERENCES threat_logs(threat_log_id) ON DELETE SET NULL,
    type VARCHAR(50) DEFAULT 'info',
    message TEXT NOT NULL,
    is_read BOOLEAN DEFAULT FALSE,
    created_at VARCHAR(50)
);

-- Create password_resets table
CREATE TABLE IF NOT EXISTS password_resets (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    otp VARCHAR(255) NOT NULL,
    otp_expiry VARCHAR(50) NOT NULL,
    otp_attempts INTEGER DEFAULT 0,
    used BOOLEAN DEFAULT FALSE
);

-- Create orders table
CREATE TABLE IF NOT EXISTS orders (
    order_id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL,
    product VARCHAR(100) NOT NULL,
    price DOUBLE PRECISION NOT NULL,
    created_at VARCHAR(50)
);

-- Create products table
CREATE TABLE IF NOT EXISTS products (
    product_id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL,
    category VARCHAR(50) NOT NULL,
    description TEXT,
    price DOUBLE PRECISION NOT NULL,
    created_at VARCHAR(50)
);

-- Create ml_model_runs table
CREATE TABLE IF NOT EXISTS ml_model_runs (
    run_id SERIAL PRIMARY KEY,
    model_version VARCHAR(50) NOT NULL,
    algorithm VARCHAR(100) NOT NULL,
    dataset_size INTEGER NOT NULL,
    accuracy DOUBLE PRECISION NOT NULL,
    precision_score DOUBLE PRECISION NOT NULL,
    recall DOUBLE PRECISION NOT NULL,
    f1_score DOUBLE PRECISION NOT NULL,
    roc_auc DOUBLE PRECISION NOT NULL,
    trained_at VARCHAR(50)
);

-- Create chatbot_sessions table
CREATE TABLE IF NOT EXISTS chatbot_sessions (
    chatbot_session_id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES users(user_id) ON DELETE CASCADE,
    page_context TEXT,
    started_at VARCHAR(50)
);

-- Create chatbot_messages table
CREATE TABLE IF NOT EXISTS chatbot_messages (
    chatbot_message_id SERIAL PRIMARY KEY,
    session_id INTEGER REFERENCES chatbot_sessions(chatbot_session_id) ON DELETE CASCADE,
    role VARCHAR(20) NOT NULL,
    content TEXT NOT NULL,
    intent_detected VARCHAR(100),
    created_at VARCHAR(50)
);
