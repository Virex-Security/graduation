CREATE TABLE roles (
    role_id SERIAL PRIMARY KEY,
    name VARCHAR(50) NOT NULL UNIQUE
);

CREATE TABLE departments (
    department_id SERIAL PRIMARY KEY,
    name VARCHAR(100) NOT NULL UNIQUE
);


CREATE TABLE users (
    user_id SERIAL PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    email VARCHAR(100) NOT NULL UNIQUE,
    password_hash VARCHAR(256) NOT NULL,
    role_id INT REFERENCES roles(role_id),
    department_id INT REFERENCES departments(department_id),
    created_at TIMESTAMP DEFAULT NOW()
);


CREATE TABLE user_sessions (
    session_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    jti_hash CHAR(64) NOT NULL,
    ip_address VARCHAR(45),
    is_active BOOLEAN DEFAULT TRUE,
    expires_at TIMESTAMP NOT NULL,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_user_sessions_user ON user_sessions(user_id);
CREATE INDEX idx_user_sessions_jti ON user_sessions(jti_hash);


CREATE TABLE login_attempts (
    attempt_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    success BOOLEAN,
    ip_address VARCHAR(45),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_login_attempts_user ON login_attempts(user_id);


CREATE TABLE blocked_ips (
    ip_address VARCHAR(45) PRIMARY KEY,
    reason VARCHAR(255),
    expires_at TIMESTAMP
);

CREATE TABLE rules (
    rule_id SERIAL PRIMARY KEY,
    name VARCHAR(100),
    type VARCHAR(50),
    regex_pattern TEXT NOT NULL,
    severity VARCHAR(20),
    action VARCHAR(20)
);


CREATE TABLE threat_logs (
    threat_id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45),
    endpoint VARCHAR(255),
    payload TEXT,
    attack_type VARCHAR(50),
    blocked BOOLEAN DEFAULT FALSE,
    ml_flag BOOLEAN DEFAULT FALSE,
    confidence NUMERIC(5,2),
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_threat_ip ON threat_logs(ip_address);
CREATE INDEX idx_threat_endpoint ON threat_logs(endpoint);
CREATE INDEX idx_threat_blocked ON threat_logs(blocked);
CREATE INDEX idx_threat_created ON threat_logs(created_at);


CREATE TABLE blocked_events AS
SELECT * FROM threat_logs WHERE blocked = TRUE;


CREATE TABLE incidents (
    incident_id SERIAL PRIMARY KEY,
    title VARCHAR(255),
    status VARCHAR(50),
    severity VARCHAR(20),
    created_at TIMESTAMP DEFAULT NOW(),
    updated_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_incidents_status ON incidents(status);


CREATE TABLE incident_events (
    incident_event_id SERIAL PRIMARY KEY,
    incident_id INT REFERENCES incidents(incident_id),
    threat_id INT REFERENCES threat_logs(threat_id)
);


CREATE TABLE incident_actions (
    action_id SERIAL PRIMARY KEY,
    incident_id INT REFERENCES incidents(incident_id),
    user_id INT REFERENCES users(user_id),
    action_type VARCHAR(100),
    notes TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);


CREATE TABLE notifications (
    notification_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    message TEXT,
    severity VARCHAR(20),
    is_sent BOOLEAN DEFAULT FALSE,
    created_at TIMESTAMP DEFAULT NOW()
);
CREATE INDEX idx_notifications_user ON notifications(user_id);
CREATE INDEX idx_notifications_severity ON notifications(severity);

CREATE TABLE audit_logs (
    audit_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    action_type VARCHAR(100),
    target_table VARCHAR(100),
    target_id INT,
    timestamp TIMESTAMP DEFAULT NOW()
);


CREATE TABLE ml_model_runs (
    run_id SERIAL PRIMARY KEY,
    model_name VARCHAR(100),
    accuracy NUMERIC(5,2),
    created_at TIMESTAMP DEFAULT NOW()
);


CREATE TABLE ml_feature_importance (
    feature_id SERIAL PRIMARY KEY,
    run_id INT REFERENCES ml_model_runs(run_id),
    feature_name VARCHAR(255),
    importance NUMERIC(5,4)
);


CREATE TABLE ml_training_data (
    sample_id SERIAL PRIMARY KEY,
    text_data TEXT,
    label VARCHAR(50),
    promoted BOOLEAN DEFAULT FALSE
);


CREATE TABLE ml_predictions (
    prediction_id SERIAL PRIMARY KEY,
    threat_id INT REFERENCES threat_logs(threat_id),
    model_name VARCHAR(100),
    confidence_score NUMERIC(5,2),
    created_at TIMESTAMP DEFAULT NOW()
);


CREATE TABLE chatbot_sessions (
    session_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    started_at TIMESTAMP DEFAULT NOW(),
    ended_at TIMESTAMP
);


CREATE TABLE chatbot_messages (
    message_id SERIAL PRIMARY KEY,
    session_id INT REFERENCES chatbot_sessions(session_id),
    message TEXT,
    sender VARCHAR(20),
    created_at TIMESTAMP DEFAULT NOW()
);


CREATE TABLE blacklist (
    entry_id SERIAL PRIMARY KEY,
    ip_address VARCHAR(45),
    domain VARCHAR(255),
    user_agent TEXT,
    created_at TIMESTAMP DEFAULT NOW()
);


CREATE TABLE password_resets (
    reset_id SERIAL PRIMARY KEY,
    user_id INT REFERENCES users(user_id),
    otp_hash CHAR(64),
    expiry TIMESTAMP,
    used BOOLEAN DEFAULT FALSE,
    attempts INT DEFAULT 0,
    created_at TIMESTAMP DEFAULT NOW()
);


CREATE TABLE api_endpoints (
    endpoint_id SERIAL PRIMARY KEY,
    path VARCHAR(255) NOT NULL,
    method VARCHAR(10) NOT NULL,
    description TEXT
);

CREATE TABLE user_settings (
    user_id INT PRIMARY KEY REFERENCES users(user_id),
    email_notifications BOOLEAN DEFAULT TRUE,
    notification_threshold VARCHAR(20) DEFAULT 'critical'
);