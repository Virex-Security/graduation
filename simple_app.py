"""
Simple API Security System for Testing
Lightweight version for demonstration and testing with dashboard integration
"""

from flask import Flask, request, jsonify
import time
import re
import logging
import requests
import threading
from collections import defaultdict, deque
import joblib

# ================= ML MODEL =================
try:
    model = joblib.load("model.pkl")
    vectorizer = joblib.load("vectorizer.pkl")
    MODEL_LOADED = True
except Exception as e:
    print(f"⚠️ Warning: Could not load ML model: {e}")
    MODEL_LOADED = False

def ml_detect(text):
    if not MODEL_LOADED:
        return False
    try:
        X = vectorizer.transform([text])
        prediction = model.predict(X)[0]
        return prediction == 1   # 1 = Attack, 0 = Normal
    except:
        return False


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SimpleSecurityManager:
    """Simplified security manager for testing with ML integration"""
    
    def __init__(self):
        self.total_requests = 0
        self.blocked_requests = 0
        self.sql_injection_count = 0
        self.xss_count = 0
        self.brute_force_count = 0
        self.rate_limit_hits = 0
        self.rate_limit_storage = defaultdict(deque)
        self.start_time = time.time()
        self.dashboard_url = "http://127.0.0.1:8070"
        
        # Robust patterns
        self.sql_patterns = [
            r"(SELECT|INSERT|UPDATE|DELETE|DROP|CREATE|ALTER|UNION|EXEC|TRUNCATE|GRANT|REVOKE)",
            r"(\bOR\b|\bAND\b).+(\=|\bLIKE\b|\bIN\b)",
            r"(--|#|/\*|\*/|;|@@|\bSLEEP\b|\bBENCHMARK\b|\bWAITFOR\b)",
            r"('|%27).+(\bOR\b|\bAND\b).+",
            r"UNION\s+SELECT"
        ]

        self.xss_patterns = [
            r"<script.*?>.*?</script>",
            r"javascript:",
            r"onerror\s*=",
            r"onload\s*=",
            r"onclick\s*=",
            r"<iframe.*?>",
            r"<svg.*?>",
            r"<img.*?onerror",
            r"<body.*?onload",
            r"alert\(.*\)"
        ]
        
        self.compiled_sql_patterns = [re.compile(p, re.IGNORECASE) for p in self.sql_patterns]
        self.compiled_xss_patterns = [re.compile(p, re.IGNORECASE) for p in self.xss_patterns]
    
    # ================= DASHBOARD =================
    def log_to_dashboard(self, threat_type, ip, description, severity="Medium", endpoint="", method="", snippet="", detection_type="Other", blocked=True):
        def send_log():
            try:
                requests.post(
                    f"{self.dashboard_url}/api/dashboard/threat",
                    json={
                        "type": threat_type,
                        "ip": ip,
                        "description": description,
                        "severity": severity,
                        "endpoint": endpoint,
                        "method": method,
                        "snippet": snippet,
                        "detection_type": detection_type,
                        "blocked": blocked
                    },
                    timeout=2
                )
            except:
                pass

        threading.Thread(target=send_log, daemon=True).start()

    def update_dashboard_stats(self):
        def send_update():
            try:
                requests.post(
                    f"{self.dashboard_url}/api/dashboard/stats",
                    json={
                        "total_requests": self.total_requests,
                        "blocked_requests": self.blocked_requests,
                        "rate_limit_hits": self.rate_limit_hits
                    },
                    timeout=2
                )
            except:
                pass

        threading.Thread(target=send_update, daemon=True).start()
    
    # ================= REGEX =================
    def detect_sql_injection(self, text, ip):
        for pattern in self.compiled_sql_patterns:
            if pattern.search(text):
                self.sql_injection_count += 1
                # blocked_requests will be incremented in before_request when request is rejected
                self.log_to_dashboard(
                    "SQL Injection", 
                    ip, 
                    f"SQL Injection attempt detected", 
                    "High",
                    endpoint=request.path,
                    method=request.method,
                    snippet=text[:100],
                    detection_type="SQL Injection",
                    blocked=True
                )
                return True
        return False

    def detect_xss(self, text, ip):
        for pattern in self.compiled_xss_patterns:
            if pattern.search(text):
                self.xss_count += 1
                # blocked_requests will be incremented in before_request when request is rejected
                self.log_to_dashboard(
                    "XSS", 
                    ip, 
                    "XSS attempt detected", 
                    "High",
                    endpoint=request.path,
                    method=request.method,
                    snippet=text[:100],
                    detection_type="XSS",
                    blocked=True
                )
                return True
        return False
    
    # ================= RATE LIMIT =================
    def check_rate_limit(self, ip):
        now = time.time()
        q = self.rate_limit_storage[ip]

        # 10 second window
        while q and now - q[0] > 10:
            q.popleft()

        if len(q) >= 10:
            self.rate_limit_hits += 1
            # blocked_requests will be incremented in before_request when request is rejected
            self.log_to_dashboard(
                "Rate Limit", 
                ip, 
                "Rate limit exceeded", 
                "Medium",
                endpoint=request.path,
                method=request.method,
                detection_type="Rate Limit",
                blocked=True
            )
            return False

        q.append(now)
        return True
    
    # ================= MAIN SECURITY =================
    def check_request_security(self, data, ip):
        def scan(value):
            if isinstance(value, dict):
                for v in value.values():
                    if not scan(v):
                        return False
            elif isinstance(value, list):
                for item in value:
                    if not scan(item):
                        return False
            elif value is not None:
                text = str(value)

                # Regex FIRST
                if self.detect_sql_injection(text, ip):
                    return False
                if self.detect_xss(text, ip):
                    return False

                # ML SECOND
                if ml_detect(text):
                    # blocked_requests will be incremented in before_request when request is rejected
                    self.log_to_dashboard(
                        "ML Detection",
                        ip,
                        "ML Detection – Attack Detected",
                        "High",
                        endpoint=request.path,
                        method=request.method,
                        snippet=text[:100],
                        detection_type="ML",
                        blocked=True
                    )
                    return False

            return True

        if not scan(data):
            return False, "Malicious content detected"

        return True, "OK"

def is_trivial(req):
    """
    Determine if a request is trivial (monitoring/health checks).
    Trivial requests are NEVER counted in any metric.
    """
    path = req.path
    
    # Health and status checks
    if path in ['/health', '/api/health', '/status', '/ping']:
        return True
    
    # Dashboard internal APIs
    if path.startswith('/api/dashboard/'):
        return True
    
    # Static files
    static_extensions = ['.js', '.css', '.png', '.jpg', '.ico', '.svg', '.woff', '.ttf']
    if any(path.endswith(ext) for ext in static_extensions):
        return True
    
    # Stats endpoint (monitoring only)
    if path == '/api/security/stats':
        return True
    
    return False

def is_business_relevant(req):
    """
    Determine if a request represents real business interaction.
    Only business-relevant requests count as total_requests (if not blocked).
    
    Business-relevant criteria:
    - POST/PUT/PATCH/DELETE to any endpoint
    - Access to sensitive endpoints (login, admin, data, user, transaction)
    - Any request to /api/* endpoints (except health/dashboard)
    """
    path = req.path
    method = req.method
    
    # All data-modifying methods are business-relevant
    if method in ['POST', 'PUT', 'PATCH', 'DELETE']:
        return True
    
    # Any API endpoint (except health and dashboard)
    if path.startswith('/api/') and not path.startswith('/api/dashboard/') and path not in ['/api/health', '/api/security/stats']:
        return True
    
    # Sensitive endpoints (even GET)
    sensitive_endpoints = [
        '/login', '/api/login',
        '/admin', '/api/admin',
        '/api/data',
        '/user/', '/api/user/',
        '/transaction/', '/api/transaction/'
    ]
    
    for endpoint in sensitive_endpoints:
        if endpoint in path:
            return True
    
    # GET with query parameters (filtered searches)
    if method == 'GET' and req.args:
        return True
    
    # Default: not business-relevant
    return False

def create_simple_app():
    """Create a simple Flask app for testing"""
    app = Flask(__name__)
    security = SimpleSecurityManager()
    
    @app.before_request
    def before_request():
        """
        Request Processing Pipeline:
        1. Filter trivial requests → Skip
        2. Validate business relevance → Continue
        3. Run security checks → Detect threats
        4. Decide: Block or Allow
        5. Log and update metrics
        
        Metrics Rules (Mutually Exclusive):
        - Blocked requests: NOT counted in total_requests
        - Allowed business requests: counted in total_requests
        - Attack types: counted separately (sql_detections, xss_detections, etc.)
        """
        
        # Step 1: Filter trivial requests
        if is_trivial(request):
            return  # Skip all processing and metrics
        
        # Step 2: Check business relevance
        is_business = is_business_relevant(request)
        
        # Step 3 & 4: Security checks (Rate Limit, Scanner, Content)
        request_blocked = False
        block_reason = None
        
        # 3a. Rate Limiting (Strict Rule)
        if not security.check_rate_limit(request.remote_addr):
            request_blocked = True
            block_reason = "Rate limit exceeded"
            security.blocked_requests += 1
            security.update_dashboard_stats()
            return jsonify({'error': block_reason}), 429

        # 3b. Scanner Detection
        sensitive_paths = ['/admin', '/wp-admin', '/phpmyadmin', '/.env', '/config', '/backup', '/etc/passwd']
        if any(path in request.path for path in sensitive_paths):
            request_blocked = True
            block_reason = "Scanner detected"
            security.log_to_dashboard(
                "Scanner", 
                request.remote_addr, 
                f"Accessed sensitive path: {request.path}", 
                "Medium",
                endpoint=request.path,
                method=request.method,
                detection_type="Scanner",
                blocked=True
            )
            security.blocked_requests += 1
            security.update_dashboard_stats()
            return jsonify({"error": "Not Found"}), 404

        # 3c. Content Security Scan (SQLi, XSS, ML)
        data_to_scan = {}
        if request.args:
            data_to_scan.update(request.args.to_dict())
        if request.is_json:
            try:
                data = request.get_json()
                if data:
                    data_to_scan.update(data)
            except:
                pass
        
        if data_to_scan:
            safe, msg = security.check_request_security(data_to_scan, request.remote_addr)
            if not safe:
                request_blocked = True
                block_reason = msg
                security.blocked_requests += 1
                security.update_dashboard_stats()
                return jsonify({'error': msg}), 400
        
        # Step 5: Update metrics for allowed requests
        # Count all non-blocked requests except GET, POST, PUT, PATCH, DELETE
        if not request_blocked and request.method not in ['GET', 'POST', 'PUT', 'PATCH', 'DELETE']:
            security.total_requests += 1
        
        security.update_dashboard_stats()
    
    @app.after_request
    def after_request(response):
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        return response
    
    @app.route('/')
    def index():
        return {
            'status': 'running',
            'message': 'API Security System Active',
            'security_level': 'high',
            'version': '1.1.0'
        }
    
    @app.route('/health')
    def health():
        return {
            'status': 'healthy',
            'uptime': time.time() - security.start_time,
            'total_requests': security.total_requests,
            'blocked_requests': security.blocked_requests
        }
    
    @app.route('/api/health')
    def api_health():
        return jsonify({
            'connected': True,
            'status': 'healthy',
            'timestamp': time.time()
        })
    
    @app.route('/api/data', methods=['POST'])
    def api_data():
        # Scanned in before_request
        return jsonify({
            'message': 'Data accepted',
            'id': int(time.time()),
            'processed_at': time.time()
        }), 201
    
    @app.route('/api/users', methods=['GET'])
    def get_users():
        # Scanned in before_request (query params)
        users = [
            {'id': 1, 'username': 'admin', 'role': 'administrator'},
            {'id': 2, 'username': 'user1', 'role': 'user'},
            {'id': 3, 'username': 'user2', 'role': 'user'}
        ]
        return jsonify({'users': users})
    
    @app.route('/api/login', methods=['POST'])
    def login():
        # Scanned in before_request
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')
        
        if username == 'admin' and password == 'secure123':
            return jsonify({'message': 'Login successful'})
        else:
            security.brute_force_count += 1
            security.log_to_dashboard(
                "Brute Force", 
                request.remote_addr, 
                f"Failed login: {username}",
                "Medium",
                endpoint=request.path,
                method=request.method,
                snippet=f"user: {username}",
                detection_type="Other",
                blocked=False
            )
            return jsonify({'error': 'Invalid credentials'}), 401
    
    @app.route('/api/security/stats')
    def security_stats():
        return jsonify({
            'total_requests': security.total_requests,
            'blocked_requests': security.blocked_requests,
            'sql_injection_attempts': security.sql_injection_count,
            'xss_attempts': security.xss_count,
            'brute_force_attempts': security.brute_force_count,
            'uptime': time.time() - security.start_time
        })
    
    return app

if __name__ == '__main__':
    print("🛡️ API Security System with ML Started")
    app = create_simple_app()
    app.run(host="127.0.0.1", port=5000, debug=True)
