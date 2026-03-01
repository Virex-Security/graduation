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
import os
from dotenv import load_dotenv
from models import user_manager
from flask_cors import CORS

load_dotenv("env")

# ================= ML MODEL =================
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.model_selection import train_test_split

# Global model state
_model = None
_vectorizer = None
_model_lock = threading.Lock()
MODEL_LOADED = False
RETRAIN_INTERVAL = 3600  # retrain every 1 hour

def _load_or_train():
    """Load existing model or train from scratch."""
    global _model, _vectorizer, MODEL_LOADED
    try:
        _model      = joblib.load("model.pkl")
        _vectorizer = joblib.load("vectorizer.pkl")
        MODEL_LOADED = True
        print("✅ ML Model loaded from disk")
    except Exception:
        print("⚠️  No model found — training from scratch...")
        _retrain_model()

def _retrain_model():
    """Train/retrain the ML model from ml_training_data.csv."""
    global _model, _vectorizer, MODEL_LOADED
    try:
        data = pd.read_csv("ml_training_data.csv")
        X_train, X_test, y_train, y_test = train_test_split(
            data['text'], data['label'],
            test_size=0.2, random_state=42, stratify=data['label']
        )
        vec = TfidfVectorizer(ngram_range=(1, 2), max_features=5000, lowercase=True)
        X_tr = vec.fit_transform(X_train)
        clf  = RandomForestClassifier(n_estimators=100, max_depth=20, random_state=42, n_jobs=-1)
        clf.fit(X_tr, y_train)

        with _model_lock:
            _model      = clf
            _vectorizer = vec
            MODEL_LOADED = True

        joblib.dump(clf, "model.pkl")
        joblib.dump(vec, "vectorizer.pkl")

        from sklearn.metrics import accuracy_score
        acc = accuracy_score(y_test, clf.predict(vec.transform(X_test)))
        print(f"✅ ML Model retrained — Accuracy: {acc*100:.2f}%  Samples: {len(data)}")
    except Exception as e:
        print(f"❌ Retrain failed: {e}")

def _auto_retrain_loop():
    """Background thread: retrain model every RETRAIN_INTERVAL seconds."""
    while True:
        time.sleep(RETRAIN_INTERVAL)
        print("🔄 Auto-retraining ML model...")
        _retrain_model()

# Load model on startup
_load_or_train()

# Start background auto-retrain thread
_retrain_thread = threading.Thread(target=_auto_retrain_loop, daemon=True)
_retrain_thread.start()
print(f"🔄 Auto-retrain scheduled every {RETRAIN_INTERVAL//60} minutes")

def ml_detect(text):
    """Run ML model on text and return (is_attack, raw_prediction).

    The existing code simply returned a boolean, but we now expose the raw
    prediction value so that callers can make additional decisions. A log
    entry is also emitted showing the text snippet and prediction for
    debugging/analytics.
    """
    if not MODEL_LOADED:
        return False, None

    # bypass ML check for trivial strings (avoid false positives on things
    # like passwords or usernames)
    text_str = str(text)
    if len(text_str) <= 3:
        return False, 0
    if len(text_str) <= 20 and text_str.isalnum():
        return False, 0

    try:
        with _model_lock:
            X = _vectorizer.transform([text_str])
            raw = _model.predict(X)[0]
        is_att = raw == 1
        logger.debug(f"[ML DETECT] text='{' '.join(text_str.split()[:8])}' pred={raw}")
        return is_att, raw
    except Exception as e:
        logger.error(f"[ML DETECT] model error: {e}")
        return False, None


# Setup logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

class SimpleSecurityManager:
    """Simplified security manager for testing with ML integration"""
    
    def __init__(self):
        self.total_requests = 0
        self.blocked_requests = 0
        self.sql_injection_count = 0
        # track ML detections separately for metrics/logging
        self.ml_detections = 0
        self.xss_count = 0
        self.brute_force_count = 0
        self.rate_limit_hits = 0
        self.rate_limit_storage = defaultdict(deque)
        self.start_time = time.time()
        self.dashboard_url = os.getenv("DASHBOARD_URL", "http://127.0.0.1:8070")
        
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
        # Disabled pushing local memory stats to dashboard
        # Dashboard recalculates its own accurate stats from siem_audit.json
        pass
    
    # ================= REGEX =================
    def detect_sql_injection(self, text, ip):
        for pattern in self.compiled_sql_patterns:
            if pattern.search(text):
                self.sql_injection_count += 1
                logger.info(f"[REGEX-SQLi] Blocked {ip} — {text[:80]}")
                # blocked_requests will be incremented in before_request when request is rejected
                logger.debug(f"[REGEX-SQL] raw_text='{text[:80]}'")
                self.log_to_dashboard(
                    "SQL Injection", 
                    ip, 
                    f"[REGEX] SQL Injection detected — pattern matched in: {text[:60]}", 
                    "High",
                    endpoint=request.path,
                    method=request.method,
                    snippet=text[:100],
                    detection_type="Signature-based",
                    blocked=True
                )
                return True
        return False

    def detect_xss(self, text, ip):
        for pattern in self.compiled_xss_patterns:
            if pattern.search(text):
                self.xss_count += 1
                logger.info(f"[REGEX-XSS] Blocked {ip} — {text[:80]}")
                # blocked_requests will be incremented in before_request when request is rejected
                logger.debug(f"[REGEX-XSS] raw_text='{text[:80]}'")
                self.log_to_dashboard(
                    "XSS", 
                    ip, 
                    f"[REGEX] XSS detected — pattern matched in: {text[:60]}", 
                    "High",
                    endpoint=request.path,
                    method=request.method,
                    snippet=text[:100],
                    detection_type="Signature-based",
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
            logger.debug(f"[RATE] limit hit for ip={ip}")
            self.log_to_dashboard(
                "Rate Limit", 
                ip, 
                "Rate limit exceeded", 
                "Medium",
                endpoint=request.path,
                method=request.method,
                detection_type="Rule-based",
                blocked=True
            )
            return False

        q.append(now)
        return True
    
    # ================= MAIN SECURITY =================
    def check_request_security(self, data, ip):
        def classify_ml_attack(text):
            """Simple heuristic classifier to assign an attack type when the ML
            engine flags something as malicious. This is separate from the ML
            prediction itself, and runs only when ml_detect returns positive.
            """
            t = str(text)
            # reuse existing regex patterns for familiarity
            for patt in self.compiled_sql_patterns:
                if patt.search(t):
                    return "SQL Injection"
            for patt in self.compiled_xss_patterns:
                if patt.search(t):
                    return "XSS"
            if re.search(r"(password|login|user|admin)", t, re.IGNORECASE):
                return "Brute Force"
            return "Unknown"

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
                is_mal, raw_pred = ml_detect(text)
                if is_mal:
                    self.ml_detections += 1
                    attack_label = classify_ml_attack(text)
                    detection_method = "ML Model"
                    logger.info(
                        f"[ML-MODEL] {attack_label} flagged for {ip} "
                        f"(raw={raw_pred})"
                    )

                    # log full raw output for auditing
                    logger.debug(
                        f"[ML-RAW] text='{text[:100]}', attack_type='{attack_label}', "
                        f"detection_method='{detection_method}', prediction={raw_pred}"
                    )

                    self.log_to_dashboard(
                        attack_label,
                        ip,
                        f"[ML] Anomaly detected — suspicious payload: {text[:60]}",
                        "High",
                        endpoint=request.path,
                        method=request.method,
                        snippet=text[:100],
                        detection_type=detection_method,
                        blocked=True,
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
    CORS(app, resources={r"/api/*": {"origins": "*"}})
    security = SimpleSecurityManager()
    
    # Brute force tracker: {ip: [timestamp, ...]}
    brute_force_tracker = defaultdict(list)
    BRUTE_FORCE_LIMIT = 5       # max failed attempts
    BRUTE_FORCE_WINDOW = 60     # seconds
    BRUTE_FORCE_BLOCK_TIME = 300  # block for 5 minutes
    blocked_ips = {}            # {ip: unblock_timestamp}
    
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
        # Count all non-blocked business-relevant requests
        if not request_blocked and is_business:
            security.total_requests += 1
        
        security.update_dashboard_stats()
    
    @app.after_request
    def after_request(response):
        # Add security headers
        response.headers['X-Content-Type-Options'] = 'nosniff'
        response.headers['X-Frame-Options'] = 'DENY'
        response.headers['X-XSS-Protection'] = '1; mode=block'
        response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        response.headers['Content-Security-Policy'] = "default-src 'self'"
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
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
    
    # ── FAKE DATABASE ──────────────────────────────────────
    FAKE_USERS = [
        {'id': 1,  'username': 'ahmed.hassan',   'email': 'ahmed@shop.com',   'role': 'admin',    'joined': '2024-01-10', 'orders': 14},
        {'id': 2,  'username': 'sara.ali',        'email': 'sara@shop.com',    'role': 'user',     'joined': '2024-02-15', 'orders': 8},
        {'id': 3,  'username': 'omar.khalid',     'email': 'omar@shop.com',    'role': 'user',     'joined': '2024-03-01', 'orders': 22},
        {'id': 4,  'username': 'lina.mostafa',    'email': 'lina@shop.com',    'role': 'user',     'joined': '2024-03-20', 'orders': 5},
        {'id': 5,  'username': 'karim.farouk',    'email': 'karim@shop.com',   'role': 'manager',  'joined': '2024-04-05', 'orders': 0},
        {'id': 6,  'username': 'nour.ibrahim',    'email': 'nour@shop.com',    'role': 'user',     'joined': '2024-05-12', 'orders': 17},
        {'id': 7,  'username': 'youssef.samir',   'email': 'youssef@shop.com', 'role': 'user',     'joined': '2024-06-08', 'orders': 3},
        {'id': 8,  'username': 'dina.ramadan',    'email': 'dina@shop.com',    'role': 'user',     'joined': '2024-07-19', 'orders': 11},
    ]

    FAKE_ORDERS = [
        {'id': 1001, 'user': 'sara.ali',      'product': 'iPhone 15 Pro',       'price': 1299.99, 'status': 'delivered', 'date': '2025-01-05'},
        {'id': 1002, 'user': 'omar.khalid',   'product': 'Samsung Galaxy S24',  'price': 999.00,  'status': 'shipped',   'date': '2025-01-08'},
        {'id': 1003, 'user': 'ahmed.hassan',  'product': 'MacBook Air M3',      'price': 1499.00, 'status': 'delivered', 'date': '2025-01-12'},
        {'id': 1004, 'user': 'lina.mostafa',  'product': 'AirPods Pro',         'price': 249.99,  'status': 'pending',   'date': '2025-01-15'},
        {'id': 1005, 'user': 'nour.ibrahim',  'product': 'Sony WH-1000XM5',     'price': 349.00,  'status': 'delivered', 'date': '2025-01-18'},
        {'id': 1006, 'user': 'youssef.samir', 'product': 'iPad Pro 12.9',       'price': 1099.00, 'status': 'shipped',   'date': '2025-01-20'},
        {'id': 1007, 'user': 'dina.ramadan',  'product': 'Dell XPS 15',         'price': 1799.00, 'status': 'processing','date': '2025-01-22'},
        {'id': 1008, 'user': 'omar.khalid',   'product': 'Apple Watch Ultra 2', 'price': 799.00,  'status': 'delivered', 'date': '2025-01-25'},
        {'id': 1009, 'user': 'sara.ali',      'product': 'Logitech MX Master 3','price': 99.99,   'status': 'pending',   'date': '2025-01-28'},
        {'id': 1010, 'user': 'ahmed.hassan',  'product': 'LG OLED 4K 55"',      'price': 1599.00, 'status': 'shipped',   'date': '2025-02-01'},
    ]

    FAKE_PRODUCTS = [
        {'id': 1, 'name': 'iPhone 15 Pro',        'category': 'phones',      'price': 1299.99, 'stock': 45},
        {'id': 2, 'name': 'Samsung Galaxy S24',   'category': 'phones',      'price': 999.00,  'stock': 30},
        {'id': 3, 'name': 'MacBook Air M3',        'category': 'laptops',     'price': 1499.00, 'stock': 20},
        {'id': 4, 'name': 'Sony WH-1000XM5',       'category': 'audio',       'price': 349.00,  'stock': 60},
        {'id': 5, 'name': 'iPad Pro 12.9',         'category': 'tablets',     'price': 1099.00, 'stock': 25},
        {'id': 6, 'name': 'Dell XPS 15',           'category': 'laptops',     'price': 1799.00, 'stock': 15},
        {'id': 7, 'name': 'AirPods Pro',           'category': 'audio',       'price': 249.99,  'stock': 80},
        {'id': 8, 'name': 'Apple Watch Ultra 2',   'category': 'wearables',   'price': 799.00,  'stock': 35},
        {'id': 9, 'name': 'LG OLED 4K 55"',        'category': 'displays',    'price': 1599.00, 'stock': 12},
        {'id': 10,'name': 'Logitech MX Master 3',  'category': 'accessories', 'price': 99.99,   'stock': 100},
    ]

    # In-memory request log (last 50)
    request_log = deque(maxlen=50)

    def log_request(endpoint, method, ip, status, payload=""):
        request_log.appendleft({
            'time':     time.strftime("%H:%M:%S"),
            'endpoint': endpoint,
            'method':   method,
            'ip':       ip,
            'status':   status,
            'payload':  str(payload)[:80] if payload else ""
        })

    # ── ENDPOINTS ───────────────────────────────────────────

    @app.route('/api/users', methods=['GET'])
    def get_users():
        q = request.args.get('search', '').lower()
        results = [u for u in FAKE_USERS if q in u['username'].lower() or q in u['email'].lower()] if q else FAKE_USERS
        log_request('/api/users', 'GET', request.remote_addr, 200, q)
        return jsonify({'users': results, 'total': len(results)})

    @app.route('/api/orders', methods=['GET'])
    def get_orders():
        user_filter = request.args.get('user', '')
        results = [o for o in FAKE_ORDERS if user_filter in o['user']] if user_filter else FAKE_ORDERS
        log_request('/api/orders', 'GET', request.remote_addr, 200, user_filter)
        return jsonify({'orders': results, 'total': len(results)})

    @app.route('/api/products', methods=['GET'])
    def get_products():
        cat = request.args.get('category', '').lower()
        q   = request.args.get('search', '').lower()
        results = FAKE_PRODUCTS
        if cat and cat != 'all':
            results = [p for p in results if p['category'] == cat]
        if q:
            results = [p for p in results if q in p['name'].lower()]
        log_request('/api/products', 'GET', request.remote_addr, 200, q or cat)
        return jsonify({'products': results, 'total': len(results)})

    @app.route('/api/orders', methods=['POST'])
    def create_order():
        data = request.get_json() or {}
        new_order = {
            'id':      1000 + len(FAKE_ORDERS) + 1,
            'user':    data.get('user', 'guest'),
            'product': data.get('product', 'Unknown'),
            'price':   data.get('price', 0),
            'status':  'pending',
            'date':    time.strftime("%Y-%m-%d")
        }
        FAKE_ORDERS.append(new_order)
        log_request('/api/orders', 'POST', request.remote_addr, 201, new_order['product'])
        return jsonify({'message': 'Order created', 'order': new_order}), 201

    @app.route('/api/logs', methods=['GET'])
    def get_logs():
        return jsonify({'logs': list(request_log), 'total': len(request_log)})
    
    @app.route('/api/login', methods=['POST'])
    def login():
        # Scanned in before_request
        data = request.get_json() or {}
        username = data.get('username')
        password = data.get('password')
        
        ip = request.remote_addr
        now = time.time()

        # Check if IP is currently blocked
        if ip in blocked_ips:
            if now < blocked_ips[ip]:
                remaining = int(blocked_ips[ip] - now)
                security.log_to_dashboard(
                    "Brute Force", ip,
                    f"Blocked IP tried to login: {username}",
                    "High",
                    endpoint=request.path, method=request.method,
                    snippet=f"user: {username}",
                    detection_type="Brute Force", blocked=True
                )
                security.blocked_requests += 1
                security.update_dashboard_stats()
                return jsonify({'error': f'IP blocked for {remaining} seconds'}), 429
            else:
                del blocked_ips[ip]

        verified_user = user_manager.verify_password(username, password) if username and password else None
        if verified_user:
            # Reset failed attempts on success
            brute_force_tracker[ip] = []
            return jsonify({'message': 'Login successful', 'role': verified_user['role']})
        else:
            # Track failed attempt
            attempts = brute_force_tracker[ip]
            attempts = [t for t in attempts if now - t < BRUTE_FORCE_WINDOW]
            attempts.append(now)
            brute_force_tracker[ip] = attempts
            security.brute_force_count += 1

            if len(attempts) >= BRUTE_FORCE_LIMIT:
                # Block the IP
                blocked_ips[ip] = now + BRUTE_FORCE_BLOCK_TIME
                security.log_to_dashboard(
                    "Brute Force", ip,
                    f"IP blocked after {BRUTE_FORCE_LIMIT} failed logins: {username}",
                    "High",
                    endpoint=request.path, method=request.method,
                    snippet=f"user: {username}",
                    detection_type="Brute Force", blocked=True
                )
                security.blocked_requests += 1
                security.update_dashboard_stats()
                return jsonify({'error': 'Too many failed attempts. IP blocked for 5 minutes.'}), 429
            else:
                security.log_to_dashboard(
                    "Brute Force", ip,
                    f"Failed login attempt {len(attempts)}/{BRUTE_FORCE_LIMIT}: {username}",
                    "Medium",
                    endpoint=request.path, method=request.method,
                    snippet=f"user: {username}",
                    detection_type="Brute Force", blocked=False
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
    api_port = int(os.getenv("API_PORT", 5000))
    app.run(host="0.0.0.0", port=api_port, debug=True)
