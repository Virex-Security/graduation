"""
VIREX Attack Simulator
Simulate realistic mixed traffic + attacks to test the WAF
"""

import os
import time
import random
from concurrent.futures import ThreadPoolExecutor
import uuid
from app.templates.requests import requests


# trigger IDE


class AttackSimulator:
    """Simulate various types of attacks against the API"""
    
    def __init__(self, base_url=None):
        self.base_url = base_url or os.getenv("API_URL", "http://localhost:5000")
        self.session = requests.Session()

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/123.0.0.0 Mobile Safari/537.36",
        ]

        self.scanner_agents = ["sqlmap/1.8.3#stable", "Nmap Scripting Engine", "Nikto/2.5.0", "masscan/1.3"]

        self.referers = [
            "https://shop.example.com/", "https://shop.example.com/products",
            "https://shop.example.com/cart", "https://shop.example.com/checkout",
        ]

        self.accept_languages = ["en-US,en;q=0.9", "ar-EG,ar;q=0.9,en;q=0.8"]
        self.legit_users = ["ahmed.hassan", "sara.ali", "omar.khalid", "lina.mostafa", "nour.ibrahim"]

    def _random_ip(self):
        return f"{random.randint(11, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def _client_context(self, client_type="normal") -> dict:
        if client_type == "scanner":
            agent = random.choice(self.scanner_agents)
            referer = ""
        else:
            agent = random.choice(self.user_agents)
            referer = random.choice(self.referers)

        return {
            "ip": self._random_ip(),
            "headers": {
                "User-Agent": agent,
                "Accept": "application/json, text/plain, */*",
                "Accept-Language": random.choice(self.accept_languages),
                "Referer": referer,
                "X-Forwarded-For": self._random_ip(),
                "X-Real-IP": self._random_ip(),
                "X-Request-ID": str(uuid.uuid4()),
            },
        }

    def _request(self, method: str, path: str, context: dict, params=None, json_data=None, timeout=4):
        url = f"{self.base_url}{path}"
        headers = dict(context["headers"])
        headers["X-Forwarded-For"] = context["ip"]
        headers["X-Real-IP"] = context["ip"]
        headers["X-Request-ID"] = str(uuid.uuid4())

        if method == "GET":
            return self.session.get(url, params=params, headers=headers, timeout=timeout)
        return self.session.post(url, json=json_data, headers=headers, timeout=timeout)

    def _pause(self, min_seconds=0.15, max_seconds=0.9):
        time.sleep(random.uniform(min_seconds, max_seconds))

    # ====================== الهجمات القديمة (كما هي) ======================

    def sql_injection_attacks(self, num_attacks=10):
        print(f"Simulating {num_attacks} SQL injection attempts...")
        sql_payloads = ["1' OR '1'='1' -- ", "' UNION SELECT username, password FROM users--", "admin'/**/OR/**/1=1#", "' OR SLEEP(3)--", "1;WAITFOR DELAY '0:0:2'--"]
        for i in range(num_attacks):
            context = self._client_context("attacker")
            payload = random.choice(sql_payloads)
            vector = random.choice(["users", "orders", "data", "login"])
            try:
                if vector == "users":
                    r = self._request("GET", "/api/users", context, params={"search": payload})
                elif vector == "orders":
                    r = self._request("GET", "/api/orders", context, params={"user": payload})
                elif vector == "data":
                    r = self._request("POST", "/api/data", context, json_data={"query": payload})
                else:
                    r = self._request("POST", "/api/login", context, json_data={"username": payload, "password": "test"})
                print(f"[SQLi] {i+1}/{num_attacks} ip={context['ip']} status={r.status_code}")
            except Exception as e:
                print(f"[SQLi] failed: {e}")
            self._pause()

    def xss_attacks(self, num_attacks=10):
        print(f"Simulating {num_attacks} XSS attempts...")
        xss_payloads = ["<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg/onload=alert(1)>"]
        for i in range(num_attacks):
            context = self._client_context("attacker")
            payload = random.choice(xss_payloads)
            body = {"name": "Test", "email": "test@mail.com", "comment": payload}
            try:
                r = self._request("POST", "/api/data", context, json_data=body)
                print(f"[XSS] {i+1}/{num_attacks} ip={context['ip']} status={r.status_code}")
            except Exception as e:
                print(f"[XSS] failed: {e}")
            self._pause()

    def dos_attacks(self, num_threads=8, requests_per_thread=15):
        print(f"Simulating DoS burst: {num_threads} threads...")
        def worker(wid):
            context = self._client_context("attacker")
            for _ in range(requests_per_thread):
                try:
                    self._request("POST", "/api/data", context, json_data={"data": "x" * random.randint(100, 800)})
                except:
                    pass
                self._pause(0.01, 0.05)
        with ThreadPoolExecutor(max_workers=num_threads) as exe:
            exe.map(worker, range(num_threads))

    def brute_force_login(self, num_attempts=20):
        print(f"Simulating {num_attempts} brute force attempts...")
        usernames = ["admin", "root", "ahmed.hassan", "support"]
        passwords = ["123456", "password", "admin123", "letmein"]
        context = self._client_context("attacker")
        for i in range(num_attempts):
            try:
                r = self._request("POST", "/api/login", context, 
                                  json_data={"username": random.choice(usernames), "password": random.choice(passwords)})
                print(f"[Brute] {i+1}/{num_attempts} ip={context['ip']} status={r.status_code}")
            except Exception as e:
                print(f"[Brute] failed: {e}")
            self._pause(0.1, 0.4)

    def scanner_simulation(self, num_scans=12):
        print(f"Simulating {num_scans} scanner probes...")
        paths = ["/admin", "/.env", "/wp-admin", "/phpmyadmin", "/backup.sql", "/.git/config"]
        context = self._client_context("scanner")
        for i in range(num_scans):
            try:
                r = self._request("GET", random.choice(paths), context)
                print(f"[Scanner] {i+1}/{num_scans} ip={context['ip']} path={r.request.url} status={r.status_code}")
            except Exception as e:
                print(f"[Scanner] failed: {e}")
            self._pause(0.05, 0.25)

    def legitimate_traffic(self, num_requests=40):
        print(f"Generating {num_requests} legitimate requests...")
        for i in range(num_requests):
            context = self._client_context("normal")
            op = random.choice(["products", "users", "orders", "data"])
            try:
                if op == "products":
                    self._request("GET", "/api/products", context, params={"category": random.choice(["phones","laptops"])})
                elif op == "users":
                    self._request("GET", "/api/users", context, params={"search": random.choice(["ahmed","sara"])})
                elif op == "orders":
                    self._request("GET", "/api/orders", context, params={"user": random.choice(self.legit_users)})
                else:
                    self._request("POST", "/api/data", context, json_data={
                        "name": random.choice(["Ahmed","Sara"]), 
                        "email": f"client{random.randint(10,999)}@mail.com",
                        "message": "Normal user message"
                    })
                if i % 10 == 0:
                    print(f"[Legit] {i+1}/{num_requests} ip={context['ip']}")
            except:
                pass
            self._pause(0.2, 1.2)

    # ====================== الثغرات الجديدة فقط (CSRF + SSRF) ======================

    def csrf_attacks(self, num_attacks=12):
        print(f"Simulating {num_attacks} CSRF attempts...")
        for i in range(num_attacks):
            context = self._client_context("attacker")
            data = {
                "name": "Victim User",
                "email": f"victim{random.randint(100,999)}@mail.com",
                "amount": random.randint(100, 5000),
                "action": "transfer"
            }
            try:
                r = self._request("POST", "/api/data", context, json_data=data)   # بدون CSRF Token
                print(f"[CSRF] {i+1}/{num_attacks} ip={context['ip']} status={r.status_code}")
            except Exception as e:
                print(f"[CSRF] failed: {e}")
            self._pause(0.2, 0.7)

    def ssrf_attacks(self, num_attacks=10):
        print(f"Simulating {num_attacks} SSRF attempts...")
        urls = [
            "http://127.0.0.1/admin",
            "http://localhost:8080",
            "http://169.254.169.254/latest/meta-data/",
            "http://192.168.1.1",
            "http://10.0.0.1",
            "http://metadata.google.internal"
        ]
        for i in range(num_attacks):
            context = self._client_context("attacker")
            target = random.choice(urls)
            try:
                r = self._request("POST", "/api/data", context, json_data={"url": target, "fetch": True})
                print(f"[SSRF] {i+1}/{num_attacks} ip={context['ip']} target={target[:60]}... status={r.status_code}")
            except Exception as e:
                print(f"[SSRF] failed: {e}")
            self._pause(0.25, 0.8)

    # ====================== المحاكاة العشوائية المختلطة ======================

    def mixed_attack_simulation(self, duration_seconds=90):
        """تشغيل دورة واحدة: كل ثغرة مرة واحدة بترتيب عشوائي مع ترافيك شرعي بين كل هجوم"""
        print(f"Running improved mixed simulation for {duration_seconds} seconds...\n")

        attack_funcs = [
            (lambda: self.sql_injection_attacks(random.randint(1, 3)), "SQL Injection"),
            (lambda: self.xss_attacks(random.randint(1, 3)), "XSS"),
            (lambda: self.brute_force_login(random.randint(3, 7)), "Brute Force"),
            (lambda: self.scanner_simulation(random.randint(2, 5)), "Scanner"),
            (lambda: self.dos_attacks(num_threads=random.randint(2, 4), requests_per_thread=8), "DoS"),
            (lambda: self.csrf_attacks(random.randint(2, 5)), "CSRF"),
            (lambda: self.ssrf_attacks(random.randint(1, 3)), "SSRF"),
        ]

        start = time.time()
        while time.time() - start < duration_seconds:
            # Shuffle attacks order every cycle
            random.shuffle(attack_funcs)
            for func, name in attack_funcs:
                print(f"\n--- [ATTACK] {name} ---")
                func()
                # Legitimate traffic between attacks
                print("[INFO] Generating legitimate traffic between attacks...")
                self.legitimate_traffic(random.randint(4, 10))
                self._pause(0.7, 2.0)
            print("\n[INFO] One full attack cycle finished.\n")
            self._pause(2.0, 4.0)

    def run(self):
        print("🚀 VIREX Attack Simulator Started (CSRF + SSRF Added)")
        print("=" * 65)

        try:
            self.session.get(f"{self.base_url}/health", timeout=3)
            print("✅ API is running.\n")
        except:
            print("❌ Cannot reach the API. Please start VIREX first!")
            return

        try:
            while True:
                self.mixed_attack_simulation(duration_seconds=random.randint(60, 130))
                print("→ Next simulation cycle starting soon...\n")
                time.sleep(random.uniform(5, 12))
        except KeyboardInterrupt:
            print("\n🛑 Simulation stopped by user.")


if __name__ == "__main__":
    simulator = AttackSimulator()
    simulator.run()