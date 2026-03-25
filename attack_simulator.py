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
        self.user_agents = [ ... ]  # نفس القائمة القديمة (ما غيرتهاش)
        self.scanner_agents = [ ... ]  # نفس القائمة القديمة
        self.referers = [ ... ]  # نفس القائمة القديمة
        self.accept_languages = ["en-US,en;q=0.9", "ar-EG,ar;q=0.9,en;q=0.8"]
        self.legit_users = ["ahmed.hassan", "sara.ali", "omar.khalid", "lina.mostafa", "nour.ibrahim"]

    # ... (كل الدوال القديمة _random_ip, _client_context, _request, _pause, sql_injection_attacks, xss_attacks, dos_attacks, brute_force_login, scanner_simulation, legitimate_traffic تبقى كما هي)

    # ====================== الدوال الجديدة ======================

    def csrf_attacks(self, num_attacks=12):
        """Simulate CSRF attacks (missing or forged token)"""
        print(f"Simulating {num_attacks} CSRF attempts...")
        for index in range(num_attacks):
            context = self._client_context("attacker")
            payload = {
                "name": "Test User",
                "email": f"client{random.randint(100,999)}@mail.com",
                "amount": random.randint(50, 500),
                "action": "transfer"
            }

            # بدون CSRF token (الحالة الأكثر شيوعاً)
            try:
                response = self._request("POST", "/api/data", context, json_data=payload)
                print(f"[CSRF] {index+1}/{num_attacks} ip={context['ip']} status={response.status_code} (No Token)")
            except Exception as e:
                print(f"[CSRF] {index+1}/{num_attacks} failed: {e}")

            self._pause(0.2, 0.8)

    def ssrf_attacks(self, num_attacks=10):
        """Simulate SSRF attacks targeting internal services"""
        print(f"Simulating {num_attacks} SSRF attempts...")
        internal_urls = [
            "http://127.0.0.1/admin",
            "http://localhost:8080",
            "http://169.254.169.254/latest/meta-data/",
            "http://192.168.1.1",
            "http://10.0.0.1",
            "https://metadata.google.internal",
            "http://169.254.169.254/computeMetadata/v1/",
        ]

        for index in range(num_attacks):
            context = self._client_context("attacker")
            url = random.choice(internal_urls)
            payload = {"url": url, "fetch": "true", "target": url}

            try:
                response = self._request("POST", "/api/data", context, json_data=payload)
                print(f"[SSRF] {index+1}/{num_attacks} ip={context['ip']} status={response.status_code} url={url}")
            except Exception as e:
                print(f"[SSRF] {index+1}/{num_attacks} failed: {e}")

            self._pause(0.25, 0.9)

    def path_traversal_attacks(self, num_attacks=8):
        """Simulate Path Traversal attacks"""
        print(f"Simulating {num_attacks} Path Traversal attempts...")
        payloads = [
            "../../../etc/passwd",
            "..%2F..%2F..%2Fwindows%2Fwin.ini",
            "/api/data/../../../../../etc/passwd",
            "../../../../etc/shadow",
            "..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
        ]
        for index in range(num_attacks):
            context = self._client_context("attacker")
            payload = random.choice(payloads)
            try:
                response = self._request("GET", f"/api/data?file={payload}", context)
                print(f"[Path Traversal] {index+1}/{num_attacks} ip={context['ip']} status={response.status_code}")
            except Exception as e:
                print(f"[Path Traversal] failed: {e}")
            self._pause()

    def command_injection_attacks(self, num_attacks=8):
        """Simulate Command Injection"""
        print(f"Simulating {num_attacks} Command Injection attempts...")
        payloads = [
            "test; ls -la",
            "test | whoami",
            "test && id",
            "$(cat /etc/passwd)",
            "`id`",
            "test; ping -c 3 127.0.0.1",
        ]
        for index in range(num_attacks):
            context = self._client_context("attacker")
            payload = random.choice(payloads)
            try:
                response = self._request("POST", "/api/data", context, json_data={"command": payload, "exec": "true"})
                print(f"[Command Injection] {index+1}/{num_attacks} ip={context['ip']} status={response.status_code}")
            except Exception as e:
                print(f"[Command Injection] failed: {e}")
            self._pause()

    # ====================== تحديث المحاكاة المختلطة ======================

    def mixed_attack_simulation(self, duration_seconds=60):
        """Run mixed realistic traffic and attack bursts"""
        print(f"Running mixed simulation for {duration_seconds} seconds...")

        start_time = time.time()
        while time.time() - start_time < duration_seconds:
            action = random.choices(
                ["legitimate", "sql_injection", "xss", "brute_force", "scanner", "csrf", "ssrf", "path_traversal", "command_injection"],
                weights=[48, 10, 10, 8, 7, 7, 6, 2, 2],   # weights محدثة
                k=1,
            )[0]

            if action == "legitimate":
                self.legitimate_traffic(random.randint(2, 6))
            elif action == "sql_injection":
                self.sql_injection_attacks(random.randint(1, 3))
            elif action == "xss":
                self.xss_attacks(random.randint(1, 3))
            elif action == "brute_force":
                self.brute_force_login(random.randint(3, 8))
            elif action == "scanner":
                self.scanner_simulation(random.randint(2, 6))
            elif action == "csrf":
                self.csrf_attacks(random.randint(2, 5))
            elif action == "ssrf":
                self.ssrf_attacks(random.randint(2, 4))
            elif action == "path_traversal":
                self.path_traversal_attacks(random.randint(1, 3))
            elif action == "command_injection":
                self.command_injection_attacks(random.randint(1, 3))

            self._pause(0.6, 2.0)

    # ====================== main ======================

def main():
    print("🚀 VIREX Attack Simulator - Updated with CSRF & SSRF")
    print("=" * 60)
    
    simulator = AttackSimulator()
    
    # Check API
    try:
        response = simulator.session.get(f"{simulator.base_url}/health")
        if response.status_code != 200:
            print("❌ API is not running. Start the application first.")
            return
    except Exception:
        print("❌ Cannot connect to API.")
        return

    print("✅ API is running. Starting simulation (Ctrl+C to stop)...\n")

    try:
        while True:
            simulator.mixed_attack_simulation(duration_seconds=random.randint(40, 90))
            print(f"→ Waiting before next cycle...\n")
            time.sleep(random.uniform(3, 8))
    except KeyboardInterrupt:
        print("\n✅ Simulation stopped by user.")

if __name__ == "__main__":
    main()