import csv
import random

def generate_normal_requests():
    """توليد طلبات عادية وشرعية"""
    normal_patterns = [
        "search query for {}",
        "user login with username {}",
        "fetch product details {}",
        "update profile name to {}",
        "get order status {}",
        "search books about {}",
        "filter results by {}",
        "sort items by {}",
        "view page number {}",
        "download file {}",
        "upload image {}",
        "create new post about {}",
        "edit comment text {}",
        "delete item id {}",
        "share link to {}",
        "save settings for {}",
        "load data from {}",
        "export report {}",
        "import contacts {}",
        "sync calendar {}",
    ]
    
    normal_values = [
        "python programming", "machine learning", "data science",
        "web development", "mobile apps", "database design",
        "user123", "admin_panel", "dashboard_view",
        "electronics", "laptops", "smartphones",
        "order_12345", "invoice_2024", "report_january",
        "home", "about", "contact", "products", "services",
        "morning", "evening", "weekend", "weekday",
        "pdf", "csv", "xlsx", "json", "xml",
    ]
    
    requests = []
    for _ in range(350):
        pattern = random.choice(normal_patterns)
        value = random.choice(normal_values)
        requests.append(pattern.format(value))
    
    return requests


def generate_sql_injection_attacks():
    """توليد هجمات SQL متنوعة"""
    sql_attacks = [
        "' OR '1'='1",
        "1' OR 1=1--",
        "admin'--",
        "' OR 'x'='x",
        "1' AND 1=1--",
        "'; DROP TABLE users--",
        "1' UNION SELECT NULL--",
        "' OR 1=1#",
        "1' OR '1'='1' /*",
        "admin' OR '1'='1",
        "' UNION SELECT username, password FROM users--",
        "1'; DELETE FROM products WHERE 1=1--",
        "' OR SLEEP(5)--",
        "1' AND EXISTS(SELECT * FROM users)--",
        "'; UPDATE users SET password='hacked'--",
        "1' UNION ALL SELECT NULL,NULL--",
        "' OR 1=1 LIMIT 1--",
        "admin'#",
        "' OR 'a'='a",
        "1' ORDER BY 10--",
        "'; EXEC xp_cmdshell('dir')--",
        "1' UNION SELECT 1,2,3--",
        "' AND 1=(SELECT COUNT(*) FROM users)--",
        "1'; WAITFOR DELAY '00:00:05'--",
        "' OR username IS NOT NULL--",
    ]
    
    attacks = []
    for _ in range(200):
        base_attack = random.choice(sql_attacks)
        variations = [
            base_attack,
            base_attack.upper(),
            base_attack.lower(),
            f"username={base_attack}",
            f"id={base_attack}",
            f"search={base_attack}",
        ]
        attacks.append(random.choice(variations))
    
    return attacks


def generate_xss_attacks():
    """توليد هجمات XSS متنوعة"""
    xss_attacks = [
        "<script>alert('XSS')</script>",
        "<img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>",
        "<iframe src=javascript:alert('XSS')>",
        "<body onload=alert('XSS')>",
        "javascript:alert('XSS')",
        "<script>document.cookie</script>",
        "<img src='x' onerror='alert(1)'>",
        "<svg/onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>",
        "<select onfocus=alert(1) autofocus>",
        "<textarea onfocus=alert(1) autofocus>",
        "<iframe src=data:text/html,<script>alert(1)</script>>",
        "<object data=javascript:alert(1)>",
        "<embed src=javascript:alert(1)>",
        "<script>window.location='http://evil.com'</script>",
        "<img src=x:alert(1) onerror=eval(src)>",
        "<svg><script>alert(1)</script></svg>",
        "<marquee onstart=alert(1)>",
        "<div onmouseover=alert(1)>hover</div>",
    ]
    
    attacks = []
    for _ in range(200):
        base_attack = random.choice(xss_attacks)
        variations = [
            base_attack,
            f"comment={base_attack}",
            f"name={base_attack}",
            f"message={base_attack}",
            f"description={base_attack}",
        ]
        attacks.append(random.choice(variations))
    
    return attacks


def save_to_csv(filename="ml_training_data.csv"):
    """حفظ البيانات في ملف CSV"""
    
    normal_data = generate_normal_requests()
    sql_data = generate_sql_injection_attacks()
    xss_data = generate_xss_attacks()
    
    all_data = []
    
    for text in normal_data:
        all_data.append({"text": text, "label": 0})
    
    for text in sql_data:
        all_data.append({"text": text, "label": 1})
    
    for text in xss_data:
        all_data.append({"text": text, "label": 1})
    
    random.shuffle(all_data)
    
    with open(filename, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['text', 'label'])
        writer.writeheader()
        writer.writerows(all_data)
    
    print(f"تم توليد {len(all_data)} صف بنجاح")
    print(f"الطلبات الطبيعية: {len(normal_data)}")
    print(f"هجمات SQL: {len(sql_data)}")
    print(f"هجمات XSS: {len(xss_data)}")
    print(f"الملف: {filename}")


if __name__ == "__main__":
    save_to_csv()
