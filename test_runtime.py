import requests, time, json

BASE = 'http://127.0.0.1:5000'

def print_res(name, r):
    print(f'=== {name} ===')
    if r is None:
        print('No response')
    else:
        print('Status:', r.status_code)
        try:
            print('JSON:', r.json())
        except Exception:
            print('Text:', r.text)
    print()

# 1. Normal request
r = None
try:
    r = requests.get(f'{BASE}/api/health')
except Exception as e:
    print('Error normal request:', e)
print_res('Normal GET /api/health', r)

# 2. SQL Injection payload
payload = {'test': 'UNION SELECT password FROM users'}
try:
    r = requests.post(f'{BASE}/api/data', json=payload)
except Exception as e:
    print('Error SQLi request:', e)
print_res('SQL Injection POST /api/data', r)

# 3. XSS payload
payload = {'test': '<script>alert("xss")</script>'}
try:
    r = requests.post(f'{BASE}/api/data', json=payload)
except Exception as e:
    print('Error XSS request:', e)
print_res('XSS POST /api/data', r)

# 4. CSRF - POST without token
payload = {'product': 'test', 'price': 10}
try:
    r = requests.post(f'{BASE}/api/orders', json=payload)
except Exception as e:
    print('Error CSRF request:', e)
print_res('CSRF POST /api/orders', r)

# 5. SSRF payload
payload = {'url': 'http://169.254.169.254/latest/meta-data/iam/security-credentials/'}
try:
    r = requests.post(f'{BASE}/api/data', json=payload)
except Exception as e:
    print('Error SSRF request:', e)
print_res('SSRF POST /api/data', r)

# 6. Brute force - multiple failed logins
for i in range(7):
    try:
        r = requests.post(f'{BASE}/api/login', json={'username':'admin','password':'wrong'} )
    except Exception as e:
        print('Error login attempt:', e)
        r = None
    print_res(f'Brute force attempt {i+1}', r)
    time.sleep(0.5)

# 7. Rate limiting - rapid requests
for i in range(8):
    try:
        r = requests.get(f'{BASE}/api/health')
    except Exception as e:
        print('Error rate limit request:', e)
        r = None
    print_res(f'Rate limit request {i+1}', r)
    time.sleep(0.2)

# 8. ML detection - send suspicious payload (e.g., large random text)
payload = {'text': 'A' * 5000}
try:
    r = requests.post(f'{BASE}/api/data', json=payload)
except Exception as e:
    print('Error ML request:', e)
print_res('ML detection POST /api/data', r)
