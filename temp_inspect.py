import requests
DASH='http://127.0.0.1:8070'
resp=requests.post(f"{DASH}/api/auth/login", json={"username":"admin","password":"admin123"})
token=resp.cookies.get('auth_token')
page=requests.get(f"{DASH}/ml-detections", cookies={"auth_token":token})
print('Brute Force present?', 'Brute Force' in page.text)
print('ML Model count', page.text.count('ML Model'))
# print a snippet around attack types
for line in page.text.splitlines():
    if 'Brute Force' in line or 'SQL Injection' in line or 'XSS' in line:
        print(line)
