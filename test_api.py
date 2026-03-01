import requests

admin_resp = requests.post('http://127.0.0.1:8070/api/auth/login', json={'username':'admin','password':'admin123'})
token = admin_resp.cookies.get('auth_token')
print('token', token)

dashboard = requests.get('http://127.0.0.1:8070/api/dashboard/data', cookies={'auth_token':token})
print('dash status', dashboard.status_code)
print('dash keys', dashboard.json().keys())
print('attack_indicators', dashboard.json().get('attack_indicators'))

ml = requests.get('http://127.0.0.1:8070/api/ml/stats', cookies={'auth_token':token})
print('ml status', ml.status_code)
print('ml attack_indicators', ml.json().get('attack_indicators'))
