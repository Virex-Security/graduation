import requests
import time
import json

DASHBOARD_URL = "http://127.0.0.1:8070"
API_URL = "http://127.0.0.1:5000"

def test_health():
    print("\n[+] Testing API Health...")
    try:
        resp = requests.get(f"{API_URL}/api/health")
        print(f"Status: {resp.status_code}, Body: {resp.json()}")
        assert resp.json().get("connected") == True
        print("✅ Health probe successful")
    except Exception as e:
        print(f"❌ Health probe failed: {e}")

def test_auth():
    print("\n[+] Testing Authentication...")
    # Test Admin Login
    login_data = {"username": "admin", "password": "admin123"}
    resp = requests.post(f"{DASHBOARD_URL}/api/auth/login", json=login_data)
    print(f"Admin Login: {resp.status_code}, Body: {resp.json()}")
    admin_token = resp.cookies.get("auth_token")
    
    # Test Viewer Login
    login_data = {"username": "viewer", "password": "viewer123"}
    resp = requests.post(f"{DASHBOARD_URL}/api/auth/login", json=login_data)
    print(f"Viewer Login: {resp.status_code}, Body: {resp.json()}")
    viewer_token = resp.cookies.get("auth_token")

    # Test Dashboard Data Access
    resp = requests.get(f"{DASHBOARD_URL}/api/dashboard/data", cookies={"auth_token": admin_token})
    print(f"Dashboard Data (Admin): {resp.status_code}")
    assert resp.status_code == 200

    # Test Reset (Viewer - should fail)
    resp = requests.post(f"{DASHBOARD_URL}/api/dashboard/reset", cookies={"auth_token": viewer_token})
    print(f"Reset Stats (Viewer): {resp.status_code}, Body: {resp.json()}")
    assert resp.status_code == 403

    # Test Reset (Admin - should succeed)
    resp = requests.post(f"{DASHBOARD_URL}/api/dashboard/reset", cookies={"auth_token": admin_token})
    print(f"Reset Stats (Admin): {resp.status_code}, Body: {resp.json()}")
    assert resp.status_code == 200
    print("✅ Auth and Role-based access verified")

def test_threat_detection():
    print("\n[+] Testing Threat Detection (Regex First)...")
    # SQL Injection (Regex should catch it)
    malicious_payload = {"id": "1' OR '1'='1"}
    resp = requests.post(f"{API_URL}/api/data", json=malicious_payload)
    print(f"SQL Injection Response: {resp.status_code}, Body: {resp.json()}")
    assert resp.status_code == 400
    assert "Malicious content detected" in resp.json().get("error")

    # XSS (Regex should catch it)
    malicious_payload = {"comment": "<script>alert(1)</script>"}
    resp = requests.post(f"{API_URL}/api/data", json=malicious_payload)
    print(f"XSS Response: {resp.status_code}, Body: {resp.json()}")
    assert resp.status_code == 400
    
    # Rate Limiting
    print("[+] Testing Rate Limiting...")
    for _ in range(110):
        requests.get(f"{API_URL}/")
    resp = requests.get(f"{API_URL}/")
    print(f"Rate Limit Response: {resp.status_code}, Body: {resp.json()}")
    assert resp.status_code == 429
    print("✅ Detection and Rate Limiting verified")

if __name__ == "__main__":
    test_health()
    test_auth()
    test_threat_detection()
    print("\n🎉 All tests passed!")
