import requests
import json
import time

BASE_URL = "http://127.0.0.1:8070"

def test_rbac():
    print("Starting RBAC Verification Tests...")
    session = requests.Session()

    # 1. Test Login - User
    print("\n[Test 1] Login as 'user'...")
    resp = session.post(f"{BASE_URL}/api/auth/login", json={
        "username": "user",
        "password": "user123"
    })
    if resp.status_code == 200:
        print("SUCCESS: User login successful")
        data = resp.json()
        print(f"Role assigned: {data.get('role')}")
    else:
        print(f"FAILED: User login failed with {resp.status_code}")
        print(resp.text)
        return

    # 2. Test Access Protected Route - User (should fail)
    print("\n[Test 2] Accessing /incidents as 'user' (should fail)...")
    resp = session.get(f"{BASE_URL}/incidents", allow_redirects=False)
    if resp.status_code == 403:
        print("SUCCESS: Access denied (403) correctly")
    else:
        print(f"FAILED: Expected 403, got {resp.status_code}")

    # 3. Test API Admin Access - User (should fail)
    print("\n[Test 3] Accessing /api/dashboard/reset as 'user' (should fail)...")
    resp = session.post(f"{BASE_URL}/api/dashboard/reset")
    if resp.status_code == 403:
        print("SUCCESS: API access denied correctly")
    else:
        print(f"FAILED: Expected 403, got {resp.status_code}")

    # 4. Test Chat Limited Mode - User
    print("\n[Test 4] Testing Dobby in limited mode (User)...")
    resp = session.post(f"{BASE_URL}/api/chat", json={
        "message": "What is the IP of the last attack?"
    })
    if resp.status_code == 200:
        reply = resp.json().get('response')
        # Encode/decode to handle emojis in windows terminal
        print(f"Dobby reply: {reply.encode('ascii', 'ignore').decode('ascii')}")
        if "XXX.XXX" in reply or "sorry" in reply.lower() or "عذراً" in reply:
            print("SUCCESS: Dobby restricted sensitive info")
        else:
            print("FAILED: Dobby did not restrict sensitive info")
    else:
        print(f"FAILED: Chat failed with {resp.status_code}")

    # 5. Logout
    print("\n[Test 5] Logging out...")
    session.get(f"{BASE_URL}/api/auth/logout")

    # 6. Test Login - Admin
    print("\n[Test 6] Login as 'admin'...")
    resp = session.post(f"{BASE_URL}/api/auth/login", json={
        "username": "admin",
        "password": "admin123"
    })
    if resp.status_code == 200:
        print("SUCCESS: Admin login successful")
    else:
        print(f"FAILED: Admin login failed")
        return

    # 7. Test Access Protected Route - Admin (should succeed)
    print("\n[Test 7] Accessing /incidents as 'admin' (should succeed)...")
    resp = session.get(f"{BASE_URL}/incidents")
    if resp.status_code == 200:
        print("SUCCESS: Admin access granted")
    else:
        print(f"FAILED: Expected 200, got {resp.status_code}")

    # 8. Test Chat Full Mode - Admin
    print("\n[Test 8] Testing Dobby in full mode (Admin)...")
    # First log a threat to have data
    session.post(f"{BASE_URL}/api/dashboard/threat", json={
        "type": "SQL Injection",
        "ip": "1.2.3.4",
        "description": "Verification Test"
    })
    time.sleep(1)
    resp = session.post(f"{BASE_URL}/api/chat", json={
        "message": "Who is the top attacker?"
    })
    if resp.status_code == 200:
        reply = resp.json().get('response')
        print(f"Dobby reply: {reply.encode('ascii', 'ignore').decode('ascii')}")
        if "1.2.3.4" in reply:
            print("SUCCESS: Dobby provided full info to admin")
        else:
            print("FAILED: Dobby did not provide full info to admin")
    else:
        print(f"FAILED: Chat failed")

    print("\nVerification Complete!")

if __name__ == "__main__":
    test_rbac()
