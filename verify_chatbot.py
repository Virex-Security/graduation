
import requests
import json
import time

BASE_URL = "http://127.0.0.1:8070"

def login(username, password):
    url = f"{BASE_URL}/api/auth/login"
    payload = {"username": username, "password": password}
    response = requests.post(url, json=payload)
    if response.status_code == 200:
        print(f"[+] Login successful as {username}")
        return response.cookies
    else:
        print(f"[-] Login failed: {response.text}")
        return None

def test_chat(cookies, message, incident_id=None):
    url = f"{BASE_URL}/api/chat"
    payload = {"message": message}
    if incident_id:
        payload["incident_id"] = incident_id
        
    response = requests.post(url, json=payload, cookies=cookies)
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n[QUERY] {message}")
        print(f"[RESPONSE] {data.get('response')}")
        print("-" * 50)
    else:
        print(f"[-] Chat failed: {response.text}")

if __name__ == "__main__":
    print("Testing Security Chatbot API...")
    
    # 1. Login as Admin
    cookies = login("admin", "admin123")
    
    if cookies:
        # 2. Test General Status
        test_chat(cookies, "What is the current system status?")
        
        # 3. Test Unknown Incident
        test_chat(cookies, "Analyze this incident", "INC-NONEXISTENT")
        
        # 4. Test Attack Logic (Mock)
        test_chat(cookies, "How do I block this IP?")

