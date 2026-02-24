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

def test_dobby(cookies, message, page_context=None, history=None):
    url = f"{BASE_URL}/api/chat"
    payload = {
        "message": message,
        "page_context": page_context,
        "history": history
    }
        
    response = requests.post(url, json=payload, cookies=cookies)
    
    if response.status_code == 200:
        data = response.json()
        print(f"\n[QUERY] {message}")
        print(f"[CONTEXT] {page_context.get('path') if page_context else 'None'}")
        print(f"[DOBBY] {data.get('response')}")
        print("-" * 50)
        return data.get('response')
    else:
        print(f"[-] Chat failed: {response.text}")
        return None

if __name__ == "__main__":
    print("Testing Dobby (Rule-based NLP Security Assistant)...")
    
    cookies = login("admin", "admin123")
    
    if cookies:
        # 1. Test Dashboard Persona
        print("\n--- Test 1: Dashboard Context ---")
        test_dobby(cookies, "Hello Dobby, what is the status?", 
                  page_context={"path": "/dashboard", "query": {}})
        
        # 2. Test Incidents Context
        print("\n--- Test 2: Incidents List Context ---")
        test_dobby(cookies, "What are these blocked incidents?", 
                  page_context={"path": "/incidents", "query": {"category": "Blocked"}})
        
        # 3. Test Memory (Simulated)
        print("\n--- Test 3: Conversation Memory ---")
        history = [
            {"role": "user", "content": "I am worried about IP 1.2.3.4"},
            {"role": "bot", "content": "I see that IP has attacked 5 times."}
        ]
        test_dobby(cookies, "Should I block it?", 
                  page_context={"path": "/dashboard", "query": {}},
                  history=history)