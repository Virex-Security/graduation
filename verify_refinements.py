import requests
import time

API_URL = "http://127.0.0.1:5000"

def test_strict_rate_limit():
    print("\n[+] Testing Strict Rate Limit (3 req / 10s)...")
    
    # 3 requests should succeed
    for i in range(3):
        resp = requests.get(f"{API_URL}/")
        print(f"Req {i+1}: {resp.status_code}")
        assert resp.status_code == 200
    
    # 4th request should fail with 429
    resp = requests.get(f"{API_URL}/")
    print(f"Req 4: {resp.status_code}")
    assert resp.status_code == 429
    print("✅ Strict rate limit (3/10s) verified")

def test_ip_blocking():
    print("\n[+] Testing IP Blocking after 10 infringements...")
    # We already did 1 infringement in the previous test
    
    for i in range(2, 11):
        # Wait a bit if needed to ensure we're still in the infringement logic
        # Actually our logic increments infringement_count every time a request is blocked
        # To trigger it again, we need to be over the limit
        resp = requests.get(f"{API_URL}/")
        print(f"Infringement {i}: {resp.status_code}")
        assert resp.status_code == 429
    
    # 11th infringement attempt (which is the 10th block event)
    # The 10th one should trigger the block
    print("[+] Attempting final infringement to trigger permanent block...")
    resp = requests.get(f"{API_URL}/")
    print(f"Final Attempt: {resp.status_code}")
    
    # Now the IP should be in blocked_ips
    # Even after waiting 10 seconds, it should still be blocked
    print("[+] Waiting 12 seconds to see if block is permanent...")
    time.sleep(12)
    resp = requests.get(f"{API_URL}/")
    print(f"Post-wait Attempt: {resp.status_code}")
    assert resp.status_code == 429 or resp.status_code == 403 # Simple app currently returns generic error or handled by after_request which might be 429
    # In my implementation, check_rate_limit returns False if in blocked_ips, which leads to 429 in before_request
    print("✅ IP blocking verified")

if __name__ == "__main__":
    try:
        test_strict_rate_limit()
        test_ip_blocking()
        print("\n🎉 Refinement verification passed!")
    except Exception as e:
        print(f"\n❌ Verification failed: {e}")
