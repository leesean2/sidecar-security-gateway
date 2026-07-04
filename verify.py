import time
import sys
import random
import requests

def print_result(test_name, success, message=""):
    status = "SUCCESS" if success else "FAILED"
    print(f"[{status}] {test_name}: {message}")

def safe_json(response):
    try:
        return response.json()
    except Exception:
        return response.text.strip()

def test_public_endpoints(base_url, client_ip):
    print(f"\n--- Running: Public Endpoints Test (IP: {client_ip}) ---")
    headers = {"X-Forwarded-For": client_ip}
    
    # 1. Test Home
    res1 = requests.get(f"{base_url}/", headers=headers)
    s1 = res1.status_code == 200
    print_result("GET / (Home)", s1, f"Status: {res1.status_code}, Body: {safe_json(res1)}")
    
    # 2. Test Products
    res2 = requests.get(f"{base_url}/products", headers=headers)
    s2 = res2.status_code == 200
    
    items_count = 0
    if s2:
        try:
            items_count = len(res2.json().get('products', []))
        except Exception:
            pass
            
    print_result("GET /products", s2, f"Status: {res2.status_code}, Items: {items_count}")
    return s1 and s2

def test_unauthorized_checkout(base_url, client_ip):
    print(f"\n--- Running: Unauthorized Checkout Test (IP: {client_ip}) ---")
    headers = {"X-Forwarded-For": client_ip}
    
    # POST /checkout without token (should be blocked by OPA inline)
    res = requests.post(f"{base_url}/checkout", headers=headers)
    success = res.status_code == 403
    print_result("POST /checkout (No JWT)", success, f"Status: {res.status_code} (Expected 403), Body: {safe_json(res)}")
    return success

def test_authorized_checkout(base_url, client_ip):
    print(f"\n--- Running: Authorized Normal Flow Test (IP: {client_ip}) ---")
    headers = {"X-Forwarded-For": client_ip}
    
    # Normal user flow: Home -> Products -> Add to Cart -> Checkout
    requests.get(f"{base_url}/", headers=headers)
    requests.get(f"{base_url}/products", headers=headers)
    requests.post(f"{base_url}/cart?item_id=1", headers=headers)
    
    # Now checkout with valid JWT
    headers["Authorization"] = "Bearer mock-jwt-alice"
    res = requests.post(f"{base_url}/checkout", headers=headers)
    
    success = res.status_code == 200
    print_result("POST /checkout (Valid JWT + Normal Flow)", success, f"Status: {res.status_code}, Response: {safe_json(res)}")
    return success

def test_rate_limiting(base_url, client_ip):
    print(f"\n--- Running: Rate Limiting Test (IP: {client_ip}) ---")
    headers = {"X-Forwarded-For": client_ip}
    
    # Send 25 rapid requests to trigger rate limit (threshold is 20)
    print("Sending 25 requests to /products rapidly...")
    blocked = False
    for i in range(25):
        try:
            res = requests.get(f"{base_url}/products", headers=headers, timeout=2)
            if res.status_code == 403:
                blocked = True
                print(f"Request {i+1}: Blocked (HTTP 403) - IP has been blacklisted!")
                break
        except Exception as e:
            print(f"Request {i+1} failed: {e}")
            
        time.sleep(0.05)
    
    if not blocked:
        print("Rate limit was not hit immediately. Waiting 12 seconds for log processing & policy bundle sync...")
        time.sleep(12)
        res = requests.get(f"{base_url}/products", headers=headers)
        blocked = res.status_code == 403
    
    print_result("Rate Limiting Enforcement", blocked, f"Final Status: {res.status_code if 'res' in locals() else 'Blocked'} (Expected 403)")
    return blocked

def test_workflow_violation(base_url, client_ip):
    print(f"\n--- Running: Workflow Violation (Bot Anomaly) Test (IP: {client_ip}) ---")
    headers = {
        "X-Forwarded-For": client_ip,
        "Authorization": "Bearer mock-jwt-bob"
    }
    
    # Skip home, products, cart. Go directly to checkout (violation!)
    print("Attempting direct checkout (skipping flow steps)...")
    res1 = requests.post(f"{base_url}/checkout", headers=headers)
    print(f"Request 1 (Direct Checkout): Status {res1.status_code} (Allowed initially because JWT is valid)")
    
    # Repeat violation to trigger blacklist (threshold = 2 violations)
    res2 = requests.post(f"{base_url}/checkout", headers=headers)
    print(f"Request 2 (Direct Checkout): Status {res2.status_code}")
    
    # Wait for the control plane to ingest logs, detect violation, and sync the new policy bundle
    print("Waiting 15 seconds for async anomaly detection and OPA sync...")
    time.sleep(15)
    
    # Request 3 should now be blocked even with the correct JWT
    res3 = requests.post(f"{base_url}/checkout", headers=headers)
    success = res3.status_code == 403
    
    print_result("Workflow Violation Detection", success, f"Request 3 Status: {res3.status_code} (Expected 403)")
    if success:
        print("Success! Bob was blacklisted for skipping checkout flow steps.")
    return success

if __name__ == "__main__":
    base_url = "http://localhost:30080"
    if len(sys.argv) > 1:
        base_url = sys.argv[1]
        
    print(f"Starting Sidecar Security Gateway verification tests targeting: {base_url}")
    
    try:
        # Check connection
        requests.get(f"{base_url}/", timeout=3)
    except Exception as e:
        print(f"Error connecting to gateway at {base_url}: {e}")
        print("Please verify that K8s pods are running and you have forwarded port 8000, or exposed NodePort 30080.")
        sys.exit(1)
        
    # Generate unique subnets/IPs for this run to avoid collisions with persistent Redis state
    run_id = random.randint(10, 254)
    ip_pub = f"192.168.{run_id}.10"
    ip_unauth = f"192.168.{run_id}.20"
    ip_auth = f"192.168.{run_id}.30"
    ip_rate = f"192.168.{run_id}.40"
    ip_bot = f"192.168.{run_id}.50"

    print(f"Simulating traffic for run_id={run_id} using IPs: {ip_pub}, {ip_unauth}, {ip_auth}, {ip_rate}, {ip_bot}")

    # Run tests
    test_public_endpoints(base_url, ip_pub)
    test_unauthorized_checkout(base_url, ip_unauth)
    test_authorized_checkout(base_url, ip_auth)
    test_rate_limiting(base_url, ip_rate)
    test_workflow_violation(base_url, ip_bot)
    
    print("\n--- Verification Completed ---")
