import urllib.request
import urllib.error
import json
import time

BASE_URL = "http://127.0.0.1:8000"

def make_request(method, path, data=None):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    req_data = json.dumps(data).encode("utf-8") if data else None
    
    req = urllib.request.Request(url, data=req_data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as response:
            res_body = response.read().decode("utf-8")
            return response.status, json.loads(res_body) if res_body else None
    except urllib.error.HTTPError as e:
        res_body = e.read().decode("utf-8")
        try:
            body_json = json.loads(res_body)
        except Exception:
            body_json = res_body
        return e.code, body_json

def run_tests():
    print("--- STARTING ARMORGUARD ENDPOINT TESTS ---")
    
    # 1. Test POST /consent
    print("\n1. Testing POST /consent...")
    status, body = make_request("POST", "/consent", {"targetUrl": "https://public-target.com"})
    print(f"Status: {status}")
    print(f"Response: {json.dumps(body, indent=2)}")
    consent_id = body.get("consentId") if isinstance(body, dict) else None
    
    # 2. Test POST /scan with missing consent on public target
    print("\n2. Testing POST /scan with missing consent on public target (Should fail)...")
    status, body = make_request("POST", "/scan", {"targetUrl": "https://public-target.com", "scanMode": "default"})
    print(f"Status: {status}")
    print(f"Response: {json.dumps(body, indent=2)}")
    
    # 3. Test POST /scan with wrong consent target mismatch
    print("\n3. Testing POST /scan with consent-target mismatch (Should fail)...")
    status, body = make_request("POST", "/scan", {
        "targetUrl": "https://another-public-target.com", 
        "scanMode": "default",
        "consentId": consent_id
    })
    print(f"Status: {status}")
    print(f"Response: {json.dumps(body, indent=2)}")

    # 4. Test POST /scan with custom mode and empty tools
    print("\n4. Testing POST /scan with custom mode and no selectedTools (Should fail)...")
    status, body = make_request("POST", "/scan", {
        "targetUrl": "http://localhost:5000",
        "scanMode": "custom",
        "selectedTools": []
    })
    print(f"Status: {status}")
    print(f"Response: {json.dumps(body, indent=2)}")

    # 5. Test POST /scan happy path (local target bypasses consent requirement)
    print("\n5. Testing POST /scan happy path (Local target)...")
    status, body = make_request("POST", "/scan", {
        "targetUrl": "http://localhost:5000",
        "scanMode": "default"
    })
    print(f"Status: {status}")
    print(f"Response: {json.dumps(body, indent=2)}")
    scan_id = body.get("scanId") if isinstance(body, dict) else None

    # 6. Test GET /scan/{scanId}
    if scan_id:
        print(f"\n6. Testing GET /scan/{scan_id}...")
        status, body = make_request("GET", f"/scan/{scan_id}")
        print(f"Status: {status}")
        print(f"Response: {json.dumps(body, indent=2)}")

    # 7. Test GET /report/{scanId}
    if scan_id:
        print(f"\n7. Testing GET /report/{scan_id}...")
        status, body = make_request("GET", f"/report/{scan_id}")
        print(f"Status: {status}")
        print(f"Response: {json.dumps(body, indent=2)}")

    # 8. Test GET /sessions
    print("\n8. Testing GET /sessions...")
    status, body = make_request("GET", "/sessions")
    print(f"Status: {status}")
    print(f"Response: {json.dumps(body, indent=2)}")

    # 9. Test GET /report/{scanId}/export (binary stream)
    if scan_id:
        print(f"\n9. Testing GET /report/{scan_id}/export...")
        url = f"{BASE_URL}/report/{scan_id}/export"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req) as r:
            content_type = r.headers.get("Content-Type")
            content_disposition = r.headers.get("Content-Disposition")
            data = r.read()
            print(f"Status: {r.status}")
            print(f"Content-Type: {content_type}")
            print(f"Content-Disposition: {content_disposition}")
            print(f"Returned PDF bytes size: {len(data)} bytes")

    print("\n--- ALL TESTS COMPLETED ---")

if __name__ == "__main__":
    run_tests()
