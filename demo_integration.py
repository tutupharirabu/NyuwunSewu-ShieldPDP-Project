#!/usr/bin/env python3
"""
Phantom Agent Integration Demo
Demonstrates the complete workflow: scan → webhook → explore → exploit → report
"""
import json
import urllib.request
import time

# Configuration
BASE_URL = "http://127.0.0.1:8001"
AGENT_SECRET = "phantom-agent-secret-123456"
TARGET_URL = "https://vps-5092b876.tail25f2a6.ts.net"

def api_call(method, path, data=None, headers=None, auth_token=None):
    """Make an API call to NyuwunSewu."""
    url = f"{BASE_URL}{path}"
    req_headers = {"Content-Type": "application/json"}
    if auth_token:
        req_headers["Authorization"] = f"Bearer {auth_token}"
    if headers:
        req_headers.update(headers)
    
    req_data = json.dumps(data).encode() if data else None
    req = urllib.request.Request(url, data=req_data, headers=req_headers, method=method)
    
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read()), resp.status
    except urllib.error.HTTPError as e:
        return json.loads(e.read()), e.code

def login(email, password):
    """Login and get auth token."""
    data, status = api_call("POST", "/auth/login", {
        "email": email,
        "password": password
    })
    if status == 200:
        return data.get("access_token")
    raise Exception(f"Login failed: {data}")

def create_webhook(token):
    """Create a webhook subscription for scan completion."""
    print("\n📡 Creating webhook subscription...")
    data, status = api_call("POST", "/webhooks", {
        "name": "Phantom Agent Notification",
        "url": "http://phantom-agent:8080/webhook",  # Replace with actual agent endpoint
        "secret": "webhook-signing-secret",
        "events": ["scan.completed", "scan.failed"]
    }, auth_token=token)
    print(f"   Status: {status}")
    if status == 201:
        print(f"   Webhook ID: {data.get('id')}")
        print(f"   Events: {data.get('events')}")
        return data.get('id')
    print(f"   Error: {data}")
    return None

def start_scan(token):
    """Start a security scan."""
    print("\n🔍 Starting security scan...")
    data, status = api_call("POST", "/scan/start", {
        "target_url": TARGET_URL,
        "project_name": "Phantom Integration Test",
        "allowed_domains": ["vps-5092b876.tail25f2a6.ts.net"],
        "initial_paths": ["/login", "/api"],
        "exploit_chains": {
            "enabled": True,
            "modern_vuln_bank_probes": True
        },
        "policy": {
            "max_depth": 2,
            "max_pages": 100
        }
    }, auth_token=token)
    print(f"   Status: {status}")
    if status == 200:
        print(f"   Scan ID: {data.get('scan_id')}")
        return data.get('scan_id')
    print(f"   Error: {data}")
    return None

def wait_for_scan(token, scan_id):
    """Wait for scan to complete."""
    print("\n⏳ Waiting for scan to complete...")
    for i in range(30):
        time.sleep(10)
        data, status = api_call("GET", f"/scan/status?scan_id={scan_id}", auth_token=token)
        if status == 200:
            scan_status = data.get('status')
            progress = data.get('stats', {}).get('progress_percentage', 0)
            print(f"   Status: {scan_status} ({progress}%)")
            if scan_status in ['completed', 'failed']:
                return data
    return None

def get_findings(token, scan_id):
    """Get findings from the scan."""
    print("\n📊 Getting scan findings...")
    data, status = api_call("GET", f"/findings?scan_id={scan_id}", auth_token=token)
    if status == 200:
        print(f"   Found {len(data)} findings")
        for f in data[:5]:
            print(f"   - [{f.get('severity')}] {f.get('title')}")
        return data
    return []

def submit_agent_finding(scan_id):
    """Submit a finding as the Phantom agent."""
    print("\n🤖 Phantom agent submitting finding...")
    data, status = api_call("POST", "/findings/ingest", {
        "scan_id": scan_id,
        "finding_type": "idor_account_takeover",
        "title": "IDOR Allows Access to Other Users' Financial Data",
        "severity": "critical",
        "confidence": 95.0,
        "description": "By manipulating the account_id parameter in the API request, an authenticated user can access any other user's financial data without proper authorization checks.",
        "reasoning": [
            "Endpoint /api/accounts/{id} does not verify ownership",
            "Authenticated user can access any account by changing the ID parameter",
            "Tested with multiple account IDs, all returned valid data"
        ],
        "evidence": {
            "proof_of_concept": "Changed account_id from 123 to 124, received valid response",
            "affected_accounts": ["123", "124", "125"]
        },
        "request_method": "GET",
        "request_url": f"{TARGET_URL}/api/accounts/124",
        "request_headers": {"Authorization": "Bearer [REDACTED]"},
        "response_status": 200,
        "response_body": '{"account_id": 124, "owner": "Another User", "balance": 5000000}',
        "remediation": "Implement ownership verification on account endpoints. Check that the authenticated user owns the requested account before returning data.",
        "agent_name": "phantom",
        "exploit_chain": [
            "1. Registered as normal user (account_id: 123)",
            "2. Accessed own account at /api/accounts/123",
            "3. Changed ID to 124 in request",
            "4. Successfully accessed another user's account data",
            "5. Repeated for multiple accounts to confirm"
        ]
    }, headers={"X-Agent-Secret": AGENT_SECRET})
    print(f"   Status: {status}")
    if status == 201:
        print(f"   Finding ID: {data.get('finding_id')}")
        print(f"   Message: {data.get('message')}")
        return data.get('finding_id')
    print(f"   Error: {data}")
    return None

def main():
    print("🚀 Phantom Agent Integration Demo")
    print("=" * 50)
    
    # Step 1: Login
    print("\n🔐 Logging in as admin...")
    try:
        token = login("admin@nyuwunsewu.local", "ChangeMe123!")
        print(f"   ✅ Logged in successfully")
    except Exception as e:
        print(f"   ❌ Login failed: {e}")
        print("   Please ensure NyuwunSewu is running and bootstrapped")
        return
    
    # Step 2: Create webhook
    webhook_id = create_webhook(token)
    
    # Step 3: Start scan
    scan_id = start_scan(token)
    if not scan_id:
        return
    
    # Step 4: Wait for scan
    scan_result = wait_for_scan(token, scan_id)
    if not scan_result:
        print("   ⏰ Scan timeout - continuing anyway")
    
    # Step 5: Get findings
    findings = get_findings(token, scan_id)
    
    # Step 6: Submit agent finding
    agent_finding_id = submit_agent_finding(scan_id)
    
    # Step 7: Summary
    print("\n" + "=" * 50)
    print("📋 Integration Summary")
    print("=" * 50)
    print(f"Webhook ID: {webhook_id}")
    print(f"Scan ID: {scan_id}")
    print(f"Auto-detected findings: {len(findings)}")
    print(f"Agent-submitted findings: {1 if agent_finding_id else 0}")
    print("\n✅ Integration demo completed!")
    print("\nNext steps:")
    print("1. Review findings in NyuwunSewu dashboard")
    print("2. Generate combined report (auto + agent findings)")
    print("3. Track remediation workflow")

if __name__ == "__main__":
    main()
