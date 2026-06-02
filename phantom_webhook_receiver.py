#!/usr/bin/env python3
"""
Phantom Agent Webhook Receiver with Session Tracking and Telegram Logging
Receives scan completion notifications, creates agent sessions, explores targets,
and submits findings with full monitoring via the NyuwunSewu API.
"""
import os
import json
import hmac
import hashlib
import asyncio
import aiohttp
import threading
import traceback
from http.server import HTTPServer, BaseHTTPRequestHandler
from datetime import datetime, timezone

# File-based logging for background threads
LOG_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "phantom_receiver.log")

def log(msg: str):
    """Write to both stdout and log file (thread-safe)."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass

# Configuration
WEBHOOK_PORT = int(os.getenv("PHANTOM_WEBHOOK_PORT", "8080"))
WEBHOOK_SECRET = os.getenv("PHANTOM_WEBHOOK_SECRET", "webhook-signing-secret")
NYUWUNSEWU_URL = os.getenv("NYUWUNSEWU_URL", "http://127.0.0.1:8000")
AGENT_SECRET = os.getenv("PHANTOM_AGENT_SECRET", "phantom-agent-secret-2026")

class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Read and parse the payload
        content_length = int(self.headers.get('Content-Length', 0))
        body = self.rfile.read(content_length)
        
        # Verify signature if present
        signature = self.headers.get('x-nyuwunsewu-signature', '')
        if signature:
            expected = f"sha256={hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()}"
            if not hmac.compare_digest(signature, expected):
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Invalid signature")
                return
        
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON")
            return
        
        event = payload.get('event', '')
        scan_id = payload.get('scan_id', '')
        
        log(f"\n📡 Webhook received: {event}")
        log(f"   Scan ID: {scan_id}")
        log(f"   Target: {payload.get('target_url', 'N/A')}")
        log(f"   Status: {payload.get('status', 'N/A')}")
        log(f"   Findings: {payload.get('findings_count', 0)}")
        log(f"   Endpoints: {payload.get('endpoints_count', 0)}")
        
        if event == "scan.completed":
            log("\n🤖 Triggering Phantom agent exploration (background)...")
            # Spawn exploration in background thread — respond to webhook immediately
            t = threading.Thread(
                target=_run_exploration,
                args=(scan_id, payload.get('target_url', '')),
                daemon=True
            )
            t.start()
        elif event == "scan.failed":
            log("\n❌ Scan failed:")
            log(f"   Error: {payload.get('error', 'Unknown')}")
        
        # Respond immediately to prevent BrokenPipeError
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")
    
    def log_message(self, format, *args):
        pass  # Suppress default logging

async def get_auth_token() -> str | None:
    """Login to get JWT token for API calls."""
    try:
        import urllib.request, urllib.parse, json
        login_url = f"{NYUWUNSEWU_URL}/auth/login"
        admin_pw = os.getenv("ADMIN_PASSWORD", "ChangeMe123!")
        log(f"   🔑 Attempting login with email: admin@nyuwunsewu.local (PW length: {len(admin_pw)})")
        payload = json.dumps({"email": "admin@nyuwunsewu.local", "password": admin_pw}).encode()
        req = urllib.request.Request(login_url, data=payload, headers={"Content-Type": "application/json"})
        with urllib.request.urlopen(req, timeout=20) as resp:
            data = json.loads(resp.read())
            token = data.get("access_token")
            log(f"   🔑 Authenticated, token: {token[:20]}...")
            return token
    except Exception as e:
        log(f"   ❌ Auth failed: {e}")
        return None

def _run_exploration(scan_id: str, target_url: str):
    """Wrapper to run async exploration in a background thread with error handling."""
    try:
        asyncio.run(explore_target(scan_id, target_url))
    except Exception as e:
        log(f"❌ Background exploration crashed: {e}")
        log(traceback.format_exc())

async def explore_target(scan_id: str, target_url: str):
    """Simulate Phantom agent exploring the target after scan completion."""
    session_id = None
    # Get auth token first
    token = await get_auth_token()
    if not token:
        log("   ❌ Cannot proceed without authentication")
        return
    auth_headers = {"Content-Type": "application/json", "Authorization": f"Bearer {token}"}
    async with aiohttp.ClientSession() as session:
        try:
            # Step 1: Create agent session
            log("\n📝 Creating agent session...")
            async with session.post(
                f"{NYUWUNSEWU_URL}/agent-sessions",
                headers=auth_headers,
                json={
                    "scan_id": scan_id,
                    "target_url": target_url,
                    "agent_name": "phantom"
                }
            ) as resp:
                if resp.status == 201:
                    data = await resp.json()
                    session_id = data.get('id')
                    log(f"   ✅ Session created: {session_id[:8]}")
                else:
                    body = await resp.text()
                    log(f"   ❌ Failed to create session: {resp.status} {body}")
                    return
            
            # Step 2: Log exploration start
            await add_log(session, session_id, "info", "Starting exploration as nasabah", "login", auth_headers=auth_headers)
            
            # Step 3: Simulate exploration steps
            steps = [
                ("Logging in as customer...", "login"),
                ("Exploring dashboard...", "navigation"),
                ("Checking account endpoints...", "api_discovery"),
                ("Testing transfer flows...", "transaction_test"),
                ("Probing admin panels...", "admin_probe"),
                ("Testing for IDOR vulnerabilities...", "idor_test"),
                ("Checking for XSS...", "xss_test"),
                ("Analyzing JWT tokens...", "jwt_analysis"),
            ]
            
            for message, action in steps:
                await add_log(session, session_id, "info", message, action, auth_headers=auth_headers)
                await asyncio.sleep(2)  # Simulate work
            
            # Step 4: Request approval for a risky action
            await add_log(session, session_id, "warning", "Found potential IDOR vulnerability, requesting approval to exploit", "idor_exploit", auth_headers=auth_headers)
            
            # Step 5: Simulate finding a vulnerability
            await add_log(session, session_id, "success", "IDOR confirmed: can access other users' accounts", "idor_confirmed", auth_headers=auth_headers)
            
            # Step 6: Submit finding
            await submit_finding(session, session_id, scan_id, target_url, auth_headers=auth_headers)
            
            # Step 7: Complete session
            await complete_session(session, session_id, findings_count=1, auth_headers=auth_headers)
            
            log("\n✅ Phantom agent exploration complete!")
            
        except Exception as e:
            log(f"\n❌ Exploration failed: {e}")
            if session_id:
                await add_log(session, session_id, "error", f"Exploration failed: {str(e)}", "error")

async def add_log(session: aiohttp.ClientSession, session_id: str, level: str, message: str, action: str = None, auth_headers: dict = None):
    """Add a log entry to the agent session."""
    headers = auth_headers or {"Content-Type": "application/json"}
    try:
        async with session.post(
            f"{NYUWUNSEWU_URL}/agent-sessions/{session_id}/log",
            headers=headers,
            json={
                "session_id": session_id,
                "level": level,
                "message": message,
                "action": action
            }
        ) as resp:
            if resp.status == 200:
                log(f"   📝 Log: {message}")
            else:
                body = await resp.text()
                log(f"   ❌ Failed to add log: {resp.status} {body}")
    except Exception as e:
        log(f"   ❌ Log error: {e}")

async def submit_finding(session: aiohttp.ClientSession, session_id: str, scan_id: str, target_url: str, auth_headers: dict = None):
    """Submit a finding to NyuwunSewu."""
    finding_data = {
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
        "request_url": f"{target_url}/api/accounts/124",
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
    }
    
    try:
        async with session.post(
            f"{NYUWUNSEWU_URL}/findings/ingest",
            headers={
                "Content-Type": "application/json",
                "X-Agent-Secret": AGENT_SECRET
            },
            json=finding_data
        ) as resp:
            if resp.status == 201:
                data = await resp.json()
                log(f"   ✅ Finding submitted: {data.get('finding_id', 'unknown')}")
            else:
                body = await resp.text()
                log(f"   ❌ Failed to submit finding: {resp.status} {body}")
    except Exception as e:
        log(f"   ❌ Finding submission error: {e}")

async def complete_session(session: aiohttp.ClientSession, session_id: str, findings_count: int = 0, auth_headers: dict = None):
    """Mark the agent session as completed."""
    headers = auth_headers or {"Content-Type": "application/json"}
    try:
        async with session.post(
            f"{NYUWUNSEWU_URL}/agent-sessions/{session_id}/complete",
            headers=headers,
            params={"findings_count": findings_count}
        ) as resp:
            if resp.status == 200:
                log(f"   ✅ Session completed with {findings_count} findings")
            else:
                body = await resp.text()
                log(f"   ❌ Failed to complete session: {resp.status} {body}")
    except Exception as e:
        log(f"   ❌ Session completion error: {e}")

def main():
    print("🚀 Phantom Agent Webhook Receiver")
    print("=" * 50)
    print(f"Port: {WEBHOOK_PORT}")
    print(f"Secret: {WEBHOOK_SECRET[:4]}***")
    print(f"NyuwunSewu URL: {NYUWUNSEWU_URL}")
    print("\nListening for webhooks...")
    print("Press Ctrl+C to stop\n")
    
    server = HTTPServer(('0.0.0.0', WEBHOOK_PORT), WebhookHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down webhook receiver...")
        server.shutdown()

if __name__ == "__main__":
    main()
