#!/usr/bin/env python3
"""
Phantom Agent Webhook Receiver with Session Tracking and Telegram Logging
Receives scan completion notifications, creates agent sessions, explores targets,
and submits findings with full monitoring via the NyuwunSewu API.
"""

import asyncio
import hashlib
import hmac
import json
import os
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

import aiohttp

# Configuration
WEBHOOK_PORT = int(os.getenv("PHANTOM_WEBHOOK_PORT", "8080"))
WEBHOOK_SECRET = os.getenv("PHANTOM_WEBHOOK_SECRET", "")
NYUWUNSEWU_URL = os.getenv("NYUWUNSEWU_URL", "http://127.0.0.1:8000").rstrip("/")
AGENT_SECRET = os.getenv("PHANTOM_AGENT_SECRET", "")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@nyuwunsewu.local")
# Support both ADMIN_PASSWORD (receiver convention) and BOOTSTRAP_ADMIN_PASSWORD (backend convention)
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD") or os.getenv(
    "BOOTSTRAP_ADMIN_PASSWORD", ""
)
ENVIRONMENT = os.getenv("ENVIRONMENT", "local").lower()

# ─── Fail-fast: reject weak/default secrets in production ───────────────────
_DEFAULT_SECRETS = {"webhook-signing-secret", "phantom-agent-secret-2026"}


def _validate_secrets() -> None:
    """Abort if any secret is missing or still using default value."""
    errors = []
    if not WEBHOOK_SECRET:
        errors.append("PHANTOM_WEBHOOK_SECRET is not set")
    elif WEBHOOK_SECRET in _DEFAULT_SECRETS:
        errors.append("PHANTOM_WEBHOOK_SECRET is still using default value")
    if not AGENT_SECRET:
        errors.append("PHANTOM_AGENT_SECRET is not set")
    elif AGENT_SECRET in _DEFAULT_SECRETS:
        errors.append("PHANTOM_AGENT_SECRET is still using default value")
    if not ADMIN_PASSWORD:
        errors.append("ADMIN_PASSWORD (or BOOTSTRAP_ADMIN_PASSWORD) is not set")
    if ENVIRONMENT == "production" and errors:
        print("\n❌ SECURITY: Cannot start in production with weak secrets:")
        for e in errors:
            print(f"   - {e}")
        print("\n   Generate new secrets with:")
        print("   openssl rand -hex 32")
        raise SystemExit(1)
    elif errors:
        # Non-production: warn but allow start
        for e in errors:
            print(f"⚠️  WARNING: {e}")


_validate_secrets()


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        # Read and parse the payload
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length)

        # Verify signature if present
        signature = self.headers.get("x-nyuwunsewu-signature", "")
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

        event = payload.get("event", "")
        scan_id = payload.get("scan_id", "")

        print(f"\n📡 Webhook received: {event}")
        print(f"   Scan ID: {scan_id}")
        print(f"   Target: {payload.get('target_url', 'N/A')}")
        print(f"   Status: {payload.get('status', 'N/A')}")
        print(f"   Findings: {payload.get('findings_count', 0)}")
        print(f"   Endpoints: {payload.get('endpoints_count', 0)}")

        if event == "scan.completed":
            print("\n🤖 Triggering Phantom agent exploration...")
            asyncio.run(explore_target(scan_id, payload.get("target_url", "")))
        elif event == "scan.failed":
            print("\n❌ Scan failed:")
            print(f"   Error: {payload.get('error', 'Unknown')}")

        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        pass  # Suppress default logging


async def login_to_backend() -> str | None:
    """Login to NyuwunSewu backend and return JWT access token."""
    login_url = f"{NYUWUNSEWU_URL}/auth/login"
    payload = json.dumps({"email": ADMIN_EMAIL, "password": ADMIN_PASSWORD}).encode()
    print(f"\n🔑 Logging in to {NYUWUNSEWU_URL}...")
    try:
        async with aiohttp.ClientSession() as http_session:
            async with http_session.post(
                login_url,
                headers={"Content-Type": "application/json"},
                data=payload,
            ) as resp:
                if resp.status == 200:
                    data = await resp.json()
                    token = data.get("access_token")
                    if token:
                        print(f"   ✅ Logged in as {ADMIN_EMAIL}")
                        return token
                else:
                    body = await resp.text()
                    print(f"   ❌ Login failed ({resp.status}): {body}")
                return None
    except Exception as e:
        print(f"   ❌ Login request failed: {e}")
        return None


async def explore_target(scan_id: str, target_url: str):
    """Simulate Phantom agent exploring the target after scan completion."""
    session_id = None
    bearer_token = None

    # Step 0: Login to get JWT token
    try:
        bearer_token = await login_to_backend()
        if not bearer_token:
            print("\n❌ Failed to login — cannot proceed with exploration")
            return
        print(f"   ✅ Authenticated as {ADMIN_EMAIL}")
    except Exception as e:
        print(f"\n❌ Login failed: {e}")
        return

    auth_headers = {
        "Content-Type": "application/json",
        "Authorization": f"Bearer {bearer_token}",
    }

    async with aiohttp.ClientSession() as session:
        try:
            # Step 1: Create agent session
            print("\n Creating agent session...")
            async with session.post(
                f"{NYUWUNSEWU_URL}/agent-sessions",
                headers=auth_headers,
                json={
                    "scan_id": scan_id,
                    "target_url": target_url,
                    "agent_name": "phantom",
                },
            ) as resp:
                if resp.status == 201:
                    data = await resp.json()
                    session_id = data.get("id")
                    print(f"   ✅ Session created: {session_id[:8]}")
                else:
                    body = await resp.text()
                    print(f"    Failed to create session: {resp.status} — {body}")
                    return

            # Step 2: Log exploration start
            await add_log(
                session,
                session_id,
                "info",
                "Starting exploration as nasabah",
                "login",
                bearer_token=bearer_token,
            )

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
                await add_log(
                    session,
                    session_id,
                    "info",
                    message,
                    action,
                    bearer_token=bearer_token,
                )
                await asyncio.sleep(2)  # Simulate work

            # Step 4: Request approval for a risky action
            await add_log(
                session,
                session_id,
                "warning",
                "Found potential IDOR vulnerability, requesting approval to exploit",
                "idor_exploit",
                bearer_token=bearer_token,
            )

            # Step 5: Simulate finding a vulnerability
            await add_log(
                session,
                session_id,
                "success",
                "IDOR confirmed: can access other users' accounts",
                "idor_confirmed",
                bearer_token=bearer_token,
            )

            # Step 6: Submit finding (uses X-Agent-Secret, no JWT needed)
            await submit_finding(session, session_id, scan_id, target_url)

            # Step 7: Complete session
            await complete_session(
                session, session_id, findings_count=1, bearer_token=bearer_token
            )

            print("\n✅ Phantom agent exploration complete!")

        except Exception as e:
            print(f"\n❌ Exploration failed: {e}")
            if session_id:
                await add_log(
                    session,
                    session_id,
                    "error",
                    f"Exploration failed: {str(e)}",
                    "error",
                    bearer_token=bearer_token,
                )


async def add_log(
    session: aiohttp.ClientSession,
    session_id: str,
    level: str,
    message: str,
    action: str = None,
    bearer_token: str = None,
):
    """Add a log entry to the agent session."""
    auth_headers = {"Content-Type": "application/json"}
    if bearer_token:
        auth_headers["Authorization"] = f"Bearer {bearer_token}"
    try:
        async with session.post(
            f"{NYUWUNSEWU_URL}/agent-sessions/{session_id}/log",
            headers=auth_headers,
            json={
                "session_id": session_id,
                "level": level,
                "message": message,
                "action": action,
            },
        ) as resp:
            if resp.status == 200:
                print(f"   📝 Log: {message}")
            else:
                body = await resp.text()
                print(f"   ❌ Failed to add log: {resp.status} — {body}")
    except Exception as e:
        print(f"   ❌ Log error: {e}")


async def submit_finding(
    session: aiohttp.ClientSession, session_id: str, scan_id: str, target_url: str
):
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
            "Tested with multiple account IDs, all returned valid data",
        ],
        "evidence": {
            "proof_of_concept": "Changed account_id from 123 to 124, received valid response",
            "affected_accounts": ["123", "124", "125"],
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
            "5. Repeated for multiple accounts to confirm",
        ],
    }

    try:
        async with session.post(
            f"{NYUWUNSEWU_URL}/findings/ingest",
            headers={
                "Content-Type": "application/json",
                "X-Agent-Secret": AGENT_SECRET,
            },
            json=finding_data,
        ) as resp:
            if resp.status == 201:
                data = await resp.json()
                print(f"   ✅ Finding submitted: {data.get('finding_id', 'unknown')}")
            else:
                print(f"   ❌ Failed to submit finding: {resp.status}")
    except Exception as e:
        print(f"   ❌ Finding submission error: {e}")


async def complete_session(
    session: aiohttp.ClientSession,
    session_id: str,
    findings_count: int = 0,
    bearer_token: str = None,
):
    """Mark the agent session as completed."""
    auth_headers = {}
    if bearer_token:
        auth_headers["Authorization"] = f"Bearer {bearer_token}"
    try:
        async with session.post(
            f"{NYUWUNSEWU_URL}/agent-sessions/{session_id}/complete",
            headers=auth_headers,
            params={"findings_count": findings_count},
        ) as resp:
            if resp.status == 200:
                print(f"   ✅ Session completed with {findings_count} findings")
            else:
                body = await resp.text()
                print(f"   ❌ Failed to complete session: {resp.status} — {body}")
    except Exception as e:
        print(f"    Session completion error: {e}")


def main():
    print("🚀 Phantom Agent Webhook Receiver")
    print("=" * 50)
    print(f"Port: {WEBHOOK_PORT}")
    print(f"Secret: {WEBHOOK_SECRET[:4]}***")
    print(f"NyuwunSewu URL: {NYUWUNSEWU_URL}")
    print("\nListening for webhooks...")
    print("Press Ctrl+C to stop\n")

    server = HTTPServer(("0.0.0.0", WEBHOOK_PORT), WebhookHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n👋 Shutting down webhook receiver...")
        server.shutdown()


if __name__ == "__main__":
    main()
