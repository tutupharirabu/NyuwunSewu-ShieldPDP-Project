#!/usr/bin/env python3
"""
Phantom Agent Webhook Receiver - Production Version
Receives scan completion notifications from NyuwunSewu ShieldPDP,
saves scan context, triggers real Hermes agent exploration via cron,
and notifies the user via Telegram.

Architecture:
  1. NyuwunSewu scan completes -> fires webhook -> this receiver (port 8080)
  2. Receiver saves scan context -> {HERMES_HOME}/profiles/{PROFILE}/pending_scans/{scan_id}.json
  3. Receiver creates a one-shot Hermes cron job to explore the target
  4. Hermes scheduler ticks the cron job -> agent explores target -> submits findings
  5. Receiver notifies user via `hermes send` (non-blocking, best-effort)

NOTE: This receiver listens on port 8080 and is SEPARATE from Hermes' own
native webhook platform (port 8644). They are two different ingestion paths.
This receiver does NOT require the native webhook platform to be enabled.
"""

import hashlib
import hmac
import json
import os
import subprocess
import threading
import time
import traceback
import urllib.error
import urllib.request
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, HTTPServer

# --- Configuration ---

WEBHOOK_PORT = int(os.getenv("PHANTOM_WEBHOOK_PORT", "8080"))
WEBHOOK_SECRET = os.getenv("PHANTOM_WEBHOOK_SECRET", "")
NYUWUNSEWU_URL = os.getenv("NYUWUNSEWU_URL", "http://127.0.0.1:8000").rstrip("/")
AGENT_SECRET = os.getenv("PHANTOM_AGENT_SECRET", "")
ADMIN_EMAIL = os.getenv("ADMIN_EMAIL", "admin@nyuwunsewu.local")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD") or os.getenv(
    "BOOTSTRAP_ADMIN_PASSWORD", ""
)
ENVIRONMENT = os.getenv("ENVIRONMENT", "local").lower()

PROFILE = os.getenv("HERMES_PROFILE", "phantom")


def _normalize_hermes_home(raw: str) -> str:
    """Always return the Hermes ROOT home (~/.hermes), never a profile dir.

    If HERMES_HOME is accidentally set to the profile directory
    (e.g. /root/.hermes/profiles/phantom), strip the profile suffix so the
    Hermes CLI does not double-nest paths (the /profiles/phantom/profiles/phantom/ bug).
    Profile selection is done explicitly via the `-p PROFILE` flag instead.
    """
    home = raw.rstrip("/")
    suffix = f"/profiles/{PROFILE}"
    if home.endswith(suffix):
        home = home[: -len(suffix)]
    return home or os.path.expanduser("~/.hermes")


# Hermes root home (normalized) + derived profile paths
HERMES_HOME = _normalize_hermes_home(
    os.getenv("HERMES_HOME", os.path.expanduser("~/.hermes"))
)
PROFILE_DIR = os.path.join(HERMES_HOME, "profiles", PROFILE)
PENDING_SCANS_DIR = os.path.join(PROFILE_DIR, "pending_scans")
CRON_DIR = os.path.join(PROFILE_DIR, "cron")

# Ensure pending scans directory exists
os.makedirs(PENDING_SCANS_DIR, exist_ok=True)

LOG_FILE = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "phantom_receiver.log"
)

# --- Logging ---


def log(msg: str):
    """Thread-safe logging to stdout and file."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{ts}] {msg}"
    print(line, flush=True)
    try:
        with open(LOG_FILE, "a") as f:
            f.write(line + "\n")
    except Exception:
        pass


# --- Fail-fast: reject weak/default secrets ---

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
        print("\n[ERR] SECURITY: Cannot start in production with weak secrets:")
        for e in errors:
            print(f"   - {e}")
        print("\n   Generate new secrets with:")
        print("   openssl rand -hex 32")
        raise SystemExit(1)
    elif errors:
        for e in errors:
            print(f"[WARN] {e}")


_validate_secrets()

# --- Default conservative Rules of Engagement (versioned) ---

DEFAULT_ROE_V1 = """DEFAULT conservative RoE (default_roe_v1) - no document supplied.
- IN SCOPE: the target host ONLY ({target_url}). No other hosts, subdomains, or
  third-party services.
- Non-destructive ONLY: no state-changing writes, no deletion, no DoS, no
  brute-force floods.
- No real-user-data exfiltration beyond the minimum needed to prove a finding.
- Respect the scan policy's forbidden/excluded paths and robots directives.
- Stop immediately and report (status=refused) if any action risks impacting
  real users or production data."""

# --- Persistent-goal scaffold (approach A; reused verbatim by approach B) ---


def _goal_objective(scan_id: str, target_url: str) -> str:
    """One-line standing objective.

    MUST stay single-line: in approach B this exact string is passed as the
    `/goal` argument, where a newline would break the command.
    """
    return (
        f"Validate and submit EVERY confirmed finding for scan {scan_id} on "
        f"{target_url}, then mark the session completed (or refused)."
    )


def _goal_block(scan_id: str, target_url: str) -> str:
    """STANDING GOAL + judge-evaluable DONE CRITERIA.

    The DONE CRITERIA text is reused verbatim by the native goal-judge in
    approach B, so keep it phrased as objective, checkable conditions.
    """
    return f"""== STANDING GOAL (your single objective for this whole run) ==
{_goal_objective(scan_id, target_url)}
DONE CRITERIA - you are finished ONLY when:
  - every prioritized validation category has been attempted, AND
  - every confirmed finding has been submitted via POST /findings/ingest, AND
  - the session has been marked completed (or refused).
Treat every turn as spent toward this goal; do not wander."""


def _durability_block() -> str:
    """Flush-before-spend rule + explicit context-compaction warning."""
    return """== DURABILITY (CRITICAL - your context is volatile) ==
Your Hermes context WILL be compacted near the turn limit. Anything living ONLY
in context - partial evidence, half-built exploit chains, your note of which
endpoints you already checked - is LOST on compaction. The ShieldPDP backend is
your ONLY persistent memory. Therefore: the MOMENT a finding is confirmed, submit
it via POST /findings/ingest BEFORE doing anything else. Never hold a confirmed
finding to "batch later." Capture request+response evidence into the submission
at the moment of confirmation."""


def _checkpoint_block(session_id: str, scan_id: str, target_url: str) -> str:
    """Resume-checklist instruction using the EXISTING ingest-log endpoint.

    Only meaningful when a session_id exists, so it lives inside the session
    block. The `details` object is the durable resume note that survives a
    context compaction and that an approach-B agent reads on resume.
    """
    return f"""== CHECKPOINT (durable resume trail) ==
At key milestones AND whenever you sense you are near the turn budget, push a
progress checkpoint so work survives a context compaction or a resume:
  curl -X POST {NYUWUNSEWU_URL}/agent-sessions/{session_id}/ingest-log \\
    -H "Content-Type: application/json" -H "X-Agent-Secret: {AGENT_SECRET}" \\
    -d '{{"level": "info", "message": "checkpoint", "action": "summarizing", "details": {{"categories_done": ["idor"], "endpoints_remaining": ["/api/x"], "in_progress": "authz on /admin"}}}}'
This `details` object is your durable resume note: categories completed, endpoints
remaining, and what is currently in progress."""


def _session_block(session_id: str, scan_id: str, target_url: str) -> str:
    """SESSION TRACKING instructions + appended CHECKPOINT resume trail."""
    return f"""== SESSION TRACKING (update backend as you work) ==
Your AgentSession ID: {session_id}
Update your session state via the backend API so the operator can track progress.
Use these endpoints (auth: X-Agent-Secret header = {AGENT_SECRET}):

ALWAYS send an `action_phase` (canonical enum) on every update so the operator's
dashboard shows a uniform, descriptive status. Valid action_phase values:
  initializing, recon, enumerating_accounts, testing_idor, testing_authz,
  testing_auth, testing_injection, testing_info_disclosure, submitting_finding,
  awaiting_approval, summarizing, completed, refused, failed.
Pick the one matching what you are doing RIGHT NOW (e.g. testing_idor while
replaying swapped IDs, enumerating_accounts while registering userA/userB).

- Update status to "exploring" when you start:
  curl -X POST {NYUWUNSEWU_URL}/agent-sessions/ingest \\
    -H "Content-Type: application/json" -H "X-Agent-Secret: {AGENT_SECRET}" \\
    -d '{{"scan_id": "{scan_id}", "target_url": "{target_url}", "agent_name": "phantom", "status": "exploring", "action_phase": "recon", "message": "Agent started, beginning validation", "level": "info"}}'

- Push log entries for key milestones (include `action_phase`, and a `details`
  object for any structured context — it is shown verbatim to the operator):
  curl -X POST {NYUWUNSEWU_URL}/agent-sessions/{session_id}/ingest-log \\
    -H "Content-Type: application/json" -H "X-Agent-Secret: {AGENT_SECRET}" \\
    -d '{{"level": "info", "message": "Completed IDOR check on /api/accounts", "action": "testing_idor", "details": {{"endpoint": "/api/accounts", "result": "no cross-account read"}}}}'
  Levels: info, warning, error, success.

- Increment findings_count when you submit a finding (call the ingest endpoint
  with status="exploring", action_phase="submitting_finding").

- When ALL done, mark session complete:
  curl -X POST {NYUWUNSEWU_URL}/agent-sessions/{session_id}/ingest-complete \\
    -H "X-Agent-Secret: {AGENT_SECRET}" \\
    -d 'findings_count=<number_of_findings_submitted>'

- REFUSAL: if at any point you decline to continue because an action would
  collide with your non-offensive policy / rules of engagement, do NOT silently
  stop. Report it explicitly so the session is marked "refused" (an ethical
  halt, distinct from a crash) with the reason visible to the operator:
  curl -X POST {NYUWUNSEWU_URL}/agent-sessions/ingest \\
    -H "Content-Type: application/json" -H "X-Agent-Secret: {AGENT_SECRET}" \\
    -d '{{"scan_id": "{scan_id}", "target_url": "{target_url}", "agent_name": "phantom", "status": "refused", "action_phase": "refused", "level": "warning", "message": "<one-line reason you are declining to proceed>"}}'

Do this at key milestones: start (status=exploring), each finding confirmed,
the very end (status=completed), and immediately on any policy refusal
(status=refused).

{_checkpoint_block(session_id, scan_id, target_url)}"""

# --- Bridge to Hermes ---


def _hermes_cli(*args: str, timeout: int = 120) -> subprocess.CompletedProcess:
    """Run a Hermes CLI command (always scoped to PROFILE) and return the result.

    The `-p PROFILE` flag is injected globally so every call is unambiguous,
    regardless of HERMES_HOME / HERMES_PROFILE env state.
    """
    cmd = ["hermes", "-p", PROFILE] + list(args)
    log(f"   [CMD] Running: {' '.join(cmd[:5])}... ({len(cmd)} args)")
    env = os.environ.copy()
    env["HERMES_HOME"] = HERMES_HOME  # normalized root, never a profile dir
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=env)


def _save_scan_context(scan_id: str, payload: dict) -> str:
    """Save scan context to pending_scans directory. Returns file path."""
    context = {
        "scan_id": scan_id,
        "target_url": payload.get("target_url", ""),
        "event": payload.get("event", "scan.completed"),
        "status": payload.get("status", ""),
        "findings_count": payload.get("findings_count", 0),
        "endpoints_count": payload.get("endpoints_count", 0),
        "engagement_mode": payload.get("engagement_mode", "internal"),
        "roe_basis": payload.get("roe_basis"),
        "roe_text": payload.get("roe_text"),
        "roe_extraction_warning": payload.get("roe_extraction_warning", False),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "raw_payload": payload,
    }
    filepath = os.path.join(PENDING_SCANS_DIR, f"{scan_id}.json")
    with open(filepath, "w") as f:
        json.dump(context, f, indent=2, default=str)
    log(f"   [FILE] Saved scan context: {filepath}")
    return filepath


def _create_agent_session(scan_id: str, target_url: str) -> str | None:
    """Create an AgentSession record via the backend API (agent-auth endpoint).

    Returns the session_id on success, None on failure.
    This bridges the receiver pipeline to the frontend AgentSessionsPage.
    """
    url = f"{NYUWUNSEWU_URL}/agent-sessions/ingest"
    body = json.dumps(
        {
            "scan_id": scan_id,
            "target_url": target_url,
            "agent_name": "phantom",
            "status": "idle",
            "message": f"Scan {scan_id} completed. Agent exploration pending.",
            "level": "info",
        }
    ).encode()

    req = urllib.request.Request(
        url,
        data=body,
        headers={
            "Content-Type": "application/json",
            "X-Agent-Secret": AGENT_SECRET,
        },
        method="POST",
    )

    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
            session_id = data.get("session_id")
            log(f"   [OK] AgentSession created: {session_id}")
            return session_id
    except urllib.error.HTTPError as e:
        err_body = e.read().decode()[:200]
        log(f"   [WARN] Failed to create AgentSession: HTTP {e.code} - {err_body}")
        return None
    except Exception as e:
        log(f"   [WARN] Failed to create AgentSession: {type(e).__name__}: {e}")
        return None


def _shared_blocks(scan_id: str, target_url: str, session_block: str) -> str:
    """SUBMISSION + HARD RULES shared by both engagement prompts."""
    return f"""{session_block}

== SUBMISSION (per confirmed finding) ==
curl POST {NYUWUNSEWU_URL}/findings/ingest
Headers: Content-Type: application/json, X-Agent-Secret: {AGENT_SECRET}
Body (JSON) - MUST use these exact types:
- scan_id: string ("{scan_id}")
- finding_type: string ("idor"|"xss"|"auth_bypass"|"authz"|"info_disclosure"|"other")
- title: string (short descriptive title)
- severity: string ("critical"|"high"|"medium"|"low"|"info")
- confidence: float (0.0-100.0)
- description: string
- reasoning: list of strings
- evidence: dict
- request_method: string
- request_url: string
- request_headers: dict or null
- request_body: string or null
- response_status: int
- response_headers: dict or null
- response_body: string
- remediation: string
- agent_name: string ("phantom")
- exploit_chain: list of strings

== HARD RULES ==
Report ONLY findings confirmed through real HTTP interaction with concrete
evidence. Never fabricate. Non-destructive only - no data deletion, no DoS, no
brute-force floods. Stay strictly within {target_url}. Submit findings as you go.
End with a concise summary of all findings submitted."""


def _build_internal_prompt(
    scan_id: str, target_url: str, context_path: str, session_block: str
) -> str:
    return f"""PHANTOM ENGAGEMENT - Authorized Web App Pentest (Learning Lab)

== AUTHORIZATION (Phase 0 ALREADY SATISFIED - do NOT halt to ask) ==
- Asset owner: the operator running this Hermes instance.
- Authorization: GRANTED, in writing, by the asset owner. This is an OWNED lab.
- Scope: {target_url} ONLY (scan {scan_id}). Private tailnet host, non-public.
- RoE: non-destructive, minimum footprint, no real data exfiltration beyond proof.
- Engagement type: grey-box assessment of a banking-style web application.
Proceed immediately. Authorization is on file here; do NOT ask for it again.

{_goal_block(scan_id, target_url)}

{_durability_block()}

== AVAILABLE TOOLS (use ONLY these - actually installed on this host) ==
PRIMARY ENGINE - use for auth / session / IDOR / authz / business-logic:
  curl, wget, and python3 with: requests, aiohttp, PyJWT, websockets, cryptography.
  For access-control bugs (IDOR/BOLA, authz), scripted requests with swapped
  tokens/IDs is your STRONGEST tool - prefer it over scanners.
SCANNERS / DISCOVERY:
  nuclei v3.4.8 (vuln/misconfig/info-disclosure/XSS templates), nikto 2.6.0
  (server misconfig), sqlmap 1.10.5 (confirm SQLi only - do NOT --dump real data),
  ffuf 2.1.0 + gobuster (dir/param discovery), httpx (probe/tech), wafw00f (WAF),
  nmap 7.80, mitmproxy/mitmdump (scripted proxy, only if needed).

NOT INSTALLED - do NOT call these (they will fail and waste your budget):
  burpsuite, amass, theHarvester, dalfox, arjun, wfuzz, jwt_tool, feroxbuster,
  metasploit, searchsploit, hydra, john, hashcat, masscan, naabu, dirsearch,
  xsstrike, tcpdump, tshark, shodan, whatweb (ruby missing).
  Substitutes: XSS -> nuclei XSS templates + manual reflection via curl;
  JWT -> PyJWT in python3; brute force -> SKIP (outside RoE).

== BUDGET DISCIPLINE (CRITICAL - prior runs died in recon before submitting) ==
You have a LIMITED turn budget. Do NOT spend it all on reconnaissance.
- Recon is PARTIALLY DONE: read {context_path} first - it contains the endpoint
  map from the scan. USE that list; do NOT re-crawl from scratch.
- Run a COMPRESSED recon only (~5 turns max), then START VALIDATING.
- SUBMIT each finding the MOMENT it is confirmed (incremental), never batch at end.

== PRIORITIZED VALIDATION (banking app -> access control is the crown jewel) ==
1. BOLA / IDOR (DO FIRST): register userA AND userB, replay object-ID requests
   swapping IDs. Cross-account read/write => finding.
2. AUTHZ / privilege escalation: can a normal customer reach admin-only endpoints?
3. AUTH / session: weak password policy, missing rate-limit, JWT flaws (PyJWT).
4. INJECTION: reflected XSS, SQLi (CONFIRM ONLY).
5. INFO DISCLOSURE / MISCONFIG: verbose errors, exposed debug/config, missing headers.
{_shared_blocks(scan_id, target_url, session_block)}"""


def _build_external_prompt(
    scan_id: str,
    target_url: str,
    context_path: str,
    session_block: str,
    roe_text: str | None,
    roe_basis: str,
    extraction_warning: bool,
) -> str:
    roe_block = roe_text if roe_text else DEFAULT_ROE_V1.format(target_url=target_url)
    warn_line = (
        "\n[WARNING] RoE extraction incomplete - the uploaded document could not be "
        "read in full. VERIFY SCOPE MANUALLY before acting and refuse if uncertain."
        if extraction_warning
        else ""
    )
    return f"""PHANTOM ENGAGEMENT - Authorized Test of a LIVE / PUBLIC-FACING System

== AUTHORIZATION (basis: {roe_basis}) ==
This is an AUTHORIZED engagement against a live, public-facing production system.
Your scope, permitted actions, and limits are DEFINED BY THE RULES OF ENGAGEMENT
below. Treat the RoE as binding. If an action is not clearly permitted by the
RoE, do NOT perform it - report a refusal (status=refused) instead.{warn_line}

-- RULES OF ENGAGEMENT (authoritative) --
{roe_block}
-- END RULES OF ENGAGEMENT --

== EXTRA HARD-STOPS (production system) ==
- NO state-changing writes (no create/update/delete on real records).
- NO real-user-data exfiltration beyond the minimum to prove a finding.
- Honor every in-scope / out-of-scope boundary in the RoE. Out-of-scope = do not touch.
- Stop and report (status=refused) at the first sign of real-user or production impact.

{_goal_block(scan_id, target_url)}

{_durability_block()}

== AVAILABLE TOOLS (use ONLY these - actually installed on this host) ==
PRIMARY: curl, wget, python3 (requests, aiohttp, PyJWT, websockets, cryptography).
  Scripted requests with swapped tokens/IDs are your STRONGEST tool for IDOR/authz.
SCANNERS: nuclei v3.4.8, nikto 2.6.0, sqlmap 1.10.5 (confirm only - never --dump
  real data), ffuf 2.1.0 + gobuster, httpx, wafw00f, nmap 7.80, mitmproxy
  (only if RoE permits).
NOT INSTALLED - do NOT call (they fail and waste budget): burpsuite, amass,
  theHarvester, dalfox, arjun, wfuzz, jwt_tool, feroxbuster, metasploit,
  searchsploit, hydra, john, hashcat, masscan, naabu, dirsearch, xsstrike,
  tcpdump, tshark, shodan, whatweb. Substitutes: XSS -> nuclei templates + manual
  curl reflection; JWT -> PyJWT; brute force -> SKIP (outside RoE).

== BUDGET DISCIPLINE ==
- Recon is PARTIALLY DONE: read {context_path} first (endpoint map). Do NOT re-crawl.
- Compressed recon (~5 turns), then validate. Submit each finding when confirmed.

== PRIORITIZED VALIDATION (within RoE scope) ==
1. BOLA / IDOR  2. AUTHZ / privilege escalation  3. AUTH / session / JWT
4. INJECTION (confirm only)  5. INFO DISCLOSURE / MISCONFIG
{_shared_blocks(scan_id, target_url, session_block)}"""


def _create_exploration_job(
    scan_id: str,
    target_url: str,
    context_path: str,
    session_id: str | None = None,
    engagement_mode: str = "internal",
    roe_text: str | None = None,
    roe_basis: str | None = None,
    extraction_warning: bool = False,
) -> str | None:
    """Create a one-shot Hermes cron job that runs the agent exploration.

    Relies on the Hermes scheduler ticking (root-cause lock bug is mitigated by
    the watchdog below + a clean gateway start). Returns a job ID string on
    success, None on failure.
    """
    session_block = ""
    if session_id:
        session_block = _session_block(session_id, scan_id, target_url)

    if engagement_mode == "external":
        prompt = _build_external_prompt(
            scan_id, target_url, context_path, session_block,
            roe_text, roe_basis or "default_roe_v1", extraction_warning,
        )
        job_suffix = "ext-roe" if roe_basis == "document" else "ext-default"
    else:
        prompt = _build_internal_prompt(
            scan_id, target_url, context_path, session_block
        )
        job_suffix = "int"

    result = _hermes_cli(
        "cron",
        "create",
        "1m",
        prompt,
        "--repeat",
        "1",
        "--name",
        f"explore-{job_suffix}-{scan_id[:8]}",
        "--deliver",
        "origin",
        timeout=60,
    )

    if result.returncode == 0:
        import re

        stdout = result.stdout.strip()
        job_match = re.search(r"([0-9a-f]{12})", stdout)
        job_id = (
            job_match.group(1)
            if job_match
            else (stdout[-12:] if len(stdout) >= 12 else "unknown")
        )
        log(f"   [OK] Exploration job created: {job_id}")
        log(f"   [INFO] Scheduler will tick this within ~1 minute")
        return job_id
    else:
        log(f"   [ERR] Failed to create exploration job:")
        log(f"      stderr: {result.stderr[:500]}")
        log(f"      stdout: {result.stdout[:500]}")
        return None


def _notify_user(scan_id: str, target_url: str, job_id: str | None):
    """Notify user via Hermes send that exploration is starting (best-effort)."""
    status_text = (
        f"Job: {job_id}"
        if job_id
        else "[WARN] Could not schedule exploration - manual intervention needed"
    )
    message = f"""[SCAN] Scan Completed - Starting Agent Exploration

Scan ID: {scan_id}
Target: {target_url}
Status: {status_text}

The Phantom agent will now explore the target and submit findings automatically."""

    def _do_notify():
        try:
            result = _hermes_cli(
                "send",
                "--to",
                "telegram",
                "-s",
                "[SCAN] Pentest Agent Report",
                message,
                timeout=10,
            )
            if result.returncode == 0:
                log(f"   [OK] Notification sent to user")
            else:
                log(f"   [WARN] Failed to send notification: {result.stderr[:200]}")
        except subprocess.TimeoutExpired:
            log(f"   [WARN] Notification timed out (non-fatal, pipeline continues)")
        except Exception as e:
            log(f"   [WARN] Notification error (non-fatal): {type(e).__name__}: {e}")

    t = threading.Thread(target=_do_notify, daemon=True)
    t.start()


# --- Webhook Handler ---


class WebhookHandler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            self._handle_webhook()
        except Exception as e:
            log(f"\n[CRASH] UNHANDLED ERROR in webhook handler:")
            log(f"   Type: {type(e).__name__}")
            log(f"   Detail: {e}")
            log(traceback.format_exc())
            try:
                self.send_response(500)
                self.end_headers()
                self.wfile.write(b"Internal server error")
            except Exception:
                pass

    def _handle_webhook(self):
        """Process an incoming webhook with full error context."""
        content_length = int(self.headers.get("Content-Length", 0))
        if content_length == 0:
            log("\n[WARN] Webhook received with empty body")
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Empty payload")
            return

        body = self.rfile.read(content_length)

        # Verify signature if present
        signature = self.headers.get("x-nyuwunsewu-signature", "")
        if signature:
            expected = f"sha256={hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()}"
            if not hmac.compare_digest(signature, expected):
                log(f"\n[BLOCKED] Webhook signature MISMATCH")
                log(f"   Remote: {self.client_address}")
                log(f"   Expected: {expected[:20]}...")
                log(f"   Got:      {signature[:20]}...")
                self.send_response(403)
                self.end_headers()
                self.wfile.write(b"Invalid signature")
                return
            log(f"   [OK] Signature verified")

        try:
            payload = json.loads(body)
        except json.JSONDecodeError as e:
            log(f"\n[ERR] Invalid JSON in webhook: {e}")
            log(f"   Body preview: {body[:200]}")
            self.send_response(400)
            self.end_headers()
            self.wfile.write(b"Invalid JSON")
            return

        event = payload.get("event", "")
        scan_id = payload.get("scan_id", "")

        log(f"\n[WEBHOOK] Webhook received: {event}")
        log(f"   Scan ID: {scan_id}")
        log(f"   Target: {payload.get('target_url', 'N/A')}")
        log(f"   Status: {payload.get('status', 'N/A')}")
        log(f"   Findings: {payload.get('findings_count', 0)}")
        log(f"   Endpoints: {payload.get('endpoints_count', 0)}")

        if event == "scan.completed":
            target_url = payload.get("target_url", "")
            if not target_url:
                log("   [WARN] No target_url in webhook payload - skipping")
            else:
                t = threading.Thread(
                    target=_trigger_exploration,
                    args=(scan_id, target_url, payload),
                    daemon=True,
                )
                t.start()
        elif event == "scan.failed":
            log(f"\n[ERR] Scan failed:")
            log(f"   Error: {payload.get('error', 'Unknown')}")
            t = threading.Thread(
                target=_notify_scan_failure,
                args=(scan_id, payload),
                daemon=True,
            )
            t.start()
        else:
            log(f"\n[WARN] Unknown event type: {event}")

        # Respond immediately to prevent BrokenPipeError
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"OK")

    def log_message(self, format, *args):
        pass  # Suppress default HTTP logging


def _trigger_exploration(scan_id: str, target_url: str, payload: dict):
    """Full pipeline: create session -> save context -> create job -> notify."""
    try:
        log(f"\n{'=' * 60}")
        log(f"[AGENT] TRIGGERING PHANTOM AGENT EXPLORATION")
        log(f"   Scan ID: {scan_id}")
        log(f"   Target:  {target_url}")
        log(f"{'=' * 60}")

        # Create AgentSession record (bridges to frontend)
        session_id = _create_agent_session(scan_id, target_url)

        context_path = _save_scan_context(scan_id, payload)
        job_id = _create_exploration_job(
            scan_id,
            target_url,
            context_path,
            session_id,
            engagement_mode=payload.get("engagement_mode", "internal"),
            roe_text=payload.get("roe_text"),
            roe_basis=payload.get("roe_basis"),
            extraction_warning=payload.get("roe_extraction_warning", False),
        )
        _notify_user(scan_id, target_url, job_id)

        log(f"\n[OK] Exploration pipeline complete!")
    except Exception as e:
        log(f"\n[ERR] Exploration pipeline failed: {type(e).__name__}: {e}")
        log(traceback.format_exc())


def _notify_scan_failure(scan_id: str, payload: dict):
    """Notify user about scan failure."""
    error_msg = payload.get("error", "Unknown error")
    message = f"""[ERR] Scan Failed

Scan ID: {scan_id}
Target: {payload.get("target_url", "N/A")}
Error: {error_msg}"""

    def _do_notify():
        try:
            _hermes_cli(
                "send",
                "--to",
                "telegram",
                "-s",
                "[ERR] Pentest Agent Report",
                message,
                timeout=10,
            )
        except Exception as e:
            log(
                f"   [WARN] Failure notification error (non-fatal): {type(e).__name__}: {e}"
            )

    t = threading.Thread(target=_do_notify, daemon=True)
    t.start()


# --- Cron Lock File Watchdog ---
# The Hermes cron scheduler has a known bug: if a tick crashes or takes too long,
# .tick.lock is left behind and ALL future ticks are blocked forever. It also can
# leave orphaned .jobs_*.tmp atomic-write temp files. This watchdog cleans both so
# the scheduler stays alive even if the receiver is the only thing supervising it.

_LOCK_FILE = os.path.join(CRON_DIR, ".tick.lock")


def _cron_lock_watchdog():
    """Remove stale .tick.lock and orphaned .jobs_*.tmp files periodically."""
    while True:
        now = datetime.now(timezone.utc).timestamp()
        # 1. Stale tick lock
        try:
            if os.path.exists(_LOCK_FILE):
                age = now - os.path.getmtime(_LOCK_FILE)
                if age > 45:  # older than 45s = stale
                    os.remove(_LOCK_FILE)
                    log(f"   [WATCHDOG] Removed stale .tick.lock (age={age:.0f}s)")
        except Exception:
            pass
        # 2. Orphaned atomic-write temp files
        try:
            for name in os.listdir(CRON_DIR):
                if name.startswith(".jobs_") and name.endswith(".tmp"):
                    fp = os.path.join(CRON_DIR, name)
                    age = now - os.path.getmtime(fp)
                    if age > 120:  # 2 min old = clearly orphaned
                        os.remove(fp)
                        log(
                            f"   [WATCHDOG] Removed orphan temp: {name} (age={age:.0f}s)"
                        )
        except Exception:
            pass
        time.sleep(30)


# _watchdog_thread = threading.Thread(target=_cron_lock_watchdog, daemon=True)
# _watchdog_thread.start()
# log("[WATCHDOG] Cron lock file watchdog started")

# --- Main ---


def main():
    print("[START] Phantom Agent Webhook Receiver (Production)")
    print("=" * 50)
    print(f"Port: {WEBHOOK_PORT}")
    print(f"Profile: {PROFILE}")
    print(f"Hermes home (root): {HERMES_HOME}")
    print(f"Secret: {WEBHOOK_SECRET[:4]}***")
    print(f"NyuwunSewu URL: {NYUWUNSEWU_URL}")
    print(f"Pending scans dir: {PENDING_SCANS_DIR}")
    print(f"Agent Secret: {AGENT_SECRET[:4]}***")
    print()
    print("Listening for webhooks...")
    print("Press Ctrl+C to stop")
    print()

    server = HTTPServer(("0.0.0.0", WEBHOOK_PORT), WebhookHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n\n[STOP] Shutting down webhook receiver...")
        server.shutdown()


if __name__ == "__main__":
    main()
