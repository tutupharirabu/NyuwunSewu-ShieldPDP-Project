# Phantom Agent Integration Guide

Complete guide for integrating the Hermes/Phantom AI agent with NyuwunSewu ShieldPDP.

This document covers the end-to-end integration: from scan completion webhook to agent exploration, finding submission, and combined reporting.

## Quick Start

### 1. Start NyuwunSewu + Phantom

```bash
cd shieldpdp
chmod +x run_integration.sh
./run_integration.sh
```

Or manually:

```bash
# Terminal 1: NyuwunSewu backend
DATABASE_URL=sqlite+aiosqlite:///./nyuwunsewu_prod.db \
ALLOW_PRIVATE_TARGETS=true \
USE_CELERY=false \
.venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Terminal 2: Phantom webhook receiver
source .env
python3 phantom_webhook_receiver.py
```

### 2. Register Webhook in NyuwunSewu

```bash
# Login to get auth token
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@nyuwunsewu.local","password":"ChangeMe123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Register webhook for scan completion
curl -s -X POST http://127.0.0.1:8000/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Phantom Agent",
    "url": "http://127.0.0.1:8080",
    "events": ["scan.completed", "scan.failed"]
  }'
```

### 3. Start a Scan

```bash
curl -s -X POST http://127.0.0.1:8000/scan/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://vps-5092b876.tail25f2a6.ts.net",
    "project_name": "Vuln Bank Assessment",
    "allowed_domains": ["vps-5092b876.tail25f2a6.ts.net"],
    "exploit_chains": {"enabled": true},
    "policy": {"max_depth": 2, "max_pages": 100}
  }'
```

### 4. Watch the Magic Happen

When scan completes:
1. NyuwunSewu POSTs webhook to `http://127.0.0.1:8080`
2. Phantom receiver creates an AgentSession via `/agent-sessions/ingest`
3. Receiver saves scan context (endpoint map, target URL) to `pending_scans/`
4. Receiver creates a one-shot Hermes cron job for exploration
5. Hermes scheduler ticks the cron job — agent begins exploring
6. Agent submits findings via `/findings/ingest` as it confirms each one
7. Agent updates session status/action phases via `/agent-sessions/ingest`
8. Operator monitors progress in the Agent Sessions dashboard
9. Telegram notifications for key milestones and approval requests
10. All agent findings are included in NyuwunSewu reports

## Architecture

```
┌──────────────────┐  scan.completed   ┌──────────────────────┐
│   NyuwunSewu     │ ──── webhook ────►│ Phantom Webhook      │
│   Backend        │                   │ Receiver (port 8080) │
└────────┬─────────┘                   └────────┬─────────────┘
         │                                      │
         │                              ┌───────▼────────────┐
         │                              │ 1. Create session   │
         │                              │ 2. Save scan context│
         │                              │ 3. Create cron job  │
         │                              │ 4. Notify via TG    │
         │                              └───────┬────────────┘
         │                                      │
         │                              ┌───────▼────────────┐
         │                              │ Hermes Scheduler    │
         │                              │ (ticks cron job)    │
         │                              └───────┬────────────┘
         │                                      │
         │  POST /findings/ingest               │ Agent explores
         │  POST /agent-sessions/ingest         │ target as user
         │  POST /agent-sessions/{id}/ingest-log│ (recon, IDOR,
         │◄─────────────────────────────────────┘  authz, XSS...)
         │
         │  GET /agent-sessions (real-time logs)
         │
    ┌────▼────┐
    │Dashboard│  ← Operator monitors agent progress
    │   UI    │  ← Telegram approve/deny actions
    └─────────┘
```

## Detailed Workflow

### Step 1: Scan Completes → Webhook Fires

When a NyuwunSewu scan completes (or fails), the WebhookService dispatches a POST request to all registered webhook subscriptions with matching events.

**Webhook payload:**
```json
{
  "event": "scan.completed",
  "scan_id": "abc-123",
  "target_url": "https://target.example.com",
  "project_id": "proj-123",
  "status": "completed",
  "findings_count": 5,
  "endpoints_count": 150,
  "stats": {"endpoints": 150, "findings": 5, "risk_score": 8.5},
  "engagement_mode": "external",
  "roe_basis": "document",
  "roe_text": "...extracted Rules-of-Engagement text...",
  "roe_extraction_warning": false,
  "finished_at": "2025-01-01T12:00:00Z"
}
```

The `engagement_mode`, `roe_basis`, `roe_text`, and `roe_extraction_warning` fields drive
which exploration prompt the receiver builds (see [Engagement Modes & RoE](#engagement-modes--roe)).
For `internal` engagements, `roe_basis` and `roe_text` are `null`.

**Headers:**
```
content-type: application/json
user-agent: NyuwunSewu-Webhook/1.0
x-nyuwunsewu-event: scan.completed
x-nyuwunsewu-signature: sha256=<hmac-signature>  (if secret configured)
```

### Step 2: Phantom Receiver Processes Webhook

The `phantom_webhook_receiver.py` (port 8080) receives the webhook and:

1. **Verifies HMAC signature** (if `PHANTOM_WEBHOOK_SECRET` is set)
2. **Creates AgentSession** via `POST /agent-sessions/ingest` (auth: `X-Agent-Secret`)
3. **Saves scan context** to `{HERMES_HOME}/profiles/phantom/pending_scans/{scan_id}.json`
4. **Creates Hermes cron job** — a one-shot exploration task with prioritized validation instructions
5. **Notifies operator** via Telegram (`hermes send --to telegram`)

### Step 3: Agent Exploration (via Hermes Cron)

The Hermes scheduler ticks the cron job, which runs the agent exploration. The agent:

1. **Reads scan context** — uses the endpoint map from the scan (no need to re-crawl)
2. **Registers test accounts** — creates userA and userB for cross-account testing
3. **Validates BOLA/IDOR** — swaps object IDs between accounts
4. **Tests authz/privilege escalation** — tries admin endpoints as normal user
5. **Tests auth/session** — JWT analysis, weak secrets, missing rate limits
6. **Tests injection** — XSS (reflection via curl), SQLi (confirm only via sqlmap)
7. **Tests info disclosure** — nuclei, nikto for misconfig, verbose errors, exposed endpoints
8. **Submits findings incrementally** — `POST /findings/ingest` per confirmed finding

### Step 4: Agent Session Updates

Throughout exploration, the agent updates its session status:

```
POST /agent-sessions/ingest  →  status: "exploring", action_phase: "recon"
POST /agent-sessions/ingest  →  status: "exploring", action_phase: "testing_idor"
POST /agent-sessions/ingest  →  status: "exploring", action_phase: "submitting_finding"
POST /agent-sessions/ingest  →  status: "completed"
```

Each update is visible in real-time on the Agent Sessions dashboard page.

### Step 5: Combined Reporting

Agent findings are stored alongside auto-scanned findings. When generating reports, NyuwunSewu includes both sources. Agent findings are tagged with `source: "agent"` in the evidence summary.

## Engagement Modes & RoE

Every scan carries an **engagement mode** that controls how the Phantom agent is authorized to explore the target:

| Mode | Alias | Meaning | RoE |
|------|-------|---------|-----|
| `internal` | SAFE | Owned / pre-prod target, authorization already on file | None — receiver builds the internal prompt |
| `external` | NSFW | Authorized testing of a live / public-facing system | Scope derived from an uploaded RoE document, or a versioned conservative default |

`engagement_mode` defaults to `internal` on `POST /scan/start`. For an external engagement, upload a Rules-of-Engagement document first and pass the returned `roe_document_id` on scan-start:

```bash
# Upload RoE (external engagements only, org-scoped)
curl -s -X POST http://127.0.0.1:8000/scan/roe \
  -H "Authorization: Bearer $TOKEN" \
  -F "engagement_mode=external" \
  -F "file=@rules_of_engagement.pdf"
# → { "roe_document_id": "...", "filename": "...", "char_count": 1234, "extraction_warning": false }

# Start an external scan bound to that RoE
curl -s -X POST http://127.0.0.1:8000/scan/start \
  -H "Authorization: Bearer $TOKEN" -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://target.example.com",
    "project_name": "External Assessment",
    "allowed_domains": ["target.example.com"],
    "engagement_mode": "external",
    "roe_document_id": "<roe_document_id>"
  }'
```

Behaviour notes:

- RoE upload is **external-only** and **org-scoped** — a RoE document belongs to the uploader's organization and cannot be referenced cross-org (guarded; see `test_roe_cross_org_idor.py`).
- Text is extracted from the uploaded file on upload. Image-only PDFs (no extractable text) set `extraction_warning: true`, which is surfaced to the agent so it can flag the missing machine-readable scope.
- On scan completion, the webhook payload carries `engagement_mode`, `roe_basis`, `roe_text`, and `roe_extraction_warning`. `roe_basis` is `"document"` when a RoE was uploaded or `"default_roe_v1"` when the conservative versioned default applies.
- The webhook receiver builds an **internal prompt** (`_build_internal_prompt`) or an **external prompt** (`_build_external_prompt`, which embeds the RoE text or `DEFAULT_ROE_V1`) based on `engagement_mode`.

## API Reference

### Agent Sessions API (User Auth — JWT Bearer Token)

| Method | Path | Description | Permission |
|--------|------|-------------|------------|
| `GET` | `/agent-sessions` | List agent sessions | READ_DASHBOARD |
| `GET` | `/agent-sessions/{id}` | Get session detail | READ_DASHBOARD |
| `POST` | `/agent-sessions` | Create session | SCAN_CREATE |
| `POST` | `/agent-sessions/{id}/log` | Add log entry | READ_DASHBOARD |
| `POST` | `/agent-sessions/{id}/request-approval` | Request approval | READ_DASHBOARD |
| `POST` | `/agent-sessions/{id}/approve` | Approve/deny action | SCAN_CREATE |
| `POST` | `/agent-sessions/{id}/complete` | Mark completed | SCAN_CREATE |

### Agent Sessions API (Agent Auth — X-Agent-Secret)

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/agent-sessions/ingest` | Create or update session |
| `POST` | `/agent-sessions/{id}/ingest-log` | Push log entry |
| `POST` | `/agent-sessions/{id}/ingest-complete` | Mark session complete |

### Findings Ingestion API

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `POST` | `/findings/ingest` | Submit finding from agent | `X-Agent-Secret` header |

### Webhook Management API

| Method | Path | Description | Auth |
|--------|------|-------------|------|
| `GET` | `/webhooks` | List webhook subscriptions | Bearer Token |
| `POST` | `/webhooks` | Create webhook subscription | Bearer Token |
| `GET` | `/webhooks/{id}` | Get webhook detail | Bearer Token |
| `PATCH` | `/webhooks/{id}` | Update webhook | Bearer Token |
| `DELETE` | `/webhooks/{id}` | Delete webhook | Bearer Token |

### Telegram Integration

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/telegram/webhook` | Handle Telegram commands (approve/deny/status) |

## Agent Action Phases

The Phantom agent reports canonical action phases for real-time tracking. These are defined in `app/models/enums.py` and mirrored in the frontend dashboard.

| Phase | Description | Icon |
|-------|-------------|------|
| `initializing` | Setting up session | Loader |
| `recon` | Reconnaissance and endpoint mapping | Search |
| `enumerating_accounts` | Registering / enumerating test accounts | UserPlus |
| `testing_idor` | Testing IDOR / BOLA | ShieldAlert |
| `testing_authz` | Testing authorization / privilege escalation | ShieldAlert |
| `testing_auth` | Testing authentication / session / JWT | KeyRound |
| `testing_injection` | Testing injection (XSS / SQLi) | Bug |
| `testing_info_disclosure` | Testing info disclosure / misconfig | FileSearch |
| `submitting_finding` | Submitting a confirmed finding | Send |
| `awaiting_approval` | Waiting for operator approval | Clock |
| `summarizing` | Summarizing results | FileText |
| `completed` | Exploration complete | CheckCircle |
| `refused` | Halted by non-offensive policy (ethical halt) | Ban |
| `failed` | Exploration failed | XCircle |

### Session Status Values

| Status | Description |
|--------|-------------|
| `idle` | Session created, agent not yet started |
| `exploring` | Agent actively exploring target |
| `pending_approval` | Agent waiting for operator approval |
| `approved` | Action approved |
| `denied` | Action denied |
| `completed` | Exploration finished |
| `failed` | Exploration failed |
| `refused` | Agent declined to continue (ethical halt — distinct from failure) |

## Finding Ingestion

### Request

```bash
curl -X POST http://127.0.0.1:8000/findings/ingest \
  -H "Content-Type: application/json" \
  -H "X-Agent-Secret: $AGENT_SECRET" \
  -d '{
    "scan_id": "scan-uuid",
    "finding_type": "idor_account_takeover",
    "title": "IDOR Allows Access to Other Users Data",
    "severity": "critical",
    "confidence": 95.0,
    "description": "By manipulating the account_id parameter...",
    "reasoning": [
      "Registered as userA (account_id: 123)",
      "Accessed own account at /api/accounts/123",
      "Changed ID to 124 in request",
      "Successfully accessed another users account data"
    ],
    "evidence": {
      "proof_of_concept": "Changed account_id from 123 to 124",
      "affected_accounts": ["123", "124", "125"]
    },
    "request_method": "GET",
    "request_url": "https://target/api/accounts/124",
    "request_headers": {"Authorization": "Bearer [REDACTED]"},
    "response_status": 200,
    "response_body": "{\"account_id\": 124, \"owner\": \"Another User\", \"balance\": 5000000}",
    "remediation": "Implement ownership verification on account endpoints",
    "agent_name": "phantom",
    "exploit_chain": [
      "Registered as normal user (account_id: 123)",
      "Accessed own account at /api/accounts/123",
      "Changed ID to 124 in request",
      "Successfully accessed another users account data",
      "Repeated for multiple accounts to confirm"
    ]
  }'
```

### Response

```json
{
  "finding_id": "uuid-here",
  "status": "open",
  "message": "Finding ingested: IDOR Allows Access to Other Users Data"
}
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENT_SECRET` / `PHANTOM_AGENT_SECRET` | Shared secret for agent auth | None |
| `PHANTOM_WEBHOOK_SECRET` | HMAC secret for webhook signature verification | None |
| `PHANTOM_WEBHOOK_PORT` | Port for webhook receiver | `8080` |
| `NYUWUNSEWU_URL` | NyuwunSewu API URL | `http://127.0.0.1:8000` |
| `ADMIN_EMAIL` | Admin email for API login | `admin@nyuwunsewu.local` |
| `ADMIN_PASSWORD` / `BOOTSTRAP_ADMIN_PASSWORD` | Admin password for API login | `ChangeMe123!` |
| `HERMES_HOME` | Hermes root home directory | `~/.hermes` |
| `HERMES_PROFILE` | Hermes profile name | `phantom` |
| `ENVIRONMENT` | Environment (local/production) | `local` |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token for notifications | None |
| `TELEGRAM_CHAT_ID` | Telegram chat ID for notifications | None |
| `WEB_CONCURRENCY` | Uvicorn worker count for the API container | `2` |

### Secrets Validation

The webhook receiver validates secrets on startup:

- In `production` environment: refuses to start with missing or default secrets
- In `local` environment: warns but continues

Generate strong secrets with:
```bash
openssl rand -hex 32
```

## Security

- **Agent authentication** via `X-Agent-Secret` header with HMAC timing-safe comparison
- **Webhook signature verification** via `x-nyuwunsewu-signature` (HMAC-SHA256)
- **Sensitive headers** (`Authorization`, `Cookie`, `X-API-Key`) redacted before storage
- **Agent findings** tagged with `source: "agent"` for audit trail
- **Agent session** scoped to scan's organization (no cross-tenant IDOR)
- **Fail-fast secrets** — receiver rejects weak/default secrets in production
- **Agent secret** does not carry tenant identity; organization is resolved strictly from `scan_id`

## Phantom Webhook Receiver

### How It Works

The `phantom_webhook_receiver.py` is a standalone HTTP server (port 8080) that:

1. **Receives webhooks** from NyuwunSewu when scans complete/fail
2. **Verifies HMAC signatures** if `PHANTOM_WEBHOOK_SECRET` is configured
3. **Creates AgentSession** via the backend API (`POST /agent-sessions/ingest`)
4. **Saves scan context** (endpoint map, metadata) to the Hermes profile directory
5. **Creates a one-shot Hermes cron job** with prioritized validation instructions
6. **Notifies the operator** via Telegram (`hermes send --to telegram`)

### Hermes Cron Job

The receiver creates a detailed prompt for the Hermes agent that includes:

- **Authorization** — pre-confirmed, agent proceeds immediately
- **Available tools** — only actually installed tools (curl, python3, nuclei, nikto, sqlmap, ffuf, nmap, etc.)
- **Budget discipline** — compressed recon, use existing endpoint map, submit findings incrementally
- **Prioritized validation** — BOLA/IDOR first (banking app), then authz, auth, injection, info disclosure
- **Session tracking** — instructions to update AgentSession via API
- **Submission format** — exact JSON schema for `/findings/ingest`
- **Hard rules** — non-destructive, confirmed evidence only, stay within scope

### Cron Lock Watchdog

The Hermes cron scheduler has a known bug: if a tick crashes, `.tick.lock` is left behind and blocks all future ticks. The receiver includes a watchdog thread that:

- Removes stale `.tick.lock` files (older than 45 seconds)
- Removes orphaned `.jobs_*.tmp` atomic-write temp files (older than 2 minutes)

## Telegram Integration

### Commands

| Command | Description |
|---------|-------------|
| `approve <session_prefix> [notes...]` | Approve a pending agent action |
| `deny <session_prefix> [notes...]` | Deny a pending agent action |
| `status` | List all active agent sessions |

### Setup

1. Create a Telegram bot via @BotFather
2. Get the bot token
3. Get the chat ID (send a message to the bot, then check `https://api.telegram.org/bot<TOKEN>/getUpdates`)
4. Set `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` in `.env`
5. Configure Telegram webhook: `POST https://api.telegram.org/bot<TOKEN>/setWebhook?url=https://your-domain/telegram/webhook`

## Troubleshooting

### Server won't start
```bash
# Check if port is in use
lsof -i :8000
lsof -i :8080

# Check logs
DATABASE_URL=sqlite+aiosqlite:///./nyuwunsewu.db ALLOW_PRIVATE_TARGETS=true \
  .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Webhook not received
1. Verify webhook is registered: `GET /webhooks`
2. Check webhook URL is reachable from NyuwunSewu
3. Verify events match: `["scan.completed"]`
4. Check webhook delivery status in subscription
5. Check Phantom receiver logs: `phantom_receiver.log`

### Finding ingestion fails
1. Verify `AGENT_SECRET` matches in both `.env` and request header
2. Check `scan_id` exists (if provided)
3. Verify JSON payload structure matches the schema
4. Check server logs for errors

### Agent session not appearing in dashboard
1. Verify `scan_id` in the ingest request maps to an existing scan
2. The session is scoped to the scan's organization — check you're logged into the right org
3. Check `/agent-sessions` API directly to see if the session exists

### Telegram not sending notifications
1. Check `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` in `.env`
2. Verify bot token is valid
3. Check chat ID is correct and bot is added to the group/chat
4. Check receiver logs for Telegram API errors
