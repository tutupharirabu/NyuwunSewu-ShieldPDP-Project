# NyuwunSewu + Phantom Agent

Compliance-driven security validation and privacy risk management platform with integrated AI-powered agent exploration.

NyuwunSewu is intentionally not a general vulnerability scanner. It implements proprietary lightweight validation engines in Python and avoids sqlmap, nuclei, ffuf, katana, Burp automation, ZAP, Nikto, nmap wrappers, and external pentest engines — those tools are delegated to the Phantom agent for interactive exploration.

## Overview

NyuwunSewu is a two-component security assessment platform:

1. **NyuwunSewu Backend** — Automated API security scanning engine with compliance mapping, PII detection, RBAC, audit logging, and remediation tracking.
2. **Phantom Agent** — External AI agent (Hermes-based) that receives scan results via webhook, performs interactive vulnerability exploration (login, navigate, chain exploits), and submits findings back to NyuwunSewu.

Together they provide end-to-end security assessment: automated recon + validation (NyuwunSewu) followed by interactive business-logic testing (Phantom).

## MVP Scope

Implemented production-oriented modules:

### Security Validation Engine

- Async recon engine with bounded full-response reading, recursive crawling, operator-seeded entry paths, guest-then-authenticated session crawling, HTML form and browser-style JSON-token login support, standards discovery (`robots.txt`, sitemap, and OpenAPI locations), HTML/static resource extraction, JavaScript and JSON API route parsing, retries, deduplication, scope filtering, and connection pooling.
- Passive technology inventory for server signatures, programming-language hints, application frameworks, and JSON API field names without storing field values.
- Recon profiles for environment-specific crawling configuration.
- Endpoint classification engine using heuristic scoring.
- PII detection for email, JWT, API keys, access tokens, UUID, NIK, NPWP, bank account numbers, phone numbers, and customer identifiers.
- Lightweight SQLi validation with bounded error, boolean, optional timing probes, and JavaScript JSON-login authentication-bypass confirmation.
- Bounded path traversal validation for observed file/path-like inputs, requiring repeated operating-system file signatures before reporting.
- Bounded reflected HTML injection validation with an inert markup canary, identifying XSS risk without executing JavaScript.
- BOLA / IDOR validation with object ID mutation and authorization-context comparison, including access matrix enforcement.
- Auth validation for JWT structure and missing authorization checks.
- CORS origin validation with controlled invalid-origin probes.
- Safe API exposure validation for guest-visible structured financial/identity responses, client-side authentication-token storage patterns, and publicly advertised GraphQL introspection.
- Bounded modern-auth validation for token cookie protection attributes, credential-free CORS origin reflection, limited invalid-password username enumeration comparison, and an invalid-signature JWT privilege negative control for operator-supplied non-admin sessions.
- Data rights validation aligned with UU PDP obligations.
- Discovery validation service for systematic endpoint and capability discovery.
- Optional lab exploit-chain mode for authorized vulnerable apps. When `exploit_chains.enabled=true`, the scan can extract the authenticated JWT from Cookie or Authorization context, try claim manipulation execution against admin routes, enumerate configured username candidates with invalid passwords only, chain browser-accessible token storage with no-exfiltration XSS proof payloads, and probe known vuln-bank modern lab endpoints.
- False positive reduction with baseline comparison, response diffing, timing consistency, soft 404 filtering, retry-aware confidence, and anomaly scoring.

### Compliance & Reporting

- UU PDP (Undang-undang Nomor 27 Tahun 2022) compliance mapping per finding.
- OWASP ASVS compliance mapping.
- Breach notification workflow per Pasal 46 UU PDP (3x24h SLA).
- Remediation matrix with priority ranking, effort estimates, and timeline recommendations.
- HTML and PDF report generation with evidence hashing and per-finding HTTP request/response evidence.
- RBAC (Super Admin, Security Manager, Pentester, Auditor, Read Only).
- Immutable audit logs.

### Phantom Agent Integration

- Webhook-based push notification from NyuwunSewu to Phantom when scan completes/fails.
- Agent finding ingestion via `POST /findings/ingest` with `X-Agent-Secret` authentication.
- Agent session lifecycle management (create, update, log, approve, complete, refuse).
- Canonical action phases for real-time status tracking in the frontend dashboard.
- Engagement modes — `internal` (SAFE: owned/pre-prod target, authorization on file) and `external` (NSFW: authorized testing of a live system, scope derived from an attached Rules-of-Engagement document or a versioned conservative default). The agent receives an internal- or external-specific exploration prompt accordingly.
- Rules-of-Engagement (RoE) document upload via `POST /scan/roe` for external engagements, with text extraction and an image-only-PDF extraction warning. RoE text and basis propagate to the agent in the scan-completed webhook.
- Telegram integration for human-in-the-loop agent session approval.
- Cron lock watchdog for Hermes scheduler reliability.

## Architecture

```text
┌─────────────────────────────────────────────────────────────────────┐
│                        NyuwunSewu Platform                          │
├──────────────────────────────┬──────────────────────────────────────┤
│   Backend (FastAPI)          │   Frontend (React + Vite)            │
│   ┌────────────────────────┐ │   ┌────────────────────────────────┐ │
│   │ API Layer              │ │   │ Dashboard                      │ │
│   │  /auth, /scans,        │ │   │  Projects, Targets, Scans,     │ │
│   │  /findings, /reports,  │ │   │  Findings, Compliance,         │ │
│   │  /compliance,          │ │   │  Reports, Remediation,         │ │
│   │  /remediation,         │ │   │  Agent Sessions, Settings      │ │
│   │  /agent-sessions,      │ │   │                                │ │
│   │  /webhooks,            │ │   │ Tech: React 18, TypeScript,    │ │
│   │  /telegram             │ │   │ TailwindCSS, shadcn/ui,        │ │
│   └──────────┬─────────────┘ │   │ Recharts, lucide-react         │ │
│              │               │   └────────────────────────────────┘ │
│   ┌──────────▼─────────────┐ │                                      │
│   │ Service Layer          │ │                                      │
│   │  ScanService           │ │                                      │
│   │  AgentService          │ │                                      │
│   │  WebhookService        │ │                                      │
│   │  BreachNotification    │ │                                      │
│   │  PolicyEngine          │ │                                      │
│   │  RiskEngine            │ │                                      │
│   │  AuditService          │ │                                      │
│   │  ScopeGuard            │ │                                      │
│   └──────────┬─────────────┘ │                                      │
│              │               │                                      │
│   ┌──────────▼─────────────┐ │                                      │
│   │ Validation Engines     │ │                                      │
│   │  SQLi, BOLA/IDOR,      │ │                                      │
│   │  Path Traversal, XSS,  │ │                                      │
│   │  CORS, Auth, API       │ │                                      │
│   │  Exposure, Data Rights │ │                                      │
│   │  Exploit Chains,       │ │                                      │
│   │  False Positive Reducer│ │                                      │
│   └──────────┬─────────────┘ │                                      │
│              │               │                                      │
│   ┌──────────▼─────────────┐ │                                      │
│   │ Recon & Crawling       │ │                                      │
│   │  Async Crawler         │ │                                      │
│   │  Tech Inventory        │ │                                      │
│   │  PII Detection         │ │                                      │
│   │  Endpoint Classifier   │ │                                      │
│   │  Compliance Mapper     │ │                                      │
│   └────────────────────────┘ │                                      │
├──────────────────────────────┴──────────────────────────────────────┤
│   Infrastructure                                                     │
│   ┌──────────┐  ┌──────────┐  ┌──────────────┐  ┌───────────────┐  │
│   │PostgreSQL│  │  Redis   │  │Celery Worker │  │ Phantom Agent │  │
│   │ (async)  │  │ (queue)  │  │ (background) │  │ (Hermes CLI)  │  │
│   └──────────┘  └──────────┘  └──────────────┘  └───────────────┘  │
└─────────────────────────────────────────────────────────────────────┘
```

### Project Structure

```text
app/
  api/             FastAPI routes and dependencies
  core/            settings, security, RBAC, bootstrap
  recon/           async recon engine
  crawler/         async crawler and extraction engine
  classifier/      endpoint heuristic classifier
  validation/      SQLi, BOLA/IDOR, auth, CORS, path traversal, reflected HTML,
                   exploit chains, username enumeration, false-positive reduction,
                   access matrix, API exposure, data rights
  pii_detection/   privacy exposure detector
  compliance/      UU PDP and OWASP ASVS mapper
  reporting/       HTML and minimal PDF report generation
  evidence/        immutable evidence hashing and curl reproduction
  remediation/     remediation workflow service
  dashboard/       dashboard aggregation service
  database/        async SQLAlchemy session
  middleware/      request context and security headers
  services/        orchestration, policy, audit, risk, scope guard,
                   agent service, webhook service, discovery validation,
                   breach notification
  repositories/    tenant-scoped repository helpers
  models/          SQLAlchemy models (entities)
  schemas/         Pydantic API schemas
  utils/           rate limiter, redaction utilities
  templates/       Jinja2 HTML templates (dashboard, report)
frontend/          React + Vite dashboard (TypeScript, TailwindCSS)
worker/            Celery worker entrypoint and tasks
migrations/        Alembic migrations
tests/             unit and integration tests
```

## Safety Controls

- Scope boundaries are enforced before every crawl or validation request.
- Private, loopback, link-local, reserved, multicast, and unspecified IP ranges are blocked unless `ALLOW_PRIVATE_TARGETS=true`.
- Scan policies clamp request rate, depth, page count, forbidden paths, excluded paths, and validation families.
- Optional login credentials first preserve the guest inventory and then establish an in-scope authenticated session for the current in-process scan. Browser-style JSON-token logins are supported when detected in the login page; credentials and acquired tokens are not written to scan evidence or persisted in scan records.
- Anonymous authorization comparisons run without the authenticated session cookie, so public access findings are backed by the actual guest response.
- Stop requests propagate into active reconnaissance workers before validation begins.
- SQLi checks are bounded and non-destructive. Login-bypass validation records an authenticated-state transition but does not proceed to protected actions, data dumping, or exploit chaining.
- API exposure and GraphQL checks analyze already crawled read-only responses and do not execute mutations or extract schemas.
- Default JWT claim validation never requests token-forging endpoints or signs administrator tokens. Opt-in lab exploit-chain mode can additionally try unsigned, weak-secret-signed, and lab `/api/jwt/forge` strategies, then re-request configured admin routes to prove execution.
- Default username enumeration compares one operator-supplied username with one generated control using invalid passwords only. Opt-in lab exploit-chain mode can test configured username candidates, still with invalid passwords only and without password reset workflows.
- CORS validation uses a controlled invalid origin without an authenticated cookie or bearer token.
- The engine deliberately does not automate password/PIN brute force, money/card/payment changes, malicious uploads, off-site token exfiltration, AI data-dump prompts, webhook triggers, package publishing, or pipeline modification. The opt-in modern vuln-bank probe pack includes bounded read/proof probes such as loopback-only SSRF checks and debug endpoint reachability.
- Path traversal checks run only against discovered file/path-like parameters and use bounded read-only confirmation probes.
- Reflected HTML checks use a non-executing element marker and require repeatable parsed reflection before a finding is recorded.
- BOLA checks require bounded identifier mutation and optional secondary auth context.
- Exploit-chain mode is opt-in and remains scope-bound. It does not generate off-site cookie exfiltration payloads, does not use external SSRF callbacks, and stores redacted evidence.
- Findings are discarded when signals are unstable, soft 404-like, or below confidence thresholds.
- Stored headers and evidence are redacted before persistence.
- Agent authentication uses HMAC timing-safe comparison to prevent timing attacks.
- Webhook payloads are optionally signed with HMAC-SHA256 via `x-nyuwunsewu-signature` header.

## Run With Docker

```bash
cd shieldpdp
cp .env.example .env
# Edit .env — set SECRET_KEY, PHANTOM_AGENT_SECRET, PHANTOM_WEBHOOK_SECRET
docker compose up --build
```

Services started:

| Service | URL | Description |
|---------|-----|-------------|
| NyuwunSewu API | `http://localhost:8000` | Backend + Swagger docs at `/docs` |
| PostgreSQL | `localhost:5432` | Database |
| Redis | `localhost:6379` | Queue |
| Celery Worker | — | Background scan execution |

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `SECRET_KEY` | JWT signing secret | `change-me-in-production` |
| `AGENT_SECRET` / `PHANTOM_AGENT_SECRET` | Shared secret for agent finding ingestion | None |
| `PHANTOM_WEBHOOK_SECRET` | HMAC secret for webhook signature verification | None |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://...` |
| `ALLOW_PRIVATE_TARGETS` | Allow scanning private/local IPs | `false` |
| `USE_CELERY` | Use Celery for background tasks | `false` |
| `WEB_CONCURRENCY` | Uvicorn worker count for the API container | `2` |
| `TELEGRAM_BOT_TOKEN` | Telegram bot token for agent notifications | None |
| `TELEGRAM_CHAT_ID` | Telegram chat ID for agent notifications | None |
| `ADMIN_PASSWORD` / `BOOTSTRAP_ADMIN_PASSWORD` | Bootstrap admin password | `ChangeMe123!` |

## Run The Frontend Dashboard

Start the FastAPI backend first, then run the React dashboard:

```bash
cd shieldpdp/frontend
npm install
npm run dev
```

Open:

```text
http://localhost:5173
```

The frontend is a Vite React app using TailwindCSS, shadcn-style local components, Recharts, lucide-react, protected routes, and JWT authentication. During local development `frontend/.env` proxies API calls to the backend via `VITE_PROXY_TARGET` (default `http://127.0.0.1:8000`). The scan-start page exposes the engagement-mode selector (internal/external) and RoE upload, and dashboard/agent-session views poll with a non-overlapping, tab-visibility-aware guard.

### Frontend Pages

| Page | Description |
|------|-------------|
| **Dashboard** | Overview with scan stats, finding severity distribution, compliance summary, recent activity |
| **Projects** | Project list with target/scan/finding counts |
| **Targets** | Target inventory with scan/finding counts |
| **Scans** | Scan list with status, stats, and drill-down to scan detail |
| **Scan Detail** | Endpoint inventory, technology tags, forms, parameters, guest/authenticated route counts |
| **Findings** | Finding list with severity filtering, evidence preview, and detail view |
| **Compliance** | UU PDP / OWASP ASVS mapping, breach notification management, remediation matrix |
| **Reports** | Report generation (HTML/PDF), download, and management |
| **Remediation** | Remediation tracking workflow (Open → Assigned → In Progress → Re-Test → Closed) |
| **Agent Sessions** | Phantom agent session monitoring with real-time logs, action phases, and Telegram approval |
| **Settings** | User management and configuration |

### Default Bootstrap Credentials

```text
email: admin@nyuwunsewu.local
password: ChangeMe123!
organization_slug: default-organization
```

Change these before using the platform outside local development.

## Run Locally

Start PostgreSQL and Redis, then:

```bash
cd shieldpdp
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
cp .env.example .env
alembic upgrade head
uvicorn app.main:app --reload
```

For quick local SQLite testing without PostgreSQL:

```bash
export DATABASE_URL=sqlite+aiosqlite:///./nyuwunsewu_local.db
export ALLOW_PRIVATE_TARGETS=true
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

Keep `ALLOW_PRIVATE_TARGETS=false` for production-like deployments. Enable it only for authorized local lab targets such as `localhost`, `127.0.0.1`, or private RFC1918 test ranges.

Deep scans remain policy bounded. The shipped ceiling permits `MAX_CRAWL_DEPTH=5` and `MAX_CRAWL_PAGES=5000`; choose lower per-scan values for ordinary assessments, and increase them only for an authorized long-running mapping exercise.

## Core API

### Authentication

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/auth/login` | Login and get JWT token |
| `POST` | `/auth/logout` | Logout (invalidate token) |
| `GET` | `/auth/me` | Get current user profile |
| `GET` | `/auth/users` | List users |
| `POST` | `/auth/users` | Create user |

### Scans

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/scan/start` | Start a new scan (accepts `engagement_mode`, `roe_document_id`) |
| `POST` | `/scan/roe` | Upload a Rules-of-Engagement document (external engagements only, org-scoped) |
| `POST` | `/scan/stop` | Request scan stop |
| `GET` | `/scan/status?scan_id=...` | Get scan status |
| `GET` | `/scans` | List all scans |
| `GET` | `/scans/{scan_id}` | Get scan detail |
| `GET` | `/scans/{scan_id}/endpoints` | Get scan endpoint inventory |

### Findings

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/findings` | List findings (filterable by project/scan/target/status) |
| `GET` | `/findings/{finding_id}/evidence` | Get finding evidence |
| `POST` | `/findings/ingest` | Submit finding from external agent (X-Agent-Secret auth) |

### Reports

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/reports` | List reports |
| `GET` | `/reports/{report_id}` | Get report detail |
| `GET` | `/reports/{report_id}/download` | Download report (HTML/PDF) |
| `POST` | `/reports/generate` | Generate a new report |
| `DELETE` | `/reports/{report_id}` | Delete a report |

### Compliance & Breach Notification

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/compliance` | Get compliance mappings (UU PDP, OWASP ASVS) |
| `GET` | `/compliance/remediation-matrix` | Get prioritized remediation action plan |
| `POST` | `/compliance/breach-assess` | Assess if findings constitute a notifiable breach |
| `POST` | `/compliance/breach-create` | Create breach notification record (starts 3x24h SLA) |
| `POST` | `/compliance/breach-notify` | Send breach notification via channels (Telegram) |
| `POST` | `/compliance/breach-dismiss` | Dismiss breach as non-notifiable |
| `GET` | `/compliance/breach/{breach_id}` | Get breach notification detail |
| `GET` | `/compliance/breaches` | List all breach notifications |

### Enterprise

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/projects` | List projects with target/scan/finding counts |
| `GET` | `/targets` | List targets with scan/finding counts |
| `GET` | `/remediations` | List remediation tracking items |
| `GET` | `/audit-logs` | List audit logs (Admin only) |

### Dashboard

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/dashboard` | Dashboard overview (JSON) |
| `GET` | `/ui/dashboard` | Dashboard overview (HTML) |

### Agent Sessions

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/agent-sessions` | List agent sessions |
| `GET` | `/agent-sessions/{session_id}` | Get agent session detail |
| `POST` | `/agent-sessions` | Create agent session (user auth) |
| `POST` | `/agent-sessions/{session_id}/log` | Add log entry to session |
| `POST` | `/agent-sessions/{session_id}/request-approval` | Request approval for risky action |
| `POST` | `/agent-sessions/{session_id}/approve` | Approve/deny pending action |
| `POST` | `/agent-sessions/{session_id}/complete` | Mark session as completed |
| `POST` | `/agent-sessions/ingest` | Create/update session from agent (X-Agent-Secret auth) |
| `POST` | `/agent-sessions/{session_id}/ingest-log` | Push log entry from agent |
| `POST` | `/agent-sessions/{session_id}/ingest-complete` | Mark session complete from agent |

### Webhooks

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/webhooks` | List webhook subscriptions |
| `POST` | `/webhooks` | Create webhook subscription |
| `GET` | `/webhooks/{id}` | Get webhook detail |
| `PATCH` | `/webhooks/{id}` | Update webhook |
| `DELETE` | `/webhooks/{id}` | Delete webhook |

### Telegram

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/telegram/webhook` | Telegram inbound webhook (approve/deny/status commands) |

### Other

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/retest` | Trigger retest for a finding |
| `GET` | `/health` | Health check |
| `GET` | `/` | Root info |

Example scan start:

```bash
curl -X POST http://localhost:8000/scan/start \
  -H "authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "project_name": "Example Assessment",
    "allowed_domains": ["example.com"],
    "engagement_mode": "internal",
    "initial_paths": ["/login", "/app/dashboard"],
    "credential_auth": {
      "login_path": "/login",
      "username": "authorized-assessment-user",
      "password": "provided-at-scan-time"
    },
    "exploit_chains": {
      "enabled": true,
      "username_candidates": ["admin", "administrator", "test", "user"],
      "weak_jwt_secrets": ["secret", "jwtsecret", "admin123"],
      "admin_paths": ["/admin", "/admin/dashboard", "/dashboard"],
      "modern_vuln_bank_probes": true
    },
    "policy": {
      "max_requests_per_second": 5,
      "allow_sqli_validation": true,
      "allow_auth_validation": true,
      "allow_timing_validation": false,
      "excluded_paths": ["/payment/live"],
      "forbidden_paths": ["/admin/delete"],
      "max_depth": 2,
      "max_pages": 250
    }
  }'
```

## RBAC

Roles:

| Role | Permissions |
|------|-------------|
| **Super Admin** | All permissions |
| **Security Manager** | scan:create, scan:stop, finding:review, evidence:access, report:export, remediation:approve, remediation:update, dashboard:read, findings:read, compliance:read, compliance:manage |
| **Pentester** | scan:create, scan:stop, evidence:access, remediation:update, dashboard:read, findings:read, compliance:read, compliance:manage |
| **Auditor** | evidence:access, report:export, dashboard:read, findings:read, compliance:read |
| **Read Only** | dashboard:read, findings:read, compliance:read |

RBAC is backed by `Organization`, `Role`, and `User` models with tenant-scoped repository helpers.

## Remediation Workflow

Findings follow:

```text
Open -> Assigned -> In Progress -> Re-Test -> Closed
```

False-positive marking is tracked explicitly and audit logged.

## Compliance Mapping

The MVP maps findings to UU PDP and OWASP ASVS impact statements. UU PDP metadata is based on the official BPK regulation entry for Undang-undang Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi: https://peraturan.bpk.go.id/Details/229798

The mapping engine is audit-supporting software, not legal advice.

## Phantom Agent Integration

NyuwunSewu integrates with the Hermes/Phantom AI agent for interactive vulnerability exploration beyond automated scanning. Phantom explores the target as a real user (login, navigate, test business logic), finds and chains vulnerabilities, and submits findings back to NyuwunSewu.

### Architecture

```text
┌──────────────────┐  scan.completed   ┌──────────────────┐
│   NyuwunSewu     │ ──── webhook ────►│ Phantom Receiver  │
│   (Scanner)      │                   │ (port 8080)       │
└────────┬─────────┘                   └────────┬──────────┘
         │                                      │
         │                                  ┌───▼───────────┐
         │                                  │ Hermes CLI    │
         │                                  │ (cron job)    │
         │                                  └───┬───────────┘
         │                                      │
         │  POST /findings/ingest               │ Agent explores
         │  POST /agent-sessions/ingest         │ target as user
         │◄─────────────────────────────────────┘
         │
         │  GET /agent-sessions (real-time logs)
         │
    ┌────▼────┐
    │Dashboard│  ← Operator monitors agent progress
    │   UI    │  ← Telegram approve/deny actions
    └─────────┘
```

### Workflow

1. **Scan completes** → NyuwunSewu fires webhook to Phantom receiver (port 8080).
2. **Receiver creates agent session** → `POST /agent-sessions/ingest` with `X-Agent-Secret`.
3. **Receiver saves scan context** → Endpoint map, target URL, scan metadata to `pending_scans/`.
4. **Receiver creates Hermes cron job** → One-shot exploration task with prioritized validation instructions.
5. **Hermes scheduler ticks** → Agent begins exploration (recon, IDOR, authz, injection, info disclosure).
6. **Agent submits findings** → `POST /findings/ingest` with `X-Agent-Secret` per confirmed finding.
7. **Agent updates session** → Status, action phases, log entries via `/agent-sessions/ingest`.
8. **Operator monitors** → Real-time session view in frontend dashboard.
9. **Human-in-the-loop** → Telegram commands for approve/deny risky actions.
10. **Session completes** → All findings included in NyuwunSewu reports.

### Setup

1. **Configure secrets** in `.env`:

   ```bash
   AGENT_SECRET=your-shared-secret-here
   PHANTOM_WEBHOOK_SECRET=your-webhook-signing-secret
   PHANTOM_AGENT_SECRET=your-shared-secret-here
   ADMIN_PASSWORD=your-admin-password
   ```

2. **Register a webhook** (enables push notification to agent):

   ```bash
   curl -X POST http://localhost:8000/webhooks \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "Phantom Agent",
       "url": "http://127.0.0.1:8080",
       "events": ["scan.completed", "scan.failed"]
     }'
   ```

3. **Start Phantom webhook receiver**:

   ```bash
   python3 phantom_webhook_receiver.py
   ```

4. **Start a scan** — when it completes, Phantom will automatically begin exploration.

### Agent Action Phases

The Phantom agent reports canonical action phases for real-time tracking in the dashboard:

| Phase | Description |
|-------|-------------|
| `initializing` | Setting up session |
| `recon` | Reconnaissance and endpoint mapping |
| `enumerating_accounts` | Registering / enumerating test accounts |
| `testing_idor` | Testing IDOR / BOLA |
| `testing_authz` | Testing authorization / privilege escalation |
| `testing_auth` | Testing authentication / session / JWT |
| `testing_injection` | Testing injection (XSS / SQLi) |
| `testing_info_disclosure` | Testing info disclosure / misconfig |
| `submitting_finding` | Submitting a confirmed finding |
| `awaiting_approval` | Waiting for operator approval |
| `summarizing` | Summarizing results |
| `completed` | Exploration complete |
| `refused` | Halted by non-offensive policy (ethical halt) |
| `failed` | Exploration failed |

### Agent Finding Ingestion

Agents submit findings via `POST /findings/ingest` with `X-Agent-Secret` header:

```bash
curl -X POST http://localhost:8000/findings/ingest \
  -H "Content-Type: application/json" \
  -H "X-Agent-Secret: your-shared-secret-here" \
  -d '{
    "scan_id": "optional-scan-id",
    "finding_type": "idor_account_takeover",
    "title": "IDOR Allows Access to Other Users Data",
    "severity": "critical",
    "confidence": 95.0,
    "description": "...",
    "reasoning": ["Step 1...", "Step 2..."],
    "request_method": "GET",
    "request_url": "https://target/api/accounts/124",
    "response_status": 200,
    "response_body": "...",
    "remediation": "Implement ownership verification",
    "agent_name": "phantom",
    "exploit_chain": ["Step 1", "Step 2", "Step 3"]
  }'
```

### Telegram Integration

NyuwunSewu supports Telegram commands for human-in-the-loop agent session approval:

- `approve <session_prefix> [notes...]` — approve a pending agent action
- `deny <session_prefix> [notes...]` — deny a pending agent action
- `status` — list active agent sessions

Configure `TELEGRAM_BOT_TOKEN` and `TELEGRAM_CHAT_ID` in `.env` to enable.

### Webhook Payload

When a scan completes or fails, NyuwunSewu POSTs to registered webhooks:

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

For `internal` engagements, `engagement_mode` is `"internal"` and `roe_basis`/`roe_text`
are `null`. For `external` engagements, `roe_basis` is `"document"` when a RoE was uploaded
or `"default_roe_v1"` when the conservative versioned default applies.

Webhook payloads are optionally signed with HMAC-SHA256 via the
`x-nyuwunsewu-signature` header when a `secret` is configured on the subscription.

### Security

- Agent authentication via `X-Agent-Secret` header with HMAC timing-safe comparison.
- Webhook signature verification via `x-nyuwunsewu-signature` (HMAC-SHA256).
- Sensitive headers redacted before storage.
- Agent findings tagged with `source: "agent"`.
- Agent session scoped to scan's organization (no cross-tenant IDOR).

## Tests

```bash
cd shieldpdp
pytest
```

The test suite covers:

| Test File | Coverage |
|---|---|
| `test_classifier.py` | Endpoint classification heuristics |
| `test_pii_detection.py` | PII pattern detection |
| `test_policy_engine.py` | Policy enforcement and scope guarding |
| `test_false_positive.py` | False-positive reduction logic |
| `test_validation_helpers.py` | Validation utility functions |
| `test_api_smoke.py` | API bootstrap and login smoke tests |
| `test_api_exposure_validation.py` | API exposure and GraphQL checks |
| `test_modern_validation.py` | Modern auth validation (CORS, JWT, username enumeration) |
| `test_breach_notification.py` | Breach notification workflow |
| `test_discovery_validation.py` | Discovery validation service |
| `test_phase1_integration.py` | Phase 1 end-to-end integration |
| `test_recon_profiles.py` | Recon profile configuration |
| `test_agent_session_ingest.py` | Agent session ingestion |
| `test_findings_ingest.py` | External agent finding ingestion |
| `test_reporting.py` | Report generation |
| `test_webhook_dispatch_failure.py` | Webhook dispatch and failure handling |
| `test_webhook_dispatch_engagement.py` | Webhook engagement-mode / RoE propagation |
| `test_dashboard_overview.py` | Dashboard aggregation |
| `test_data_rights_engine.py` | Data rights validation engine |
| `test_models_registry.py` | Model registry validation |
| `test_find_session_by_prefix.py` | Telegram session lookup |
| `test_scan_engagement_mode.py` | Engagement-mode handling on scan-start |
| `test_roe_upload.py` | RoE document upload endpoint |
| `test_roe_extract.py` | RoE text extraction and image-only warning |
| `test_roe_cross_org_idor.py` | Cross-org RoE access (IDOR) guard |
| `test_phantom_prompt_builders.py` | Internal/external Phantom prompt builders |

## Tech Stack

| Component | Technology |
|-----------|------------|
| **Backend** | Python 3.11, FastAPI, SQLAlchemy 2.0 (async), Pydantic 2 |
| **Frontend** | React 18, TypeScript, Vite, TailwindCSS, shadcn/ui, Recharts |
| **Database** | PostgreSQL 16 (production), SQLite (dev/testing) |
| **Queue** | Redis 7 + Celery 5 |
| **ORM** | SQLAlchemy 2.0 + Alembic migrations |
| **Container** | Docker + Docker Compose |
| **Agent** | Hermes CLI (cron-based exploration) |

## License

Proprietary — internal use only.
