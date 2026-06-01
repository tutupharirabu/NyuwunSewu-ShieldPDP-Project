# NyuwunSewu

Compliance-driven security validation and privacy risk management MVP for enterprise API assessment.

NyuwunSewu is intentionally not a general vulnerability scanner. It implements proprietary lightweight validation engines in Python and avoids sqlmap, nuclei, ffuf, katana, Burp automation, ZAP, Nikto, nmap wrappers, and external pentest engines.

## MVP Scope

Implemented production-oriented modules:

- Async recon engine with bounded full-response reading, recursive crawling, operator-seeded entry paths, guest-then-authenticated session crawling, HTML form and browser-style JSON-token login support, standards discovery (`robots.txt`, sitemap, and OpenAPI locations), HTML/static resource extraction, JavaScript and JSON API route parsing, retries, deduplication, scope filtering, and connection pooling.
- Passive technology inventory for server signatures, programming-language hints, application frameworks, and JSON API field names without storing field values.
- Endpoint classification engine using heuristic scoring.
- PII detection for email, JWT, API keys, access tokens, UUID, NIK, NPWP, bank account numbers, phone numbers, and customer identifiers.
- Lightweight SQLi validation with bounded error, boolean, optional timing probes, and JavaScript JSON-login authentication-bypass confirmation.
- Bounded path traversal validation for observed file/path-like inputs, requiring repeated operating-system file signatures before reporting.
- Bounded reflected HTML injection validation with an inert markup canary, identifying XSS risk without executing JavaScript.
- BOLA / IDOR validation with object ID mutation and authorization-context comparison.
- Auth validation for JWT structure and missing authorization checks.
- Safe API exposure validation for guest-visible structured financial/identity responses, client-side authentication-token storage patterns, and publicly advertised GraphQL introspection.
- Bounded modern-auth validation for token cookie protection attributes, credential-free CORS origin reflection, limited invalid-password username enumeration comparison, and an invalid-signature JWT privilege negative control for operator-supplied non-admin sessions.
- Optional lab exploit-chain mode for authorized vulnerable apps. When `exploit_chains.enabled=true`, the scan can extract the authenticated JWT from Cookie or Authorization context, try claim manipulation execution against admin routes, enumerate configured username candidates with invalid passwords only, chain browser-accessible token storage with no-exfiltration XSS proof payloads, and probe known vuln-bank modern lab endpoints.
- False positive reduction with baseline comparison, response diffing, timing consistency, soft 404 filtering, retry-aware confidence, and anomaly scoring.
- Risk prioritization, UU PDP and OWASP ASVS compliance mapping, evidence hashing, per-finding HTTP request/response evidence, HTML/PDF reporting, RBAC, immutable audit logs, and remediation tracking.

## Architecture

The codebase follows the requested modular structure:

```text
app/
  api/             FastAPI routes and dependencies
  core/            settings, security, RBAC, bootstrap
  recon/           async crawler and extraction engine
  classifier/      endpoint heuristic classifier
  validation/      SQLi, BOLA/IDOR, auth, false-positive reduction
  pii_detection/   privacy exposure detector
  compliance/      UU PDP and OWASP ASVS mapper
  reporting/       HTML and minimal PDF report generation
  evidence/        immutable evidence hashing and curl reproduction
  remediation/     remediation workflow service
  dashboard/       dashboard aggregation service
  database/        async SQLAlchemy session
  middleware/      request context and security headers
  services/        orchestration, policy, audit, risk, scope guard
  repositories/    tenant-scoped repository helpers
  models/          SQLAlchemy models
  schemas/         Pydantic API schemas
worker/            Celery worker entrypoint
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

## Run With Docker

```bash
cd shieldpdp
cp .env.example .env
docker compose up --build
```

The API will be available at:

- `http://localhost:8000`
- `http://localhost:8000/docs`

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

The frontend is a Vite React app using TailwindCSS, shadcn-style local components, Recharts, lucide-react, protected routes, and JWT authentication. During local development `frontend/.env` proxies API calls to `http://127.0.0.1:8001`.

Use **Dashboard > Recent Scans > Open** to inspect discovered endpoints, technology tags, forms, parameters, authenticated-discovery status, and guest/authenticated route counts. On **New Scan**, enter known initial paths such as `/login`, `/graphql`, or `/api/cors-test`; optionally provide an authorized account to let the crawler map guest routes first and then preserve the authenticated session while it maps deeper in-scope routes. Use **Findings > View** to review the literal safe-validation input and sanitized raw HTTP request/response retained for an accepted finding.

Default bootstrap credentials:

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
set DATABASE_URL=sqlite+aiosqlite:///./nyuwunsewu_local.db
set ALLOW_PRIVATE_TARGETS=true
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

Keep `ALLOW_PRIVATE_TARGETS=false` for production-like deployments. Enable it only for authorized local lab targets such as `localhost`, `127.0.0.1`, or private RFC1918 test ranges.

Deep scans remain policy bounded. The shipped ceiling permits `MAX_CRAWL_DEPTH=5` and `MAX_CRAWL_PAGES=5000`; choose lower per-scan values for ordinary assessments, and increase them only for an authorized long-running mapping exercise.

On Windows PowerShell:

```powershell
cd shieldpdp
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt
Copy-Item .env.example .env
alembic upgrade head
uvicorn app.main:app --reload
```

PowerShell local SQLite mode:

```powershell
$env:DATABASE_URL="sqlite+aiosqlite:///./nyuwunsewu_local.db"
$env:ALLOW_PRIVATE_TARGETS="true"
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001
```

## Core API

- `POST /auth/login`
- `POST /auth/logout`
- `GET /auth/me`
- `GET /auth/users`
- `POST /auth/users`
- `POST /scan/start`
- `POST /scan/stop`
- `GET /scan/status?scan_id=...`
- `GET /findings`
- `GET /findings/{finding_id}/evidence`
- `GET /reports`
- `GET /reports/{report_id}`
- `GET /reports/{report_id}/download`
- `POST /reports/generate`
- `POST /retest`
- `GET /compliance`
- `GET /dashboard`
- `GET /ui/dashboard`
- `GET /projects`
- `GET /targets`
- `GET /scans`
- `GET /scans/{scan_id}`
- `GET /scans/{scan_id}/endpoints`
- `GET /remediations`
- `GET /audit-logs`

Example scan start:

```bash
curl -X POST http://localhost:8000/scan/start \
  -H "authorization: Bearer $TOKEN" \
  -H "content-type: application/json" \
  -d '{
    "target_url": "https://example.com",
    "project_name": "Example Assessment",
    "allowed_domains": ["example.com"],
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

- Super Admin
- Security Manager
- Pentester
- Auditor
- Read Only

Permissions cover scan creation, scan stopping, finding review, evidence access, report export, remediation approval/update, dashboard reads, findings reads, and compliance reads.

## Remediation Workflow

Findings follow:

```text
Open -> Assigned -> In Progress -> Re-Test -> Closed
```

False-positive marking is tracked explicitly and audit logged.

## Compliance Mapping

The MVP maps findings to UU PDP and OWASP ASVS impact statements. UU PDP metadata is based on the official BPK regulation entry for Undang-undang Nomor 27 Tahun 2022 tentang Pelindungan Data Pribadi: https://peraturan.bpk.go.id/Details/229798

The mapping engine is audit-supporting software, not legal advice.

## Tests

```bash
cd shieldpdp
pytest
```

The test suite covers classifier heuristics, PII detection, policy enforcement, false-positive reduction, validation helpers, and API bootstrap/login smoke behavior.

## External Agent Integration (Phantom)

NyuwunSewu supports integration with external AI agents (e.g. Hermes/Phantom)
that perform interactive vulnerability exploration beyond automated scanning.

### Workflow

```
[NyuwunSewu scan completes] → Webhook → [Phantom agent notified]
   ↓
[Phantom explores target as "nasabah" — login, navigate, test business logic]
   ↓
[Phantom finds & chains vulnerabilities]
   ↓
[Phantom POST /findings/ingest → NyuwunSewu stores findings]
   ↓
[NyuwunSewu includes agent findings in reports]
```

### Setup

1. **Configure agent secret** in `.env`:
   ```bash
   AGENT_SECRET=your-shared-secret-here
   ```

2. **Register a webhook** (optional — enables push notification to agent):
   ```bash
   curl -X POST http://localhost:8000/webhooks \
     -H "Authorization: Bearer <token>" \
     -H "Content-Type: application/json" \
     -d '{
       "name": "Phantom Agent",
       "url": "https://your-agent-endpoint/webhook",
       "events": ["scan.completed", "scan.failed"]
     }'
   ```

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

### New API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/webhooks` | List webhook subscriptions |
| `POST` | `/webhooks` | Create webhook subscription |
| `GET` | `/webhooks/{id}` | Get webhook details |
| `PATCH` | `/webhooks/{id}` | Update webhook |
| `DELETE` | `/webhooks/{id}` | Delete webhook |
| `POST` | `/findings/ingest` | Submit finding from external agent |

### Webhook Payload

When a scan completes or fails, NyuwunSewu POSTs to registered webhooks:

```json
{
  "event": "scan.completed",
  "scan_id": "abc-123",
  "target_url": "https://target.example.com",
  "status": "completed",
  "findings_count": 5,
  "endpoints_count": 150,
  "stats": {"endpoints": 150, "findings": 5, "risk_score": 8.5},
  "finished_at": "2025-01-01T12:00:00Z"
}
```

Webhook payloads are optionally signed with HMAC-SHA256 via the
`x-nyuwunsewu-signature` header when a `secret` is configured on the subscription.
