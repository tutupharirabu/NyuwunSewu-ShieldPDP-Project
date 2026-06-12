# Peta Arsitektur ShieldPDP + Integrasi Agent Hermes/Phantom

Dokumen ini memetakan secara lengkap struktur proyek NyuwunSewu ShieldPDP dan bagaimana integrasi dengan agent Hermes/Phantom bekerja.

---

## Daftar Isi

1. [Gambaran Umum](#gambaran-umum)
2. [Struktur Proyek](#struktur-proyek)
3. [Arsitektur Integrasi Hermes](#arsitektur-integrasi-hermes)
4. [Alur Kerja Lengkap](#alur-kerja-lengkap)
5. [Komponen API untuk Agent](#komponen-api-untuk-agent)
6. [Model Data](#model-data)
7. [Keamanan](#keamanan)
8. [Deployment](#deployment)
9. [Troubleshooting](#troubleshooting)

---

## Gambaran Umum

**NyuwunSewu ShieldPDP** adalah platform validasi keamanan berbasis compliance untuk assessment API enterprise. Platform ini mengintegrasikan:

1. **Scanner otomatis** — Async crawler dan validation engine untuk SQLi, BOLA/IDOR, XSS, path traversal, CORS, auth bypass, API exposure, data rights
2. **Agent Hermes/Phantom** — AI agent yang melakukan eksplorasi interaktif dan chaining vulnerability via Hermes CLI cron
3. **Dashboard frontend** — React UI untuk monitoring, reporting, dan agent session tracking
4. **Integrasi Telegram** — Notifikasi dan approval workflow untuk aksi berisiko agent

### Hubungan ShieldPDP ↔ Hermes Agent

```
┌─────────────────────────────────────────────────────────────┐
│                    NyuwunSewu ShieldPDP                     │
│                                                             │
│  ┌─────────────┐    ┌──────────────┐    ┌───────────────┐  │
│  │   Scanner   │───▶│  Webhook     │───▶│  Agent        │  │
│  │   Engine    │    │  Dispatcher  │    │  Session Mgr  │  │
│  └─────────────┘    └──────────────┘    └───────────────┘  │
│         │                                      │            │
│         ▼                                      ▼            │
│  ┌─────────────┐                        ┌───────────────┐  │
│  │  Findings   │◄───────────────────────│  Findings     │  │
│  │  Database   │   Combined Results     │  Ingestion    │  │
│  └─────────────┘                        └───────────────┘  │
└─────────────────────────────────────────────────────────────┘
                              ▲
                              │ Webhook (scan.completed / scan.failed)
                              │
                    ┌─────────────────────┐
                    │  Phantom Webhook    │
                    │  Receiver           │
                    │  (port 8080)        │
                    └──────────┬──────────┘
                               │
                    ┌──────────▼──────────┐
                    │  Hermes CLI         │
                    │  (cron job)         │
                    │  Agent explores     │
                    │  target as user     │
                    └─────────────────────┘
```

---

## Struktur Proyek

```
shieldpdp/
├── app/                          # Backend FastAPI utama
│   ├── api/                      # API Routes
│   │   ├── agent_sessions.py     # Agent session management (user + agent auth)
│   │   ├── auth.py               # Autentikasi & RBAC
│   │   ├── compliance.py         # Compliance mapping & breach notification
│   │   ├── dashboard.py          # Dashboard aggregation
│   │   ├── deps.py               # Dependencies & auth helpers
│   │   ├── enterprise.py         # Enterprise features (projects, targets, scans, endpoints)
│   │   ├── findings.py           # Findings list & agent finding ingestion
│   │   ├── remediation.py        # Remediation workflow
│   │   ├── reports.py            # Report generation (HTML/PDF)
│   │   ├── router.py             # Router aggregation
│   │   ├── scans.py              # Scan management (start/stop/status)
│   │   ├── telegram.py           # Telegram webhook handler (approve/deny/status)
│   │   └── webhooks.py           # Webhook subscription CRUD
│   │
│   ├── services/                 # Business logic layer
│   │   ├── agent_service.py      # Agent session management + Telegram notifications
│   │   ├── audit_service.py      # Immutable audit logging
│   │   ├── breach_notification.py# Breach notification workflow (Pasal 46 UU PDP)
│   │   ├── discovery_validation.py# Endpoint discovery validation
│   │   ├── policy_engine.py      # Policy enforcement & scope guarding
│   │   ├── risk_engine.py        # Risk scoring
│   │   ├── scan_crud.py          # Scan CRUD operations
│   │   ├── scan_reporting.py     # Scan reporting helpers
│   │   ├── scan_scoring.py       # Scan scoring engine
│   │   ├── scan_service.py       # Scan orchestration
│   │   ├── scope_guard.py        # Scope boundary enforcement
│   │   └── webhook_service.py    # Webhook dispatch (HMAC-SHA256 signing)
│   │
│   ├── models/                   # SQLAlchemy models
│   │   ├── agent.py              # AgentSession model
│   │   ├── audit.py              # AuditLog model
│   │   ├── enums.py              # AgentActionPhase, SessionStatus enums
│   │   ├── finding.py            # Finding model
│   │   ├── organization.py       # Organization, Role, User models
│   │   ├── project.py            # Project, Target, Scan, Endpoint, Policy models
│   │   ├── reporting.py          # Report, ComplianceMapping, RemediationTracking models
│   │   ├── roe.py               # RoeDocument model (Rules of Engagement)
│   │   └── scan.py               # Scan (+ engagement_mode/roe columns), WebhookSubscription
│   │
│   ├── schemas/                  # Pydantic schemas
│   │   ├── agent.py              # Agent session schemas
│   │   ├── auth.py               # Auth schemas
│   │   ├── dashboard.py          # Dashboard schemas
│   │   ├── enterprise.py         # Enterprise schemas
│   │   ├── finding.py            # Finding schemas
│   │   ├── report.py             # Report schemas
│   │   ├── scan.py               # Scan schemas
│   │   └── webhook.py            # Webhook & finding ingestion schemas
│   │
│   ├── core/                     # Config, security, RBAC, bootstrap
│   │   ├── config.py             # Settings (env vars, validators)
│   │   ├── rbac.py               # Permission enum, role-permission mapping
│   │   ├── security.py           # JWT, password hashing, helpers
│   │   └── bootstrap.py          # Seed defaults, mark interrupted scans
│   │
│   ├── recon/                    # Async recon engine
│   ├── crawler/                  # Async crawler and extraction engine
│   ├── classifier/               # Endpoint heuristic classifier
│   ├── validation/               # Validation engines
│   │   ├── sqli.py               # SQLi validation
│   │   ├── bola.py               # BOLA/IDOR validation
│   │   ├── path_traversal.py     # Path traversal validation
│   │   ├── reflected_html.py     # Reflected HTML/XSS validation
│   │   ├── cors.py               # CORS validation
│   │   ├── auth.py               # Auth validation
│   │   ├── api_exposure.py       # API exposure validation
│   │   ├── exploit_chains.py     # Exploit chain mode (opt-in lab)
│   │   ├── username_enumeration.py# Username enumeration validation
│   │   ├── false_positive.py     # False positive reduction
│   │   ├── access_matrix.py      # Access matrix enforcement
│   │   └── data_rights/          # Data rights validation (UU PDP)
│   │
│   ├── pii_detection/            # PII pattern detection
│   ├── compliance/               # UU PDP & OWASP ASVS mapping
│   ├── reporting/                # HTML/PDF report generation
│   ├── evidence/                 # Evidence hashing & curl reproduction
│   ├── remediation/              # Remediation workflow service
│   ├── dashboard/                # Dashboard aggregation service
│   ├── database/                 # Async SQLAlchemy session
│   ├── middleware/               # Request context & security headers
│   ├── repositories/             # Tenant-scoped repository helpers
│   ├── utils/                    # Rate limiter, redaction, RoE text extraction
│   ├── templates/                # Jinja2 HTML templates (dashboard, report)
│   └── main.py                   # FastAPI app entrypoint
│
├── frontend/                     # React dashboard (Vite + TypeScript + TailwindCSS)
│   ├── src/
│   │   ├── pages/                # Dashboard, Projects, Targets, Scans, Findings,
│   │   │                         # Compliance, Reports, Remediation, Agent Sessions,
│   │   │                         # Settings, Scan Detail, Login
│   │   ├── components/           # UI components (shadcn-style), layout, metric cards
│   │   ├── hooks/                # Custom React hooks (useApi)
│   │   ├── lib/                  # API client, utilities
│   │   ├── context/              # Auth context
│   │   └── types/                # TypeScript types
│   └── package.json
│
├── worker/                       # Celery worker (optional)
│   ├── celery_app.py
│   └── tasks.py
│
├── migrations/                   # Alembic migrations (0001–0006; 0006 = engagement_mode + RoE)
├── tests/                        # Test suite (26 test files)
├── docker/                       # Docker configuration
│   └── entrypoint.sh
│
├── phantom_webhook_receiver.py   # Standalone webhook receiver for Phantom agent
├── demo_integration.py           # Demo script for full integration workflow
├── run_integration.sh            # Setup & run script
├── start_webhook_receiver.sh     # Webhook receiver start script
├── docker-compose.yml            # Docker orchestration (postgres, redis, web, worker)
├── Dockerfile                    # Python 3.11 slim image
├── alembic.ini                   # Alembic configuration
├── requirements.txt              # Python dependencies
├── pytest.ini                    # pytest configuration
├── INTEGRATION.md                # Integration guide
├── README.md                     # Project documentation
└── ARCHITECTURE_HERMES.md        # Architecture document (this file)
```

---

## Arsitektur Integrasi Hermes

### Komponen Utama

| Komponen | File | Fungsi |
|----------|------|--------|
| **Webhook Receiver** | `phantom_webhook_receiver.py` | Menerima notifikasi scan completion, membuat Hermes cron job |
| **Agent Service** | `app/services/agent_service.py` | Manajemen sesi agent, logging, approval workflow, Telegram |
| **Agent Sessions API** | `app/api/agent_sessions.py` | REST API untuk CRUD agent sessions (user + agent auth) |
| **Findings Ingest API** | `app/api/findings.py` | Endpoint untuk agent submit findings |
| **Scan / RoE API** | `app/api/scans.py` | `POST /scan/start` (engagement_mode) & `POST /scan/roe` (RoE upload) |
| **RoE Extraction** | `app/utils/roe_extract.py` | Ekstraksi teks RoE + warning untuk PDF image-only |
| **Webhook Service** | `app/services/webhook_service.py` | Dispatch webhook ke external endpoints (HMAC-SHA256) |
| **Webhook Management API** | `app/api/webhooks.py` | CRUD webhook subscriptions |
| **Telegram Integration** | `app/api/telegram.py` | Handle Telegram commands untuk approval |
| **Compliance API** | `app/api/compliance.py` | Breach notification workflow (Pasal 46 UU PDP) |

### Alur Data

```
0. (OPSIONAL, external only) RoE UPLOAD
   User → POST /scan/roe (engagement_mode=external, file) → RoeDocument
   → return roe_document_id (org-scoped)

1. SCAN START
   User → POST /scan/start (engagement_mode, roe_document_id) → ShieldPDP Scanner Engine

2. SCAN COMPLETES
   Scanner → Webhook Service → POST ke registered webhooks (HMAC-SHA256 signed)
   Payload membawa engagement_mode, roe_basis, roe_text, roe_extraction_warning
   Webhook → phantom_webhook_receiver.py (port 8080)

3. RECEIVER PIPELINE (async, threaded)
   → Verify HMAC signature
   → POST /agent-sessions/ingest (X-Agent-Secret) → Create AgentSession
   → Save scan context → {HERMES_HOME}/profiles/phantom/pending_scans/{scan_id}.json
   → Build prompt: _build_internal_prompt / _build_external_prompt (per engagement_mode)
   → hermes cron create 1m <prompt> --repeat 1 --name explore-{scan_id} --deliver origin
   → hermes send --to telegram (notification)

4. AGENT EXPLORATION (via Hermes scheduler tick)
   Hermes CLI → Agent reads scan context → Explores target
   Agent → POST /findings/ingest (X-Agent-Secret) → Submit confirmed findings
   Agent → POST /agent-sessions/ingest → Update status/action_phase
   Agent → POST /agent-sessions/{id}/ingest-log → Push log entries

5. APPROVAL WORKFLOW (via Telegram)
   Agent → Request approval → Telegram notification
   User → Reply "approve <prefix>" or "deny <prefix>" → POST /telegram/webhook
   → POST /agent-sessions/{id}/approve

6. SESSION COMPLETE
   Agent → POST /agent-sessions/{id}/ingest-complete → Mark session done

7. REPORTING
   ShieldPDP combines auto + agent findings → Generate report (HTML/PDF)
```

---

## Alur Kerja Lengkap

### 1. Inisialisasi & Setup

```bash
# Setup environment
cd shieldpdp
cp .env.example .env

# Konfigurasi secrets di .env:
# SECRET_KEY=<generate with: openssl rand -hex 32>
# AGENT_SECRET=<generate with: openssl rand -hex 32>
# PHANTOM_AGENT_SECRET=<same as AGENT_SECRET>
# PHANTOM_WEBHOOK_SECRET=<generate with: openssl rand -hex 32>
# ADMIN_PASSWORD=<strong password>

# Optional: Telegram integration
# TELEGRAM_BOT_TOKEN=your-bot-token
# TELEGRAM_CHAT_ID=your-chat-id

# Optional: Environment
# ENVIRONMENT=local  (or "production" for strict secret validation)
```

### 2. Start Services

```bash
# Option A: Menggunakan script integrasi
./run_integration.sh

# Option B: Manual
# Terminal 1: ShieldPDP server
DATABASE_URL=sqlite+aiosqlite:///./nyuwunsewu_prod.db \
ALLOW_PRIVATE_TARGETS=true \
USE_CELERY=false \
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Terminal 2: Phantom webhook receiver
source .env
python phantom_webhook_receiver.py

# Terminal 3: Frontend (optional)
cd frontend
npm install
npm run dev
```

### 3. Register Webhook

```bash
# Login untuk mendapatkan token
TOKEN=$(curl -s -X POST http://127.0.0.1:8000/auth/login \
  -H "Content-Type: application/json" \
  -d '{"email":"admin@nyuwunsewu.local","password":"ChangeMe123!"}' \
  | python3 -c "import sys,json; print(json.load(sys.stdin)['access_token'])")

# Register webhook untuk scan completion
curl -s -X POST http://127.0.0.1:8000/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "name": "Phantom Agent",
    "url": "http://127.0.0.1:8080",
    "events": ["scan.completed", "scan.failed"]
  }'
```

### 4. Start Scan

```bash
curl -s -X POST http://127.0.0.1:8000/scan/start \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "target_url": "https://target.example.com",
    "project_name": "Security Assessment",
    "allowed_domains": ["target.example.com"],
    "exploit_chains": {"enabled": true},
    "policy": {"max_depth": 2, "max_pages": 100}
  }'
```

### 5. Otomatis: Agent Exploration

Setelah scan selesai, alur berikut berjalan otomatis:

1. **Webhook trigger** — ShieldPDP POST ke `http://127.0.0.1:8080` (HMAC-SHA256 signed)
2. **Webhook receiver** verify signature, parse payload, extract `scan_id` dan `target_url`
3. **Create agent session** — POST `/agent-sessions/ingest` dengan `X-Agent-Secret`
4. **Save scan context** — Endpoint map, metadata ke `pending_scans/{scan_id}.json`
5. **Create Hermes cron job** — One-shot exploration task dengan prioritized validation
6. **Hermes scheduler ticks** — Agent mulai eksplorasi
7. **Agent validates** — BOLA/IDOR, authz, auth, injection, info disclosure
8. **Agent submits findings** — POST `/findings/ingest` per confirmed finding
9. **Agent updates session** — Status, action_phase, log entries
10. **Complete session** — POST `/agent-sessions/{id}/ingest-complete`

### 6. Review & Report

Temuan dari scanner otomatis dan agent digabungkan dalam report:
- Dashboard UI: `http://localhost:5173` (Agent Sessions page untuk monitoring real-time)
- API: `GET /reports`
- Download: `GET /reports/{report_id}/download` (HTML atau PDF)

---

## Komponen API untuk Agent

### Agent Sessions API (User Auth — JWT Bearer Token)

| Method | Path | Deskripsi | Auth |
|--------|------|-----------|------|
| `GET` | `/agent-sessions` | List semua agent sessions | Bearer Token (READ_DASHBOARD) |
| `GET` | `/agent-sessions/{id}` | Detail session spesifik | Bearer Token (READ_DASHBOARD) |
| `POST` | `/agent-sessions` | Buat session baru | Bearer Token (SCAN_CREATE) |
| `POST` | `/agent-sessions/{id}/log` | Tambah log entry | Bearer Token (READ_DASHBOARD) |
| `POST` | `/agent-sessions/{id}/request-approval` | Request approval aksi berisiko | Bearer Token (READ_DASHBOARD) |
| `POST` | `/agent-sessions/{id}/approve` | Approve/deny pending action | Bearer Token (SCAN_CREATE) |
| `POST` | `/agent-sessions/{id}/complete` | Mark session completed | Bearer Token (SCAN_CREATE) |

### Agent Sessions API (Agent Auth — X-Agent-Secret)

| Method | Path | Deskripsi | Auth |
|--------|------|-----------|------|
| `POST` | `/agent-sessions/ingest` | Create atau update session | `X-Agent-Secret` header |
| `POST` | `/agent-sessions/{id}/ingest-log` | Push log entry | `X-Agent-Secret` header |
| `POST` | `/agent-sessions/{id}/ingest-complete` | Mark session complete | `X-Agent-Secret` header |

### Findings Ingestion API

| Method | Path | Deskripsi | Auth |
|--------|------|-----------|------|
| `POST` | `/findings/ingest` | Submit finding dari agent | `X-Agent-Secret` header |

### Webhook Management API

| Method | Path | Deskripsi | Auth |
|--------|------|-----------|------|
| `GET` | `/webhooks` | List webhook subscriptions | Bearer Token (READ_DASHBOARD) |
| `POST` | `/webhooks` | Buat webhook baru | Bearer Token (SCAN_CREATE) |
| `GET` | `/webhooks/{id}` | Detail webhook | Bearer Token (READ_DASHBOARD) |
| `PATCH` | `/webhooks/{id}` | Update webhook | Bearer Token (SCAN_CREATE) |
| `DELETE` | `/webhooks/{id}` | Hapus webhook | Bearer Token (SCAN_CREATE) |

### Telegram Integration

| Method | Path | Deskripsi | Auth |
|--------|------|-----------|------|
| `POST` | `/telegram/webhook` | Handle Telegram commands (approve/deny/status) | Telegram webhook |

### Request/Response Schemas

#### Agent Finding Ingest (`POST /findings/ingest`)

**Request Headers:**
```
Content-Type: application/json
X-Agent-Secret: <shared-secret>
```

**Request Body:**
```json
{
  "scan_id": "optional-scan-id",
  "target_url": "https://target.example.com",
  "finding_type": "idor_account_takeover",
  "title": "IDOR Allows Access to Other Users Data",
  "severity": "critical",
  "confidence": 95.0,
  "description": "Detailed description of the finding",
  "reasoning": ["Step 1", "Step 2", "Step 3"],
  "evidence": {
    "proof_of_concept": "PoC description",
    "affected_accounts": ["123", "124"]
  },
  "request_method": "GET",
  "request_url": "https://target/api/accounts/124",
  "request_headers": {"Authorization": "Bearer [REDACTED]"},
  "response_status": 200,
  "response_body": "{\"account_id\": 124, ...}",
  "remediation": "Implement ownership verification",
  "agent_name": "phantom",
  "exploit_chain": ["Step 1", "Step 2", "Step 3"]
}
```

**Response:**
```json
{
  "finding_id": "uuid-here",
  "status": "open",
  "message": "Finding ingested: IDOR Allows Access to Other Users Data"
}
```

#### Agent Session Ingest (`POST /agent-sessions/ingest`)

**Request Headers:**
```
Content-Type: application/json
X-Agent-Secret: <shared-secret>
```

**Request Body:**
```json
{
  "scan_id": "scan-uuid",
  "target_url": "https://target.example.com",
  "agent_name": "phantom",
  "status": "exploring",
  "action_phase": "testing_idor",
  "current_action": "Testing IDOR on /api/accounts",
  "message": "Starting IDOR validation on account endpoints",
  "level": "info",
  "action": "testing_idor"
}
```

**Response:**
```json
{
  "session_id": "uuid-here",
  "status": "exploring",
  "message": "Session updated"
}
```

#### Webhook Payload (dari ShieldPDP ke Agent)

```json
{
  "event": "scan.completed",
  "scan_id": "abc-123",
  "target_url": "https://target.example.com",
  "project_id": "proj-123",
  "status": "completed",
  "findings_count": 5,
  "endpoints_count": 150,
  "stats": {
    "endpoints": 150,
    "findings": 5,
    "risk_score": 8.5
  },
  "engagement_mode": "external",
  "roe_basis": "document",
  "roe_text": "...extracted Rules-of-Engagement text...",
  "roe_extraction_warning": false,
  "finished_at": "2025-01-01T12:00:00Z"
}
```

Field `engagement_mode` adalah `internal` atau `external`. Untuk `internal`, `roe_basis`
dan `roe_text` bernilai `null`. Untuk `external`, `roe_basis` adalah `"document"` (RoE
diupload) atau `"default_roe_v1"` (default konservatif berversi). Receiver memakai field
ini untuk memilih internal vs external exploration prompt.

**Headers:**
```
content-type: application/json
user-agent: NyuwunSewu-Webhook/1.0
x-nyuwunsewu-event: scan.completed
x-nyuwunsewu-signature: sha256=<hmac-signature>
```

---

## Model Data

### AgentSession

| Field | Type | Deskripsi |
|-------|------|-----------|
| `id` | String(36) | UUID primary key |
| `organization_id` | String(36) | FK ke organizations (resolved from scan) |
| `scan_id` | String(36) | FK ke scans (optional) |
| `agent_name` | String(120) | Nama agent (default: "phantom") |
| `target_url` | String(2048) | Target URL yang di-explore |
| `status` | String(32) | idle, exploring, pending_approval, approved, denied, completed, failed, refused |
| `current_action` | String(512) | Aksi yang sedang dilakukan (canonical action phase) |
| `logs` | JSON | Array of log entries |
| `pending_action` | JSON | Detail aksi yang menunggu approval |
| `findings_count` | Integer | Jumlah finding yang disubmit |
| `started_at` | DateTime | Waktu mulai session |
| `completed_at` | DateTime | Waktu selesai session |
| `created_at` | DateTime | Auto-generated |
| `updated_at` | DateTime | Auto-generated |

### Scan — Kolom Engagement (tabel `scans`)

| Field | Type | Deskripsi |
|-------|------|-----------|
| `engagement_mode` | String(16) | `internal` (SAFE) atau `external` (NSFW); default `internal` |
| `roe_document_id` | String(36) | FK ke `roe_documents` (nullable) |
| `roe_basis` | String(32) | `document` atau `default_roe_v1` (nullable; hanya external) |

### RoeDocument (tabel `roe_documents`)

Dokumen Rules-of-Engagement yang diupload untuk engagement external. Disimpan untuk audit/compliance meski scan sudah selesai.

| Field | Type | Deskripsi |
|-------|------|-----------|
| `id` | String(36) | UUID primary key |
| `organization_id` | String(36) | FK ke organizations (org-scoped, indexed) |
| `filename` | String(512) | Nama file asli |
| `extracted_text` | Text | Teks yang diekstrak dari dokumen |
| `char_count` | Integer | Jumlah karakter teks terekstrak |
| `extraction_warning` | Boolean | `true` jika PDF image-only (tidak ada teks terbaca) |

### EngagementMode (enum)

| Value | Alias | Deskripsi |
|-------|-------|-----------|
| `internal` | SAFE | Target milik sendiri / pre-prod, otorisasi sudah ada |
| `external` | NSFW | Testing sistem live yang terotorisasi; scope dari RoE atau default berversi |

### Agent Action Phases (Canonical)

| Phase | Deskripsi |
|-------|-----------|
| `initializing` | Session sedang dibuat |
| `recon` | Reconnaissance dan endpoint mapping |
| `enumerating_accounts` | Registrasi / enumerasi test accounts |
| `testing_idor` | Testing IDOR / BOLA |
| `testing_authz` | Testing authorization / privilege escalation |
| `testing_auth` | Testing authentication / session / JWT |
| `testing_injection` | Testing injection (XSS / SQLi) |
| `testing_info_disclosure` | Testing info disclosure / misconfig |
| `submitting_finding` | Submitting confirmed finding |
| `awaiting_approval` | Menunggu approval operator |
| `summarizing` | Summarizing results |
| `completed` | Exploration selesai |
| `refused` | Agent menolak melanjutkan (ethical halt — berbeda dari failed) |
| `failed` | Exploration gagal |

### Log Entry Structure

```json
{
  "timestamp": "2025-01-01T12:00:00Z",
  "level": "info",
  "message": "Starting exploration as nasabah",
  "action": "login",
  "details": {}
}
```

Levels: `info`, `warning`, `error`, `success`

### Finding (dari Agent)

Agent findings disimpan dengan struktur yang sama seperti finding otomatis, dengan tambahan metadata:

```python
evidence_summary = {
    "source": "agent",
    "agent_name": "phantom",
    "exploit_chain": ["step1", "step2"],
    "evidence": {...},
    "request": {...},
    "response": {...}
}
```

---

## Keamanan

### Authentication

| Komponen | Method | Deskripsi |
|----------|--------|-----------|
| **User API** | JWT Bearer Token | RBAC-based authentication (5 roles) |
| **Agent Ingest** | `X-Agent-Secret` header | Shared secret untuk agent authentication |
| **Webhook Signature** | HMAC-SHA256 | Payload signing via `x-nyuwunsewu-signature` header |

### Agent Secret Verification

```python
def _verify_agent_auth(x_agent_secret: str | None) -> bool:
    if not x_agent_secret:
        return False
    settings = get_settings()
    agent_secret = getattr(settings, "agent_secret", None)
    if not agent_secret:
        logger.warning("AGENT_SECRET is not configured — rejecting agent request.")
        return False
    return hmac.compare_digest(x_agent_secret, agent_secret)
```

### Webhook Signature Verification

```python
signature = self.headers.get('x-nyuwunsewu-signature', '')
if signature:
    expected = f"sha256={hmac.new(WEBHOOK_SECRET.encode(), body, hashlib.sha256).hexdigest()}"
    if not hmac.compare_digest(signature, expected):
        self.send_response(403)
        return
```

### Sensitive Data Protection

- Headers sensitif (`Authorization`, `Cookie`, `X-API-Key`) di-redact sebelum penyimpanan
- Agent findings ditandai dengan `source: "agent"` untuk audit trail
- HMAC timing-safe comparison mencegah timing attacks
- Agent session di-scope ke organization dari scan (tidak bisa cross-tenant)
- Receiver menolak secret yang lemah/default di production environment

### Environment Variables

| Variable | Deskripsi | Default |
|----------|-----------|---------|
| `SECRET_KEY` | JWT signing secret | `change-me-in-production` |
| `AGENT_SECRET` / `PHANTOM_AGENT_SECRET` | Shared secret untuk agent auth | None |
| `PHANTOM_WEBHOOK_SECRET` | HMAC secret untuk webhook signature | None |
| `PHANTOM_WEBHOOK_PORT` | Port untuk webhook receiver | `8080` |
| `NYUWUNSEWU_URL` | URL ShieldPDP API | `http://127.0.0.1:8000` |
| `ADMIN_EMAIL` | Admin email untuk API login | `admin@nyuwunsewu.local` |
| `ADMIN_PASSWORD` / `BOOTSTRAP_ADMIN_PASSWORD` | Admin password | `ChangeMe123!` |
| `HERMES_HOME` | Hermes root home directory | `~/.hermes` |
| `HERMES_PROFILE` | Hermes profile name | `phantom` |
| `ENVIRONMENT` | Environment (local/production) | `local` |
| `TELEGRAM_BOT_TOKEN` | Bot token untuk Telegram integration | None |
| `TELEGRAM_CHAT_ID` | Chat ID untuk notifikasi | None |
| `DATABASE_URL` | PostgreSQL connection string | `postgresql+asyncpg://...` |
| `ALLOW_PRIVATE_TARGETS` | Allow scanning private/local IPs | `false` |
| `USE_CELERY` | Use Celery untuk background tasks | `false` |
| `WEB_CONCURRENCY` | Jumlah uvicorn worker untuk container API | `2` |

---

## Deployment

### Docker Compose

```yaml
# docker-compose.yml (actual)
services:
  postgres:
    image: postgres:16-alpine
    environment:
      POSTGRES_DB: nyuwunsewu
      POSTGRES_USER: nyuwunsewu
      POSTGRES_PASSWORD: nyuwunsewu
    ports:
      - "5432:5432"
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7-alpine
    ports:
      - "6379:6379"

  web:
    build: .
    env_file: .env
    environment:
      DATABASE_URL: postgresql+asyncpg://nyuwunsewu:nyuwunsewu@postgres:5432/nyuwunsewu
      SECRET_KEY: ${SECRET_KEY}
      AGENT_SECRET: ${PHANTOM_AGENT_SECRET}
      BOOTSTRAP_ADMIN_PASSWORD: ChangeMe123!
      ALLOW_PRIVATE_TARGETS: "false"
      WEB_CONCURRENCY: "4"
    ports:
      - "8000:8000"
    depends_on:
      postgres: {condition: service_healthy}
      redis: {condition: service_healthy}

  worker:
    build: .
    env_file: .env
    command: celery -A worker.celery_app.celery_app worker --loglevel=INFO --concurrency=2
    restart: always
    environment:
      DATABASE_URL: postgresql+asyncpg://nyuwunsewu:nyuwunsewu@postgres:5432/nyuwunsewu
      SECRET_KEY: ${SECRET_KEY}
      AGENT_SECRET: ${PHANTOM_AGENT_SECRET}
      USE_CELERY: "true"
      ALLOW_PRIVATE_TARGETS: "false"
      RUN_MIGRATIONS: "false"
    depends_on:
      postgres: {condition: service_healthy}
      redis: {condition: service_healthy}
      web: {condition: service_started}

volumes:
  pgdata:
```

### Phantom Webhook Receiver (Standalone)

```bash
# Start receiver separately (not in docker-compose)
source .env
python3 phantom_webhook_receiver.py
```

Environment variables needed:
- `PHANTOM_WEBHOOK_SECRET` — untuk verify webhook signatures
- `PHANTOM_AGENT_SECRET` — untuk authenticate ke NyuwunSewu API
- `NYUWUNSEWU_URL` — URL NyuwunSewu backend
- `ADMIN_PASSWORD` — untuk login ke NyuwunSewu API
- `HERMES_HOME` — Hermes root home (default: `~/.hermes`)
- `HERMES_PROFILE` — Hermes profile (default: `phantom`)

### Local Development

```bash
# Terminal 1: ShieldPDP
DATABASE_URL=sqlite+aiosqlite:///./nyuwunsewu_local.db
ALLOW_PRIVATE_TARGETS=true
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001

# Terminal 2: Phantom Webhook Receiver
source .env
python phantom_webhook_receiver.py

# Terminal 3: Frontend (optional)
cd frontend
npm install
npm run dev
```

---

## Troubleshooting

### Server tidak bisa start

```bash
# Cek port yang digunakan
lsof -i :8000
lsof -i :8080

# Cek log
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Webhook tidak diterima

1. Verifikasi webhook terdaftar: `GET /webhooks`
2. Cek URL webhook reachable dari ShieldPDP
3. Verifikasi events match: `["scan.completed"]`
4. Cek delivery status di subscription
5. Cek receiver logs: `phantom_receiver.log`

### Finding ingestion gagal

1. Verifikasi `AGENT_SECRET` / `PHANTOM_AGENT_SECRET` sama di `.env` dan request header
2. Cek `scan_id` exists (jika disediakan)
3. Verifikasi struktur JSON payload sesuai schema
4. Cek server logs untuk error detail

### Agent session tidak muncul di dashboard

1. Verifikasi `scan_id` di ingest request mengarah ke scan yang ada
2. Session di-scope ke organization dari scan — pastikan login ke org yang benar
3. Cek `/agent-sessions` API langsung untuk verifikasi session ada

### Telegram tidak mengirim notifikasi

1. Cek `TELEGRAM_BOT_TOKEN` dan `TELEGRAM_CHAT_ID` di `.env`
2. Verifikasi bot token valid
3. Cek chat ID benar dan bot sudah di-add ke grup/chat
4. Cek receiver logs untuk error dari Telegram API

### Receiver tidak membuat cron job

1. Pastikan `hermes` CLI terinstall dan bisa diakses dari PATH
2. Cek `HERMES_HOME` dan `HERMES_PROFILE` di `.env`
3. Cek apakah Hermes scheduler berjalan
4. Cek `phantom_receiver.log` untuk error detail

---

## Diagram Sequence: Integrasi Lengkap

```
User                    ShieldPDP               Phantom Receiver          Hermes Agent
 │                        │                             │                      │
 │  POST /scan/start      │                             │                      │
 ├───────────────────────>│                             │                      │
 │                        │  Scan in progress...        │                      │
 │                        │                             │                      │
 │                        │  Scan completed             │                      │
 │                        │  POST webhook               │                      │
 │                        ├────────────────────────────>│                      │
 │                        │                             │                      │
 │                        │  POST /agent-sessions/ingest│                      │
 │                        │<────────────────────────────┤                      │
 │                        │                             │                      │
 │                        │                             │  Create cron job     │
 │                        │                             ├─────────────────────>│
 │                        │                             │                      │
 │                        │                             │  hermes send (TG)    │
 │                        │                             ├──────────────────────│
 │                        │                             │                      │
 │                        │  POST /findings/ingest      │                      │
 │                        │<───────────────────────────────────────────────────┤
 │                        │                             │                      │
 │                        │  POST /agent-sessions/ingest│                      │
 │                        │<───────────────────────────────────────────────────┤
 │                        │                             │                      │
 │                        │  POST /agent-sessions/{id}/ingest-log              │
 │                        │<───────────────────────────────────────────────────┤
 │                        │                             │                      │
 │  GET /agent-sessions   │                             │                      │
 │<───────────────────────┤                             │                      │
 │  (Real-time logs)      │                             │                      │
 │                        │                             │                      │
 │  "approve <prefix>"    │                             │                      │
 │ ──── Telegram ────────>│  POST /telegram/webhook     │                      │
 │                        │  POST /agent-sessions/{id}/approve                 │
 │                        │                             │                      │
 │                        │  POST /agent-sessions/{id}/ingest-complete         │
 │                        │<───────────────────────────────────────────────────┤
 │                        │                             │                      │
 │  GET /reports          │                             │                      │
 │<───────────────────────┤                             │                      │
 │  (Combined findings)   │                             │                      │
```

---

## Key Takeaways

1. **Hermes/Phantom agent** adalah komponen eksternal yang berkomunikasi dengan ShieldPDP via webhook dan API
2. **Webhook** adalah trigger utama — ketika scan selesai, ShieldPDP notifikasi agent (HMAC-SHA256 signed)
3. **Phantom webhook receiver** menerima webhook, membuat agent session, menyimpan scan context, dan membuat Hermes cron job
4. **Hermes CLI cron** menjalankan agent exploration — agent menggunakan endpoint map dari scan, tidak perlu re-crawl
5. **Agent session** melifecycle lengkap eksplorasi agent dari idle sampai completed/refused
6. **Canonical action phases** memberikan status real-time yang konsisten di dashboard
7. **Approval workflow** memungkinkan human-in-the-loop untuk aksi berisiko via Telegram
8. **Finding ingestion** menggunakan shared secret authentication (`X-Agent-Secret`) dengan HMAC timing-safe comparison
9. **Combined reporting** menggabungkan temuan scanner otomatis dan agent untuk laporan komprehensif
10. **Security** — HMAC signatures, tenant-scoped sessions, redacted evidence, fail-fast secrets

---

*Dokumen ini memetakan arsitektur integrasi Hermes/Phantom agent dengan NyuwunSewu ShieldPDP. Referensi: `INTEGRATION.md`, `README.md`, source code.*
