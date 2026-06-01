# 🗺️ Peta Arsitektur ShieldPDP + Integrasi Agent Hermes/Phantom

Dokumen ini memetakan secara lengkap struktur proyek NyuwunSewu ShieldPDP dan bagaimana integrasi dengan agent Hermes/Phantom bekerja.

---

## 📋 Daftar Isi

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

## 📖 Gambaran Umum

**NyuwunSewu ShieldPDP** adalah platform validasi keamanan berbasis compliance untuk assessment API enterprise. Platform ini mengintegrasikan:

1. **Scanner otomatis** - Async crawler dan validation engine untuk SQLi, BOLA/IDOR, XSS, dll
2. **Agent Hermes/Phantom** - AI agent yang melakukan eksplorasi interaktif dan chaining vulnerability
3. **Dashboard frontend** - React UI untuk monitoring dan reporting
4. **Integrasi Telegram** - Notifikasi dan approval workflow untuk aksi berisiko

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
                              │ Webhook (scan.completed)
                              │
                    ┌─────────────────────┐
                    │  Hermes/Phantom     │
                    │  Agent Server       │
                    │  (port 8080)        │
                    └─────────────────────┘
```

---

## 📁 Struktur Proyek

```
shieldpdp/
├── app/                          # Backend FastAPI utama
│   ├── api/                      # API Routes
│   │   ├── agent_sessions.py     # 🤖 Endpoint manajemen sesi agent
│   │   ├── auth.py               # Autentikasi & RBAC
│   │   ├── findings.py           # 🤖 Endpoint ingest finding dari agent
│   │   ├── webhooks.py           # 🤖 Manajemen webhook subscription
│   │   ├── telegram.py           # 🤖 Webhook handler Telegram
│   │   ├── scans.py              # Manajemen scan
│   │   ├── reports.py            # Report generation
│   │   ├── dashboard.py          # Dashboard aggregation
│   │   ├── compliance.py         # Compliance mapping
│   │   ├── remediation.py        # Remediation workflow
│   │   ├── enterprise.py         # Enterprise features
│   │   ├── deps.py               # Dependencies & auth helpers
│   │   └── router.py             # Router aggregation
│   │
│   ├── services/                 # Business logic layer
│   │   ├── agent_service.py      # 🤖 Agent session management + Telegram
│   │   ├── webhook_service.py    # 🤖 Webhook dispatch service
│   │   ├── scan_service.py       # Scan orchestration
│   │   ├── policy_engine.py      # Policy enforcement
│   │   ├── risk_engine.py        # Risk scoring
│   │   ├── scope_guard.py        # Scope boundary enforcement
│   │   ├── audit_service.py      # Audit logging
│   │   └── discovery_validation.py # Validation engines
│   │
│   ├── models/                   # SQLAlchemy models
│   │   └── entities.py           # 🤖 AgentSession, WebhookSubscription, dll
│   │
│   ├── schemas/                  # Pydantic schemas
│   │   ├── agent.py              # 🤖 Agent session schemas
│   │   └── webhook.py            # 🤖 Webhook & finding ingestion schemas
│   │
│   ├── core/                     # Config, security, bootstrap
│   ├── recon/                    # Async crawler engine
│   ├── validation/               # Validation engines (SQLi, IDOR, XSS)
│   ├── classifier/               # Endpoint classification
│   ├── pii_detection/            # PII detection
│   ├── compliance/               # UU PDP & OWASP ASVS mapping
│   ├── reporting/                # HTML/PDF report generation
│   ├── evidence/                 # Evidence hashing
│   ├── remediation/              # Remediation workflow
│   ├── dashboard/                # Dashboard aggregation
│   ├── database/                 # Async SQLAlchemy session
│   ├── middleware/               # Request context & security headers
│   ├── repositories/             # Tenant-scoped repository helpers
│   └── main.py                   # FastAPI app entrypoint
│
├── frontend/                     # React dashboard (Vite + Tailwind)
├── worker/                       # Celery worker (optional)
│   ├── celery_app.py
│   └── tasks.py
├── migrations/                   # Alembic migrations
├── tests/                        # Test suite
├── docker/                       # Docker configuration
│   └── entrypoint.sh
│
├── phantom_webhook_receiver.py   # 🤖 Standalone webhook receiver untuk agent
├── demo_integration.py           # 🤖 Demo script integrasi lengkap
├── run_integration.sh            # 🤖 Setup & run script
├── docker-compose.yml            # Docker orchestration
├── INTEGRATION.md                # 📖 Integration guide
├── README.md                     # 📖 Project documentation
└── requirements.txt              # Python dependencies
```

---

## 🔄 Arsitektur Integrasi Hermes

### Komponen Utama

| Komponen | File | Fungsi |
|----------|------|--------|
| **Webhook Receiver** | `phantom_webhook_receiver.py` | Menerima notifikasi scan completion dari ShieldPDP |
| **Agent Service** | `app/services/agent_service.py` | Manajemen sesi agent, logging, approval workflow |
| **Agent Sessions API** | `app/api/agent_sessions.py` | REST API untuk CRUD agent sessions |
| **Findings Ingest API** | `app/api/findings.py` | Endpoint untuk agent submit findings |
| **Webhook Service** | `app/services/webhook_service.py` | Dispatch webhook ke external endpoints |
| **Webhook Management API** | `app/api/webhooks.py` | CRUD webhook subscriptions |
| **Telegram Integration** | `app/api/telegram.py` | Handle Telegram commands untuk approval |

### Alur Data

```
1. SCAN START
   User → POST /scan/start → ShieldPDP Scanner Engine
   
2. SCAN COMPLETES
   Scanner → Webhook Service → POST ke registered webhooks
   Webhook → phantom_webhook_receiver.py (port 8080)
   
3. AGENT EXPLORATION
   Webhook Receiver → POST /agent-sessions → Create session
   Agent → POST /agent-sessions/{id}/log → Log exploration steps
   Agent → POST /agent-sessions/{id}/request-approval → Request risky action approval
   
4. APPROVAL WORKFLOW (via Telegram)
   Agent → Request approval → Telegram notification
   User → Reply Telegram → POST /telegram/webhook → POST /agent-sessions/{id}/approve
   
5. FINDING SUBMISSION
   Agent → POST /findings/ingest (dengan X-Agent-Secret header) → ShieldPDP
   
6. SESSION COMPLETE
   Agent → POST /agent-sessions/{id}/complete → Mark session done
   
7. REPORTING
   ShieldPDP combines auto + agent findings → Generate report
```

---

## 🚀 Alur Kerja Lengkap

### 1. Inisialisasi & Setup

```bash
# Setup environment
cd /root/NyuwunSewu-ShieldPDP-Project
cp .env.example .env

# Konfigurasi agent secret di .env:
# AGENT_SECRET=phantom-agent-secret-2026
# PHANTOM_WEBHOOK_PORT=8080
# PHANTOM_AGENT_SECRET=phantom-agent-secret-2026
# NYUWUNSEWU_URL=http://127.0.0.1:8000

# Optional: Telegram integration
# TELEGRAM_BOT_TOKEN=your-bot-token
# TELEGRAM_CHAT_ID=your-chat-id
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
python phantom_webhook_receiver.py
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

1. **Webhook trigger** → ShieldPDP POST ke `http://127.0.0.1:8080`
2. **Webhook receiver** parse payload, extract `scan_id` dan `target_url`
3. **Create agent session** → POST `/agent-sessions`
4. **Exploration steps** → Agent logging setiap aksi via `/agent-sessions/{id}/log`
5. **Approval workflow** → Jika perlu aksi berisiko, request via `/agent-sessions/{id}/request-approval`
6. **Submit findings** → POST `/findings/ingest` dengan `X-Agent-Secret` header
7. **Complete session** → POST `/agent-sessions/{id}/complete`

### 6. Review & Report

Temuan dari scanner otomatis dan agent digabungkan dalam report yang bisa diakses via:
- Dashboard UI: `http://localhost:5173`
- API: `GET /reports`
- Download: `GET /reports/{report_id}/download`

---

## 🔌 Komponen API untuk Agent

### Agent Sessions API

| Method | Path | Deskripsi | Auth |
|--------|------|-----------|------|
| `GET` | `/agent-sessions` | List semua agent sessions | Bearer Token (READ_DASHBOARD) |
| `GET` | `/agent-sessions/{id}` | Detail session spesifik | Bearer Token (READ_DASHBOARD) |
| `POST` | `/agent-sessions` | Buat session baru | Bearer Token (SCAN_CREATE) |
| `POST` | `/agent-sessions/{id}/log` | Tambah log entry | Bearer Token (READ_DASHBOARD) |
| `POST` | `/agent-sessions/{id}/request-approval` | Request approval aksi berisiko | Bearer Token (READ_DASHBOARD) |
| `POST` | `/agent-sessions/{id}/approve` | Approve/deny pending action | Bearer Token (SCAN_CREATE) |
| `POST` | `/agent-sessions/{id}/complete` | Mark session completed | Bearer Token (SCAN_CREATE) |

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
| `POST` | `/telegram/webhook` | Handle Telegram commands | Telegram webhook secret |

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
  "response_body": '{"account_id": 124, ...}',
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

#### Webhook Payload (dari ShieldPDP ke Agent)

```json
{
  "event": "scan.completed",
  "scan_id": "abc-123",
  "target_url": "https://target.example.com",
  "status": "completed",
  "findings_count": 5,
  "endpoints_count": 150,
  "stats": {
    "endpoints": 150,
    "findings": 5,
    "risk_score": 8.5
  },
  "finished_at": "2025-01-01T12:00:00Z"
}
```

**Headers:**
```
content-type: application/json
user-agent: NyuwunSewu-Webhook/1.0
x-nyuwunsewu-event: scan.completed
x-nyuwunsewu-signature: sha256=<hmac-signature>
```

---

## 🗄️ Model Data

### AgentSession

| Field | Type | Deskripsi |
|-------|------|-----------|
| `id` | String(36) | UUID primary key |
| `organization_id` | String(36) | FK ke organizations |
| `scan_id` | String(36) | FK ke scans (optional) |
| `agent_name` | String(120) | Nama agent (default: "phantom") |
| `target_url` | String(2048) | Target URL yang di-explore |
| `status` | String(32) | idle, exploring, pending_approval, approved, denied, completed, failed |
| `current_action` | String(512) | Aksi yang sedang dilakukan |
| `logs` | JSON | Array of log entries |
| `pending_action` | JSON | Detail aksi yang menunggu approval |
| `findings_count` | Integer | Jumlah finding yang disubmit |
| `started_at` | DateTime | Waktu mulai session |
| `completed_at` | DateTime | Waktu selesai session |
| `created_at` | DateTime | Auto-generated |
| `updated_at` | DateTime | Auto-generated |

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

## 🔒 Keamanan

### Authentication

| Komponen | Method | Deskripsi |
|----------|--------|-----------|
| **User API** | JWT Bearer Token | RBAC-based authentication |
| **Agent Ingest** | `X-Agent-Secret` header | Shared secret untuk agent authentication |
| **Webhook Signature** | HMAC-SHA256 | Payload signing via `x-nyuwunsewu-signature` header |

### Agent Secret Verification

```python
def _verify_agent_auth(x_agent_secret: str | None) -> bool:
    if not x_agent_secret:
        return False
    settings = get_settings()
    agent_secret = getattr(settings, "agent_secret", None)
    if agent_secret and hmac.compare_digest(x_agent_secret, agent_secret):
        return True
    # Fallback: check if it matches the app secret_key
    return hmac.compare_digest(x_agent_secret, settings.secret_key)
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

### Environment Variables

| Variable | Deskripsi | Default |
|----------|-----------|---------|
| `AGENT_SECRET` | Shared secret untuk agent auth | None |
| `PHANTOM_WEBHOOK_PORT` | Port untuk webhook receiver | 8080 |
| `PHANTOM_AGENT_SECRET` | Secret untuk agent finding submission | phantom-agent-secret-2026 |
| `NYUWUNSEWU_URL` | URL ShieldPDP API | http://127.0.0.1:8000 |
| `TELEGRAM_BOT_TOKEN` | Bot token untuk Telegram integration | None |
| `TELEGRAM_CHAT_ID` | Chat ID untuk notifikasi | None |

---

## 🚀 Deployment

### Docker Compose

```yaml
# docker-compose.yml
services:
  shieldpdp:
    build: .
    ports:
      - "8000:8000"
    environment:
      - DATABASE_URL=postgresql+asyncpg://user:pass@db:5432/shieldpdp
      - REDIS_URL=redis://redis:6379
      - AGENT_SECRET=${AGENT_SECRET}
      - TELEGRAM_BOT_TOKEN=${TELEGRAM_BOT_TOKEN}
      - TELEGRAM_CHAT_ID=${TELEGRAM_CHAT_ID}
    depends_on:
      - db
      - redis

  phantom-webhook:
    build: .
    command: python phantom_webhook_receiver.py
    ports:
      - "8080:8080"
    environment:
      - NYUWUNSEWU_URL=http://shieldpdp:8000
      - PHANTOM_WEBHOOK_PORT=8080
      - PHANTOM_AGENT_SECRET=${AGENT_SECRET}
    depends_on:
      - shieldpdp

  db:
    image: postgres:15
    environment:
      - POSTGRES_USER=user
      - POSTGRES_PASSWORD=pass
      - POSTGRES_DB=shieldpdp
    volumes:
      - pgdata:/var/lib/postgresql/data

  redis:
    image: redis:7

volumes:
  pgdata:
```

### Local Development

```bash
# Terminal 1: ShieldPDP
DATABASE_URL=sqlite+aiosqlite:///./nyuwunsewu_local.db
ALLOW_PRIVATE_TARGETS=true
python -m uvicorn app.main:app --host 127.0.0.1 --port 8001

# Terminal 2: Phantom Webhook Receiver
python phantom_webhook_receiver.py

# Terminal 3: Frontend (optional)
cd frontend
npm install
npm run dev
```

---

## 🔧 Troubleshooting

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

### Finding ingestion gagal

1. Verifikasi `AGENT_SECRET` sama di .env dan request header
2. Cek `scan_id` exists (jika disediakan)
3. Verifikasi struktur JSON payload
4. Cek server logs untuk error detail

### Telegram tidak mengirim notifikasi

1. Cek `TELEGRAM_BOT_TOKEN` dan `TELEGRAM_CHAT_ID` di .env
2. Verifikasi bot token valid
3. Cek chat ID benar dan bot sudah di-add ke grup
4. Cek logs untuk error dari Telegram API

---

## 📊 Diagram Sequence: Integrasi Lengkap

```
User                    ShieldPDP                    Hermes Agent              Telegram
 │                        │                             │                        │
 │  POST /scan/start      │                             │                        │
 ├───────────────────────>│                             │                        │
 │                        │  Scan in progress...        │                        │
 │                        │                             │                        │
 │                        │  Scan completed             │                        │
 │                        │  POST webhook               │                        │
 │                        ├────────────────────────────>│                        │
 │                        │                             │                        │
 │                        │  POST /agent-sessions       │                        │
 │                        │<────────────────────────────┤                        │
 │                        │                             │                        │
 │                        │  POST /agent-sessions/{id}/log                      │
 │                        │<────────────────────────────┤                        │
 │                        │                             │                        │
 │                        │  POST /agent-sessions/{id}/request-approval          │
 │                        │<────────────────────────────┤                        │
 │                        │                             │                        │
 │                        │  POST /telegram/webhook     │                        │
 │                        │                             │  approve/deny reply    │
 │                        │<────────────────────────────────────────────────────┤
 │                        │                             │                        │
 │                        │  POST /agent-sessions/{id}/approve                  │
 │                        │<────────────────────────────┤                        │
 │                        │                             │                        │
 │                        │  POST /findings/ingest      │                        │
 │                        │<────────────────────────────┤                        │
 │                        │                             │                        │
 │                        │  POST /agent-sessions/{id}/complete                 │
 │                        │<────────────────────────────┤                        │
 │                        │                             │                        │
 │  GET /reports          │                             │                        │
 │<───────────────────────┤                             │                        │
 │  (Combined findings)   │                             │                        │
```

---

## 🎯 Key Takeaways

1. **Hermes/Phantom agent** adalah komponen eksternal yang berkomunikasi dengan ShieldPDP via webhook dan API
2. **Webhook** adalah trigger utama - ketika scan selesai, ShieldPDP notifikasi agent
3. **Agent session** melifecycle lengkap eksplorasi agent dari start sampai complete
4. **Approval workflow** memungkinkan human-in-the-loop untuk aksi berisiko via Telegram
5. **Finding ingestion** menggunakan shared secret authentication (`X-Agent-Secret`)
6. **Combined reporting** menggabungkan temuan scanner otomatis dan agent untuk laporan komprehensif

---

*Dokumen ini dibuat untuk memetakan arsitektur integrasi Hermes agent dengan ShieldPDP. Referensi: `INTEGRATION.md`, `README.md`, source code.*
