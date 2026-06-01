# 🤖 Phantom Agent Integration Guide

Complete guide for integrating Hermes/Phantom agent with NyuwunSewu ShieldPDP.

## Quick Start

### 1. Start NyuwunSewu + Phantom

```bash
cd /root/NyuwunSewu-ShieldPDP-Project
chmod +x run_integration.sh
./run_integration.sh
```

### 2. Register Webhook in NyuwunSewu

```bash
# First, login to get auth token
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
1. NyuwunSewu POSTs to `http://127.0.0.1:8080`
2. Phantom receives notification
3. Phantom explores target as nasabah
4. Phantom finds & chains vulnerabilities
5. Phantom submits findings via `/findings/ingest`
6. NyuwunSewu includes findings in reports

## Architecture

```
┌─────────────────┐     scan.completed     ┌─────────────────┐
│  NyuwunSewu     │ ──────────────────────►│  Phantom Agent  │
│  (Scanner)      │                        │  (Explorer)     │
└────────┬────────┘                        └────────┬────────┘
         │                                          │
         │ GET /findings?scan_id=...                │ POST /findings/ingest
         │                                          │
         ▼                                          ▼
┌─────────────────┐                        ┌─────────────────┐
│   Database      │◄───────────────────────┤   Findings DB   │
│   (Findings)    │   Combined Results     │   (Agent Subm.) │
└─────────────────┘                        └─────────────────┘
```

## API Reference

### Webhook Management

```bash
# List webhooks
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/webhooks

# Create webhook
curl -X POST http://127.0.0.1:8000/webhooks \
  -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"Phantom","url":"http://127.0.0.1:8080","events":["scan.completed"]}'

# Delete webhook
curl -X DELETE http://127.0.0.1:8000/webhooks/{id} \
  -H "Authorization: Bearer $TOKEN"
```

### Agent Finding Ingestion

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
    "description": "...",
    "reasoning": ["Step 1", "Step 2"],
    "request_method": "GET",
    "request_url": "https://target/api/accounts/124",
    "response_status": 200,
    "response_body": "...",
    "remediation": "Implement ownership verification",
    "agent_name": "phantom",
    "exploit_chain": ["Login", "Access account", "Change ID", "Access other"]
  }'
```

## Configuration

### Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `AGENT_SECRET` | Shared secret for agent auth | None |
| `PHANTOM_WEBHOOK_PORT` | Port for webhook receiver | 8080 |
| `NYUWUNSEWU_URL` | NyuwunSewu API URL | http://127.0.0.1:8000 |

### Webhook Payload

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

## Security

- Agent authentication via `X-Agent-Secret` header
- HMAC timing-safe comparison prevents timing attacks
- Webhook payloads optionally signed with HMAC-SHA256
- Sensitive headers redacted before storage
- Agent findings tagged with `source: "agent"`

## Troubleshooting

### Server won't start
```bash
# Check if port is in use
lsof -i :8000

# Check logs
DATABASE_URL=sqlite+aiosqlite:///./nyuwunsewu.db ALLOW_PRIVATE_TARGETS=true \
  .venv/bin/python -m uvicorn app.main:app --host 127.0.0.1 --port 8000
```

### Webhook not received
1. Verify webhook is registered: `GET /webhooks`
2. Check webhook URL is reachable from NyuwunSewu
3. Verify events match: `["scan.completed"]`
4. Check webhook delivery status in subscription

### Finding ingestion fails
1. Verify `AGENT_SECRET` matches in both .env and request header
2. Check scan_id exists (if provided)
3. Verify JSON payload structure
4. Check server logs for errors
