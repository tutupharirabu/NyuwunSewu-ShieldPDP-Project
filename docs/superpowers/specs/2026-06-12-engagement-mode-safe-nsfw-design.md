# Engagement Mode: SAFE (internal) vs NSFW (external) — Design

**Date:** 2026-06-12
**Status:** Approved
**Branch:** `feat/engagement-mode-safe-nsfw`

## Problem

The Phantom agent's system prompt is a single hard-coded block built inline in
`_create_exploration_job()` (`phantom_webhook_receiver.py:259-338`). It frames
every engagement as an **owned learning lab** ("OWNED lab", "Private tailnet
host, non-public", "Authorization is on file here; do NOT ask for it again").

This is correct for internal pre-prod checks but wrong for authorized testing of
live, public-facing systems where authorization and scope come from an explicit
**Rules of Engagement (RoE)** document. We need two engagement profiles, chosen
when a scan is started:

1. **SAFE / internal** — pre-prod / owned systems. Current behavior.
2. **NSFW / external** — authorized testing / bug bounty of prod / public-facing
   systems, with an optional uploaded RoE document driving scope and limits.

## Goals

- Let the operator choose an engagement mode at scan-start (API + frontend).
- Externalize the two agent prompts behind clear, testable builders.
- Bind the external mode to an explicit RoE document (or a versioned conservative
  default when none is supplied).
- Preserve an audit trail: which mode, which RoE basis/version, applied per scan.

## Non-Goals

- No artificial throttling of the external agent's aggressiveness. The
  differences are **authorization framing**, **destructive boundary**, and
  **tooling/scope** — not timidity. (Per explicit user decision.)
- No change to the validation engines, recon, or scan scheduling mechanics.
- No multi-document RoE bundles in v1 (single document per scan).

## Approach (chosen)

Two pure prompt-builder functions sharing common sub-blocks (Option A from
brainstorming). Rejected: single conditional template (B, becomes spaghetti) and
external file templates (C, needless indirection in the receiver).

## Data Flow

```
scan/start (engagement_mode, roe_document_id?)
  └─ create_scan → Scan{engagement_mode, roe_document_id, roe_basis}
        └─ scan completes → _dispatch_webhooks payload
              {engagement_mode, roe_basis, roe_text|null, ...}
                └─ phantom_webhook_receiver._save_scan_context
                      └─ _create_exploration_job
                            ├─ internal → _build_internal_prompt(...)
                            └─ external → _build_external_prompt(..., roe_text)

RoE upload (separate, before scan-start):
POST /scan/roe (multipart, engagement_mode=external) → roe_documents row
  → returns {roe_document_id, filename, char_count, extraction_warning}
```

## Components

### 1. Mode enum & request schema
- `app/models/enums.py`: new `EngagementMode` enum — `internal` (default),
  `external`.
- `app/schemas/scan.py` `ScanStartRequest`: add
  - `engagement_mode: EngagementMode = EngagementMode.INTERNAL`
  - `roe_document_id: str | None = None`
- Validation: `roe_document_id` is only permitted when
  `engagement_mode == external`; supplying it for `internal` → HTTP 400.

### 2. RoE upload endpoint & storage
- New table `roe_documents`: `id`, `organization_id` (uploader's org),
  `filename`, `extracted_text` (Text), `char_count` (int),
  `extraction_warning` (bool, default false), `created_at`.
- New endpoint `POST /scan/roe` (multipart, requires `SCAN_CREATE`):
  - Form fields: `file` (`.pdf` / `.md` / `.txt`), `engagement_mode`.
  - **Rejects (400) when `engagement_mode != external`** — no orphan RoE for
    internal scans.
  - Limits: file ≤ 2 MB; extracted text ≤ 40 000 chars (truncate + flag).
  - Extraction: `pypdf` for PDF (new dependency); `.md` / `.txt` decoded directly.
  - **Extraction fallback:** if `extracted_text` is empty / very short relative
    to file size (heuristic: < 50 chars for a file > 10 KB → likely image-only
    or scanned PDF), set `extraction_warning = true`. Returned in the response so
    the operator knows the RoE was not read in full, instead of silently running
    the agent on an effectively empty RoE.
  - Returns `{roe_document_id, filename, char_count, extraction_warning}`.
- Housekeeping (follow-up, minor): RoE rows never linked to a scan can be pruned
  on a schedule.

### 3. Scan model & persistence
- `app/models/scan.py`: add columns
  - `engagement_mode` (String, default `"internal"`, not null)
  - `roe_document_id` (FK → `roe_documents.id`, nullable)
  - `roe_basis` (String, nullable) — `"document"` or `"default_roe_v1"`.
- Alembic migration for the new table + the three scan columns.
- `create_scan` validates `roe_document_id` belongs to the caller's org (IDOR
  guard, consistent with the existing scan_id→org scoping). Sets `roe_basis`:
  `"document"` when a RoE doc is attached, `"default_roe_v1"` for external with
  no document, `null` for internal.

### 4. Versioned conservative default RoE
- `DEFAULT_ROE_V1` constant (string): target-host only, non-destructive, no
  real-user-data exfiltration beyond minimal proof, respect policy
  forbidden/excluded paths and `robots`. Used when `engagement_mode == external`
  and no RoE document is supplied.
- The version id (`default_roe_v1`) is recorded in `Scan.roe_basis`, the webhook
  payload, and the job log so future revisions to the default leave older scans
  with an accurate record of what applied.

### 5. Webhook payload propagation
- `app/services/scan_reporting.py` `_dispatch_webhooks`: add `engagement_mode`,
  `roe_basis`, and `roe_text` (loaded from the RoeDocument; `null` for internal)
  to the payload.
- Log the `roe_text` size at dispatch. If it approaches the 40k cap, send the
  body gzip-compressed with a content-encoding flag (lightweight now, or marked
  as a follow-up if the receiver/infra — e.g. n8n — needs a tolerant decoder).

### 6. Prompt builders (receiver)
- `phantom_webhook_receiver.py`:
  - `_save_scan_context` carries `engagement_mode`, `roe_basis`, `roe_text`.
  - Refactor the inline prompt into:
    - `_build_internal_prompt(...)` — current framing (owned lab, on-file
      authorization, private tailnet, proceed immediately).
    - `_build_external_prompt(..., roe_text, roe_basis)` — authorized engagement
      on a **live / public-facing** system; scope and permission derived from the
      attached RoE (or `DEFAULT_ROE_V1`); extra hard-stops (no state-changing
      writes, no real-user-data exfil beyond minimal proof, honor RoE
      in/out-of-scope, stop on signs of impact). If the source RoE had
      `extraction_warning`, the prompt states "RoE extraction incomplete — verify
      scope manually."
    - Shared sub-blocks reused by both: `session_block`, SUBMISSION,
      `action_phase` vocabulary, base HARD RULES.
  - `_create_exploration_job` selects the builder by `engagement_mode`. Job name
    encodes the authorization basis:
    - `explore-int-<scan8>` (internal)
    - `explore-ext-roe-<scan8>` (external, uploaded document)
    - `explore-ext-default-<scan8>` (external, conservative default)

### 7. Frontend (`frontend/src/pages/scans.tsx`)
- Segmented control: **Internal (SAFE · pre-prod)** vs **External (NSFW ·
  public / bug-bounty)**, default Internal.
- When External: show an optional RoE file upload + hint "empty = conservative
  default RoE applies". On submit, upload the file first (`POST /scan/roe`) to get
  `roe_document_id`, then include it in `POST /scan/start`. Surface
  `extraction_warning` to the user if returned.
- Show a mode badge in the scan list and the agent-session detail so the mode is
  visible in the audit trail.

## Testing

- **Builders:** internal prompt contains "owned lab" framing; external prompt
  contains the RoE text + extra hard-stops; external-with-no-document embeds
  `DEFAULT_ROE_V1` and sets basis `default_roe_v1`.
- **Validation:** `internal + roe_document_id` → 400; external RoE belonging to
  another org → rejected.
- **RoE parsing:** `.pdf` / `.md` / `.txt` → text; oversize file → rejected;
  over-length text → truncated + flagged.
- **Image-only PDF** (empty `extracted_text`) → triggers `extraction_warning`
  (must NOT silently pass as a valid RoE).
- **roe_basis** recorded correctly: `document` vs `default_roe_v1` vs `null`
  (internal).

## Security Notes

This strengthens responsible use: the external mode **binds** the agent to an
explicit RoE (or a conservative versioned default) rather than loosening limits.
RoE org-scoping reuses the existing IDOR guard pattern. Uploaded RoE is retained
for compliance/audit. Default-RoE versioning preserves an accurate authorization
record per historical scan.
