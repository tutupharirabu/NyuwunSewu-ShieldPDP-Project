# Engagement Mode (SAFE / NSFW) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Let an operator choose an engagement mode at scan-start — `internal` (SAFE, pre-prod, current behavior) or `external` (NSFW, public/bug-bounty bound to an optional uploaded RoE document) — and route the Phantom agent to the matching system prompt.

**Architecture:** A new `EngagementMode` enum + `roe_documents` table flow from `POST /scan/start` (and a new `POST /scan/roe` upload) onto the `Scan` record, into the `scan.completed` webhook payload, and finally into one of two pure prompt builders in `phantom_webhook_receiver.py`. The external mode binds the agent to the uploaded RoE text or a versioned conservative default (`default_roe_v1`).

**Tech Stack:** Python 3.11, FastAPI, SQLAlchemy 2.0, Alembic, pypdf (new), pytest/pytest-asyncio, React + TypeScript (Vite).

**Spec:** `docs/superpowers/specs/2026-06-12-engagement-mode-safe-nsfw-design.md`

---

## File Structure

- `app/models/enums.py` — add `EngagementMode` enum.
- `app/models/roe.py` — **new** `RoeDocument` model.
- `app/models/scan.py` — add `engagement_mode`, `roe_document_id`, `roe_basis` columns.
- `app/models/__init__.py` — export `EngagementMode`, `RoeDocument`.
- `migrations/versions/0006_engagement_mode_roe.py` — **new** migration.
- `app/utils/roe_extract.py` — **new** RoE file→text extraction utility.
- `app/schemas/scan.py` — add request fields + `RoeUploadResponse`.
- `app/api/scans.py` — add `POST /scan/roe`; pass new fields into `create_scan`.
- `app/services/scan_crud.py` — persist mode/RoE, org-scope guard, set `roe_basis`.
- `app/services/scan_reporting.py` — add mode/RoE to webhook payload.
- `phantom_webhook_receiver.py` — `DEFAULT_ROE_V1`, two prompt builders, job naming, context propagation.
- `frontend/src/types/api.ts`, `frontend/src/lib/api.ts`, `frontend/src/pages/scan.tsx` — mode selector + RoE upload + badge.
- `requirements.txt` — add `pypdf`.
- Tests: `tests/test_roe_extract.py`, `tests/test_roe_upload.py`, `tests/test_scan_engagement_mode.py`, `tests/test_phantom_prompt_builders.py`, `tests/test_webhook_dispatch_engagement.py`.

---

## Task 1: EngagementMode enum + RoeDocument model + Scan columns

**Files:**
- Modify: `app/models/enums.py`
- Create: `app/models/roe.py`
- Modify: `app/models/scan.py:1-49`
- Modify: `app/models/__init__.py`
- Test: `tests/test_models_registry.py` (existing — extend)

- [ ] **Step 1: Write the failing test**

Append to `tests/test_models_registry.py`:

```python
def test_engagement_mode_and_roe_document_registered():
    from app.models import EngagementMode, RoeDocument, Scan

    assert EngagementMode.INTERNAL.value == "internal"
    assert EngagementMode.EXTERNAL.value == "external"
    # Scan gained the engagement columns
    assert "engagement_mode" in Scan.__table__.columns
    assert "roe_document_id" in Scan.__table__.columns
    assert "roe_basis" in Scan.__table__.columns
    # RoeDocument table shape
    cols = RoeDocument.__table__.columns
    for name in ("id", "organization_id", "filename", "extracted_text",
                 "char_count", "extraction_warning", "created_at"):
        assert name in cols
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models_registry.py::test_engagement_mode_and_roe_document_registered -v`
Expected: FAIL with `ImportError: cannot import name 'EngagementMode'`.

- [ ] **Step 3a: Add the enum** to `app/models/enums.py` (after the `SessionStatus` class, before `TimestampMixin`):

```python
class EngagementMode(str, Enum):
    """How an agent engagement is authorized.

    ``INTERNAL`` (SAFE): owned / pre-prod target, authorization on file.
    ``EXTERNAL`` (NSFW): authorized testing of a live / public-facing system,
    scope and limits derived from an attached Rules-of-Engagement document
    (or a versioned conservative default).
    """

    INTERNAL = "internal"
    EXTERNAL = "external"
```

- [ ] **Step 3b: Create** `app/models/roe.py`:

```python
from sqlalchemy import Boolean, ForeignKey, Integer, String, Text
from sqlalchemy.orm import Mapped, mapped_column

from app.database.base import Base
from app.models.enums import TimestampMixin, new_id


class RoeDocument(Base, TimestampMixin):
    """An uploaded Rules-of-Engagement document for an external engagement.

    Retained for compliance / audit even after the scan completes.
    """

    __tablename__ = "roe_documents"

    id: Mapped[str] = mapped_column(String(36), primary_key=True, default=new_id)
    organization_id: Mapped[str] = mapped_column(
        ForeignKey("organizations.id"), nullable=False, index=True
    )
    filename: Mapped[str] = mapped_column(String(512), nullable=False)
    extracted_text: Mapped[str] = mapped_column(Text, nullable=False, default="")
    char_count: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    extraction_warning: Mapped[bool] = mapped_column(
        Boolean, nullable=False, default=False
    )
```

- [ ] **Step 3c: Add columns** to `app/models/scan.py`. Add `EngagementMode` to the enums import on line 19, and add three columns after `error` (line 44):

```python
    engagement_mode: Mapped[str] = mapped_column(
        String(16), default=EngagementMode.INTERNAL.value, nullable=False
    )
    roe_document_id: Mapped[str | None] = mapped_column(
        ForeignKey("roe_documents.id"), nullable=True
    )
    roe_basis: Mapped[str | None] = mapped_column(String(32), nullable=True)
```

Line 19 becomes:
```python
from app.models.enums import EngagementMode, ScanStatus, TimestampMixin, new_id, now_utc
```

- [ ] **Step 3d: Export** in `app/models/__init__.py`: add `EngagementMode` to the `from app.models.enums import (...)` block, add `from app.models.roe import RoeDocument`, and add `"EngagementMode"` and `"RoeDocument"` to `__all__`.

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_models_registry.py::test_engagement_mode_and_roe_document_registered -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/models/enums.py app/models/roe.py app/models/scan.py app/models/__init__.py tests/test_models_registry.py
git commit -m "feat(models): EngagementMode enum, RoeDocument, scan engagement columns"
```

---

## Task 2: Alembic migration

**Files:**
- Create: `migrations/versions/0006_engagement_mode_roe.py`

- [ ] **Step 1: Write the migration**

```python
"""add roe_documents table and scan engagement columns

Revision ID: 0006
Revises: 0005
Create Date: 2026-06-12
"""

import sqlalchemy as sa
from alembic import op

revision = "0006"
down_revision = "0005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "roe_documents",
        sa.Column("id", sa.String(36), primary_key=True),
        sa.Column(
            "organization_id",
            sa.String(36),
            sa.ForeignKey("organizations.id"),
            nullable=False,
            index=True,
        ),
        sa.Column("filename", sa.String(512), nullable=False),
        sa.Column("extracted_text", sa.Text, nullable=False, server_default=""),
        sa.Column("char_count", sa.Integer, nullable=False, server_default=sa.text("0")),
        sa.Column(
            "extraction_warning",
            sa.Boolean,
            nullable=False,
            server_default=sa.text("0"),
        ),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.add_column(
        "scans",
        sa.Column(
            "engagement_mode",
            sa.String(16),
            nullable=False,
            server_default="internal",
        ),
    )
    op.add_column(
        "scans",
        sa.Column(
            "roe_document_id",
            sa.String(36),
            sa.ForeignKey("roe_documents.id"),
            nullable=True,
        ),
    )
    op.add_column("scans", sa.Column("roe_basis", sa.String(32), nullable=True))


def downgrade() -> None:
    op.drop_column("scans", "roe_basis")
    op.drop_column("scans", "roe_document_id")
    op.drop_column("scans", "engagement_mode")
    op.drop_table("roe_documents")
```

- [ ] **Step 2: Verify migration applies on a scratch DB**

Run:
```bash
DATABASE_URL="sqlite+aiosqlite:///./_mig_check.db" alembic upgrade head && \
DATABASE_URL="sqlite+aiosqlite:///./_mig_check.db" alembic downgrade -1 && \
rm -f _mig_check.db
```
Expected: both commands exit 0, no errors. (If `alembic` needs a sync URL, use `sqlite:///./_mig_check.db`.)

- [ ] **Step 3: Commit**

```bash
git add migrations/versions/0006_engagement_mode_roe.py
git commit -m "feat(db): migration for roe_documents and scan engagement columns"
```

---

## Task 3: RoE extraction utility + pypdf dependency

**Files:**
- Modify: `requirements.txt`
- Create: `app/utils/roe_extract.py`
- Test: `tests/test_roe_extract.py`

**Design:** pure function `extract_roe_text(filename, raw: bytes) -> ExtractedRoe`. Returns text, char_count, truncated flag, and `extraction_warning`. Limits: text capped at `ROE_MAX_CHARS = 40_000`. Warning heuristic: stripped text shorter than `ROE_MIN_CHARS = 50` while the file is larger than `ROE_IMAGE_PDF_BYTES = 10_240` (likely image-only/scanned PDF or empty doc).

- [ ] **Step 1: Add dependency** to `requirements.txt` (append):

```
pypdf>=5,<6
```

Run: `pip install "pypdf>=5,<6"`

- [ ] **Step 2: Write the failing test** — `tests/test_roe_extract.py`:

```python
import pytest

from app.utils.roe_extract import (
    ROE_MAX_CHARS,
    UnsupportedRoeFile,
    extract_roe_text,
)


def test_markdown_extracted_verbatim():
    result = extract_roe_text("roe.md", b"# Scope\nonly example.com\n")
    assert "only example.com" in result.text
    assert result.char_count == len(result.text)
    assert result.extraction_warning is False
    assert result.truncated is False


def test_text_over_limit_is_truncated_and_flagged():
    raw = ("a" * (ROE_MAX_CHARS + 500)).encode()
    result = extract_roe_text("roe.txt", raw)
    assert len(result.text) == ROE_MAX_CHARS
    assert result.truncated is True


def test_empty_large_pdf_triggers_extraction_warning():
    # An image-only / unparseable PDF: > 10 KB of bytes, no extractable text.
    fake_pdf = b"%PDF-1.4\n" + b"0" * 11000
    result = extract_roe_text("scope.pdf", fake_pdf)
    assert result.text.strip() == ""
    assert result.extraction_warning is True


def test_unsupported_extension_rejected():
    with pytest.raises(UnsupportedRoeFile):
        extract_roe_text("scope.docx", b"...")
```

- [ ] **Step 3: Run test to verify it fails**

Run: `pytest tests/test_roe_extract.py -v`
Expected: FAIL with `ModuleNotFoundError: No module named 'app.utils.roe_extract'`.

- [ ] **Step 4: Implement** `app/utils/roe_extract.py`:

```python
"""Extract plain text from an uploaded Rules-of-Engagement document.

Supports .md / .txt (decoded directly) and .pdf (via pypdf). Image-only or
unparseable PDFs yield an ``extraction_warning`` so the operator is not misled
into running the agent on an effectively empty RoE.
"""

from __future__ import annotations

import io
from dataclasses import dataclass

ROE_MAX_CHARS = 40_000
ROE_MIN_CHARS = 50
ROE_IMAGE_PDF_BYTES = 10_240


class UnsupportedRoeFile(ValueError):
    """Raised when the uploaded RoE file extension is not supported."""


@dataclass
class ExtractedRoe:
    text: str
    char_count: int
    truncated: bool
    extraction_warning: bool


def _extract_pdf(raw: bytes) -> str:
    from pypdf import PdfReader

    try:
        reader = PdfReader(io.BytesIO(raw))
        parts = [(page.extract_text() or "") for page in reader.pages]
        return "\n".join(parts)
    except Exception:
        # Corrupt / encrypted / image-only: treat as no extractable text.
        return ""


def extract_roe_text(filename: str, raw: bytes) -> ExtractedRoe:
    lower = filename.lower()
    if lower.endswith((".md", ".txt")):
        text = raw.decode("utf-8", errors="replace")
    elif lower.endswith(".pdf"):
        text = _extract_pdf(raw)
    else:
        raise UnsupportedRoeFile(
            "Unsupported RoE file type; use .pdf, .md, or .txt"
        )

    truncated = len(text) > ROE_MAX_CHARS
    if truncated:
        text = text[:ROE_MAX_CHARS]

    warning = len(text.strip()) < ROE_MIN_CHARS and len(raw) > ROE_IMAGE_PDF_BYTES
    return ExtractedRoe(
        text=text,
        char_count=len(text),
        truncated=truncated,
        extraction_warning=warning,
    )
```

- [ ] **Step 5: Run test to verify it passes**

Run: `pytest tests/test_roe_extract.py -v`
Expected: PASS (4 passed).

- [ ] **Step 6: Commit**

```bash
git add requirements.txt app/utils/roe_extract.py tests/test_roe_extract.py
git commit -m "feat(roe): RoE file text extraction with image-only PDF warning"
```

---

## Task 4: RoE upload endpoint

**Files:**
- Modify: `app/schemas/scan.py` (add `RoeUploadResponse`)
- Modify: `app/api/scans.py`
- Test: `tests/test_roe_upload.py`

**Design:** `POST /scan/roe` — multipart, `SCAN_CREATE` permission. Form fields: `file` (UploadFile), `engagement_mode` (str). Rejects when `engagement_mode != "external"` (400). Rejects files > `ROE_MAX_UPLOAD_BYTES = 2 * 1024 * 1024` (413). Persists a `RoeDocument` scoped to the caller's org and returns its id + metadata.

- [ ] **Step 1: Write the failing test** — `tests/test_roe_upload.py`:

```python
import io

import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


async def _auth_headers(client: AsyncClient) -> dict:
    resp = await client.post(
        "/auth/login",
        json={
            "email": "admin@nyuwunsewu.local",
            "password": "ChangeMe123!",
            "organization_slug": "default-organization",
        },
    )
    assert resp.status_code == 200, resp.text
    return {"authorization": f"Bearer {resp.json()['access_token']}"}


@pytest.mark.asyncio
async def test_roe_upload_external_returns_document_id():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = await _auth_headers(client)
        files = {"file": ("scope.md", io.BytesIO(b"# Scope\nonly api.example.com\n"), "text/markdown")}
        resp = await client.post(
            "/scan/roe",
            headers=headers,
            files=files,
            data={"engagement_mode": "external"},
        )
        assert resp.status_code == 200, resp.text
        body = resp.json()
        assert body["roe_document_id"]
        assert body["filename"] == "scope.md"
        assert body["char_count"] > 0
        assert body["extraction_warning"] is False


@pytest.mark.asyncio
async def test_roe_upload_rejected_for_internal_mode():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = await _auth_headers(client)
        files = {"file": ("scope.md", io.BytesIO(b"x"), "text/markdown")}
        resp = await client.post(
            "/scan/roe",
            headers=headers,
            files=files,
            data={"engagement_mode": "internal"},
        )
        assert resp.status_code == 400
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_roe_upload.py -v`
Expected: FAIL with 404 (route not defined).

- [ ] **Step 3a: Add response schema** to `app/schemas/scan.py` (append):

```python
class RoeUploadResponse(BaseModel):
    roe_document_id: str
    filename: str
    char_count: int
    extraction_warning: bool
```

- [ ] **Step 3b: Add the endpoint** to `app/api/scans.py`. Add imports at the top:

```python
from fastapi import File, Form, UploadFile

from app.models import EngagementMode, RoeDocument
from app.schemas.scan import RoeUploadResponse
from app.utils.roe_extract import UnsupportedRoeFile, extract_roe_text

ROE_MAX_UPLOAD_BYTES = 2 * 1024 * 1024
```

Add the route (after `start_scan`):

```python
@router.post("/scan/roe", response_model=RoeUploadResponse)
async def upload_roe(
    file: UploadFile = File(...),
    engagement_mode: str = Form(...),
    user: User = Depends(require_permission(Permission.SCAN_CREATE)),
    session: AsyncSession = Depends(get_session),
) -> RoeUploadResponse:
    if engagement_mode != EngagementMode.EXTERNAL.value:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="RoE documents apply only to external engagements",
        )
    if not user.organization_id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="User must belong to an organization",
        )
    raw = await file.read()
    if len(raw) > ROE_MAX_UPLOAD_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail="RoE file exceeds 2 MB limit",
        )
    try:
        extracted = extract_roe_text(file.filename or "roe", raw)
    except UnsupportedRoeFile as exc:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST, detail=str(exc)
        ) from exc

    doc = RoeDocument(
        organization_id=user.organization_id,
        filename=file.filename or "roe",
        extracted_text=extracted.text,
        char_count=extracted.char_count,
        extraction_warning=extracted.extraction_warning,
    )
    session.add(doc)
    await session.commit()
    return RoeUploadResponse(
        roe_document_id=doc.id,
        filename=doc.filename,
        char_count=doc.char_count,
        extraction_warning=doc.extraction_warning,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_roe_upload.py -v`
Expected: PASS (2 passed). If login fails, confirm `python-multipart` is installed (it is, per requirements) and the bootstrap admin env vars in `tests/conftest.py` are set.

- [ ] **Step 5: Commit**

```bash
git add app/schemas/scan.py app/api/scans.py tests/test_roe_upload.py
git commit -m "feat(api): POST /scan/roe upload endpoint (external-only, org-scoped)"
```

---

## Task 5: ScanStartRequest fields + persistence + org-scope guard

**Files:**
- Modify: `app/schemas/scan.py:59-79`
- Modify: `app/services/scan_crud.py:24-73`
- Modify: `app/api/scans.py:36-48`
- Test: `tests/test_scan_engagement_mode.py`

**Design:** `ScanStartRequest` gains `engagement_mode` (enum, default internal) and `roe_document_id` (optional). `create_scan` validates: internal must not carry a RoE; external RoE id must exist **and** belong to the caller's org (IDOR guard); sets `roe_basis` = `"document"` (external + doc), `"default_roe_v1"` (external + no doc), or `None` (internal).

- [ ] **Step 1: Write the failing test** — `tests/test_scan_engagement_mode.py`:

```python
import pytest
from httpx import ASGITransport, AsyncClient

from app.main import app


async def _auth_headers(client):
    resp = await client.post(
        "/auth/login",
        json={
            "email": "admin@nyuwunsewu.local",
            "password": "ChangeMe123!",
            "organization_slug": "default-organization",
        },
    )
    return {"authorization": f"Bearer {resp.json()['access_token']}"}


def _base_payload(**over):
    payload = {
        "target_url": "http://127.0.0.1:9",
        "project_name": "Engagement Mode Test",
        "allowed_domains": [],
        "policy": {"name": "p", "max_requests_per_second": 1},
    }
    payload.update(over)
    return payload


@pytest.mark.asyncio
async def test_default_mode_is_internal():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = await _auth_headers(client)
        resp = await client.post("/scan/start", headers=headers, json=_base_payload())
        assert resp.status_code == 200, resp.text


@pytest.mark.asyncio
async def test_internal_with_roe_document_rejected():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = await _auth_headers(client)
        resp = await client.post(
            "/scan/start",
            headers=headers,
            json=_base_payload(engagement_mode="internal", roe_document_id="abc"),
        )
        assert resp.status_code == 400


@pytest.mark.asyncio
async def test_external_with_unknown_roe_document_rejected():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = await _auth_headers(client)
        resp = await client.post(
            "/scan/start",
            headers=headers,
            json=_base_payload(
                engagement_mode="external", roe_document_id="does-not-exist"
            ),
        )
        assert resp.status_code == 400


@pytest.mark.asyncio
async def test_external_no_document_sets_default_basis():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        headers = await _auth_headers(client)
        resp = await client.post(
            "/scan/start",
            headers=headers,
            json=_base_payload(engagement_mode="external"),
        )
        assert resp.status_code == 200, resp.text
        # verify persisted basis via the scan detail endpoint
        scan_id = resp.json()["scan_id"]
        detail = await client.get(f"/scans/{scan_id}", headers=headers)
        assert detail.json()["engagement_mode"] == "external"
        assert detail.json()["roe_basis"] == "default_roe_v1"
```

> NOTE: the last assertion requires `engagement_mode` and `roe_basis` in the scan-detail response. If `GET /scans/{id}` (in `app/api/...`) uses a Pydantic `ScanDetail` schema, add both fields there. If it serializes the ORM dict directly, no change is needed. Inspect `grep -rn "ScanDetail\|scans/{" app/api` before implementing and add the two fields to whatever response model that route uses.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_scan_engagement_mode.py -v`
Expected: FAIL — `test_internal_with_roe_document_rejected` returns 200 (no validation yet).

- [ ] **Step 3a: Schema** — add to `ScanStartRequest` in `app/schemas/scan.py` (import `EngagementMode` at top: `from app.models.enums import EngagementMode`):

```python
    engagement_mode: EngagementMode = EngagementMode.INTERNAL
    roe_document_id: str | None = None
```

- [ ] **Step 3b: create_scan** — extend the signature and body in `app/services/scan_crud.py`. Add params to `create_scan`:

```python
        engagement_mode: str = "internal",
        roe_document_id: str | None = None,
```

Add this block immediately after the `if not user.organization_id:` guard (line ~36), before `_resolve_project`:

```python
        roe_basis: str | None = None
        if engagement_mode == "internal":
            if roe_document_id:
                raise ValueError("RoE documents apply only to external engagements")
        elif engagement_mode == "external":
            if roe_document_id:
                from app.models import RoeDocument

                doc = await self.session.get(RoeDocument, roe_document_id)
                if doc is None or doc.organization_id != user.organization_id:
                    raise ValueError("RoE document not found in organization scope")
                roe_basis = "document"
            else:
                roe_basis = "default_roe_v1"
        else:
            raise ValueError(f"Unknown engagement_mode: {engagement_mode}")
```

Then set the three fields on the `Scan(...)` constructor:

```python
            engagement_mode=engagement_mode,
            roe_document_id=roe_document_id if engagement_mode == "external" else None,
            roe_basis=roe_basis,
```

- [ ] **Step 3c: Wire the API** — in `app/api/scans.py`, pass the new fields into the `service.create_scan(...)` call:

```python
            engagement_mode=payload.engagement_mode.value,
            roe_document_id=payload.roe_document_id,
```

- [ ] **Step 3d:** Apply the scan-detail NOTE from Step 1 (add `engagement_mode` and `roe_basis` to the scan-detail response model used by `GET /scans/{id}`).

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_scan_engagement_mode.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add app/schemas/scan.py app/services/scan_crud.py app/api/scans.py tests/test_scan_engagement_mode.py
git commit -m "feat(scan): engagement_mode + RoE on scan-start with org-scope guard"
```

---

## Task 6: Webhook payload propagation

**Files:**
- Modify: `app/services/scan_reporting.py:215-234`
- Test: `tests/test_webhook_dispatch_engagement.py`

**Design:** the `scan.completed` / `scan.failed` payload gains `engagement_mode`, `roe_basis`, and `roe_text` (loaded from the linked `RoeDocument`, else `None`). Log the `roe_text` length at dispatch.

- [ ] **Step 1: Write the failing test** — `tests/test_webhook_dispatch_engagement.py`:

```python
import pytest

from app.models import RoeDocument, Scan
from app.services.scan_reporting import ScanReportingMixin  # adjust if class differs


@pytest.mark.asyncio
async def test_payload_includes_engagement_fields(monkeypatch):
    """_build_webhook_payload returns engagement_mode, roe_basis, roe_text."""
    # This test calls the payload-builder directly; see Step 3 which extracts
    # payload construction into a helper `_build_webhook_payload(scan)`.
    from tests._engagement_helpers import build_scan_with_roe  # provided in Step 1b

    scan, expected_text = await build_scan_with_roe()
    reporter = build_scan_with_roe.reporter
    payload = await reporter._build_webhook_payload(scan, "scan.completed")
    assert payload["engagement_mode"] == "external"
    assert payload["roe_basis"] == "document"
    assert payload["roe_text"] == expected_text
```

> If wiring a full DB-backed `Scan` + `RoeDocument` + reporter in a unit test is too heavy, replace this with a lighter test that constructs an in-memory `Scan` object (no DB) with `engagement_mode="internal"`, `roe_document_id=None` and asserts `_build_webhook_payload` yields `engagement_mode="internal"`, `roe_basis=None`, `roe_text=None`. Prefer the lighter test; delete the helper note. The REQUIRED behavior to lock in: payload carries the three new keys, and `roe_text` is `None` when there is no document.

- [ ] **Step 1b (only if using the heavy variant):** skip — prefer the lightweight in-memory variant described above. Do not create `tests/_engagement_helpers.py`.

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_webhook_dispatch_engagement.py -v`
Expected: FAIL — `_build_webhook_payload` does not exist yet.

- [ ] **Step 3: Refactor + implement** in `app/services/scan_reporting.py`. Extract payload construction from `_dispatch_webhooks` into a helper and add the fields. Replace the inline `payload = {...}` (lines ~221-234) with a call, and add the helper:

```python
    async def _build_webhook_payload(self, scan: Scan, event: str) -> dict:
        scan_stats = scan.stats or {}
        target = (
            await self.session.get(Target, scan.target_id)
            if scan.target_id
            else None
        )
        roe_text = None
        if scan.roe_document_id:
            from app.models import RoeDocument

            doc = await self.session.get(RoeDocument, scan.roe_document_id)
            roe_text = doc.extracted_text if doc else None
        if roe_text is not None:
            import logging

            logging.getLogger(__name__).info(
                "Webhook scan %s carries roe_text of %d chars", scan.id, len(roe_text)
            )
        return {
            "event": event,
            "scan_id": scan.id,
            "target_url": target.base_url if target else None,
            "project_id": scan.project_id,
            "status": scan.status,
            "stats": scan_stats,
            "error": scan.error,
            "findings_count": scan_stats.get("findings", 0),
            "endpoints_count": scan_stats.get("endpoints", 0),
            "engagement_mode": scan.engagement_mode,
            "roe_basis": scan.roe_basis,
            "roe_text": roe_text,
            "finished_at": scan.finished_at.isoformat()
            if scan.finished_at
            else None,
        }
```

In `_dispatch_webhooks`, replace the inline payload dict with:

```python
            payload = await self._build_webhook_payload(scan, event)
```

(Keep the surrounding subscription-loop logic unchanged.)

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_webhook_dispatch_engagement.py -v`
Expected: PASS.

- [ ] **Step 5: Run the existing webhook test for regressions**

Run: `pytest tests/test_webhook_dispatch_failure.py -v`
Expected: PASS (unchanged behavior).

- [ ] **Step 6: Commit**

```bash
git add app/services/scan_reporting.py tests/test_webhook_dispatch_engagement.py
git commit -m "feat(webhook): propagate engagement_mode, roe_basis, roe_text"
```

---

## Task 7: Receiver prompt builders + DEFAULT_ROE_V1 + job naming

**Files:**
- Modify: `phantom_webhook_receiver.py` (refactor `_create_exploration_job`, lines ~203-371; `_save_scan_context`, lines ~141-157)
- Test: `tests/test_phantom_prompt_builders.py`

**Design:** extract the shared sub-blocks and split into `_build_internal_prompt(...)` and `_build_external_prompt(...)`. Add `DEFAULT_ROE_V1`. `_create_exploration_job` accepts `engagement_mode`, `roe_text`, `roe_basis`, `extraction_warning`, selects the builder, and names the job per authorization basis.

- [ ] **Step 1: Write the failing test** — `tests/test_phantom_prompt_builders.py`:

```python
import phantom_webhook_receiver as pwr


def test_internal_prompt_has_owned_lab_framing():
    prompt = pwr._build_internal_prompt(
        scan_id="s1", target_url="http://t", context_path="/tmp/ctx.json",
        session_block="",
    )
    assert "OWNED lab" in prompt
    assert "non-public" in prompt.lower() or "tailnet" in prompt.lower()


def test_external_prompt_embeds_supplied_roe():
    prompt = pwr._build_external_prompt(
        scan_id="s1", target_url="http://t", context_path="/tmp/ctx.json",
        session_block="", roe_text="IN SCOPE: api.example.com ONLY",
        roe_basis="document", extraction_warning=False,
    )
    assert "IN SCOPE: api.example.com ONLY" in prompt
    assert "public-facing" in prompt.lower()
    assert "OWNED lab" not in prompt


def test_external_prompt_uses_default_roe_when_absent():
    prompt = pwr._build_external_prompt(
        scan_id="s1", target_url="http://t", context_path="/tmp/ctx.json",
        session_block="", roe_text=None, roe_basis="default_roe_v1",
        extraction_warning=False,
    )
    assert pwr.DEFAULT_ROE_V1.strip()[:30] in prompt
    assert "default_roe_v1" in prompt


def test_external_prompt_flags_extraction_warning():
    prompt = pwr._build_external_prompt(
        scan_id="s1", target_url="http://t", context_path="/tmp/ctx.json",
        session_block="", roe_text="", roe_basis="document",
        extraction_warning=True,
    )
    assert "extraction incomplete" in prompt.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_phantom_prompt_builders.py -v`
Expected: FAIL — `_build_internal_prompt` not defined.

- [ ] **Step 3a: Add the default RoE constant** near the top of `phantom_webhook_receiver.py` (after the imports / config block):

```python
DEFAULT_ROE_V1 = """DEFAULT conservative RoE (default_roe_v1) - no document supplied.
- IN SCOPE: the target host ONLY ({target_url}). No other hosts, subdomains, or
  third-party services.
- Non-destructive ONLY: no state-changing writes, no deletion, no DoS, no
  brute-force floods.
- No real-user-data exfiltration beyond the minimum needed to prove a finding.
- Respect the scan policy's forbidden/excluded paths and robots directives.
- Stop immediately and report (status=refused) if any action risks impacting
  real users or production data."""
```

- [ ] **Step 3b: Extract the two builders.** Move the existing big `prompt = f"""PHANTOM ENGAGEMENT ..."""` body into `_build_internal_prompt`, and write `_build_external_prompt` reusing the shared SUBMISSION + HARD RULES + `session_block`. Add both functions above `_create_exploration_job`:

```python
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

== AVAILABLE TOOLS (use ONLY these - actually installed on this host) ==
PRIMARY ENGINE - use for auth / session / IDOR / authz / business-logic:
  curl, wget, and python3 with: requests, aiohttp, PyJWT, websockets, cryptography.
  For access-control bugs (IDOR/BOLA, authz), scripted requests with swapped
  tokens/IDs is your STRONGEST tool - prefer it over scanners.
SCANNERS / DISCOVERY:
  nuclei, nikto, sqlmap (confirm SQLi only - do NOT --dump real data),
  ffuf + gobuster, httpx, wafw00f, nmap, mitmproxy/mitmdump (only if needed).

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

== AVAILABLE TOOLS (use ONLY these - actually installed on this host) ==
PRIMARY: curl, wget, python3 (requests, aiohttp, PyJWT, websockets, cryptography).
  Scripted requests with swapped tokens/IDs are your STRONGEST tool for IDOR/authz.
SCANNERS: nuclei, nikto, sqlmap (confirm only - never --dump real data),
  ffuf + gobuster, httpx, wafw00f, nmap, mitmproxy (only if RoE permits).

== BUDGET DISCIPLINE ==
- Recon is PARTIALLY DONE: read {context_path} first (endpoint map). Do NOT re-crawl.
- Compressed recon (~5 turns), then validate. Submit each finding when confirmed.

== PRIORITIZED VALIDATION (within RoE scope) ==
1. BOLA / IDOR  2. AUTHZ / privilege escalation  3. AUTH / session / JWT
4. INJECTION (confirm only)  5. INFO DISCLOSURE / MISCONFIG
{_shared_blocks(scan_id, target_url, session_block)}"""
```

- [ ] **Step 3c: Wire builder selection** into `_create_exploration_job`. Change its signature to accept the new context and replace the inline `prompt = f"""PHANTOM ENGAGEMENT ..."""` with builder selection + job-name basis:

```python
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
    # ... keep the existing `session_block = ...` construction ...

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
        "cron", "create", "1m", prompt,
        "--repeat", "1",
        "--name", f"explore-{job_suffix}-{scan_id[:8]}",
        "--deliver", "origin",
        timeout=60,
    )
    # ... keep the existing result-parsing / return logic ...
```

- [ ] **Step 3d: Propagate context** — in `_save_scan_context` add `engagement_mode`, `roe_basis`, `roe_text`, `extraction_warning` from `payload` into the saved `context` dict, and update the caller (`_trigger_exploration`) to read them from the webhook payload and pass them into `_create_exploration_job`. (Inspect `_trigger_exploration` around lines 372-450 and thread the four values through; default to `internal` / `None` / `False` when absent so older payloads still work.)

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_phantom_prompt_builders.py -v`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add phantom_webhook_receiver.py tests/test_phantom_prompt_builders.py
git commit -m "feat(phantom): split internal/external prompt builders, versioned default RoE"
```

---

## Task 8: Frontend — mode selector, RoE upload, badge

**Files:**
- Modify: `frontend/src/types/api.ts:209` (ScanStartPayload)
- Modify: `frontend/src/lib/api.ts` (add `uploadRoe`, extend `startScan` payload)
- Modify: `frontend/src/pages/scan.tsx`
- Modify: `frontend/src/pages/scan-detail.tsx` (mode badge — optional, mechanical)

**Design:** add `engagement_mode` + `roe_document_id` to the payload type; a segmented Internal/External control defaulting to Internal; when External, an optional file input that uploads via `POST /scan/roe` and stores the returned id; surface `extraction_warning`.

- [ ] **Step 1: Extend the payload type** in `frontend/src/types/api.ts` — add to `ScanStartPayload`:

```typescript
  engagement_mode?: "internal" | "external";
  roe_document_id?: string | null;
```

- [ ] **Step 2: Add the upload call** in `frontend/src/lib/api.ts` (inside the `api` object). Because this is multipart, build a `FormData` and let the browser set the content-type (the shared `request()` helper forces JSON, so call `fetch` directly here):

```typescript
  uploadRoe: async (file: File): Promise<{
    roe_document_id: string;
    filename: string;
    char_count: number;
    extraction_warning: boolean;
  }> => {
    const token = getToken();
    const form = new FormData();
    form.append("file", file);
    form.append("engagement_mode", "external");
    const resp = await fetch(`${API_BASE}/scan/roe`, {
      method: "POST",
      headers: token ? { authorization: `Bearer ${token}` } : undefined,
      body: form,
    });
    if (!resp.ok) {
      throw new ApiError((await resp.text()) || resp.statusText, resp.status);
    }
    return resp.json();
  },
```

(`getToken`, `API_BASE`, and `ApiError` are already defined in this module.)

- [ ] **Step 3: Add UI state + control** in `frontend/src/pages/scan.tsx`. Add state near the other `useState` calls (line ~56):

```typescript
  const [engagementMode, setEngagementMode] = useState<"internal" | "external">("internal");
  const [roeFile, setRoeFile] = useState<File | null>(null);
  const [roeWarning, setRoeWarning] = useState<string | null>(null);
```

In `submit()` (before building `payload`), upload the RoE when external + file present:

```typescript
      let roeDocumentId: string | null = null;
      if (engagementMode === "external" && roeFile) {
        const up = await api.uploadRoe(roeFile);
        roeDocumentId = up.roe_document_id;
        setRoeWarning(
          up.extraction_warning
            ? "RoE text could not be fully extracted (image-only PDF?). The agent will be warned to verify scope manually."
            : null,
        );
      }
```

Add to the `payload` object:

```typescript
        engagement_mode: engagementMode,
        roe_document_id: roeDocumentId,
```

Add the control inside the first `<Card>` (after the Target URL block, around line 147). Use the existing `Select` component already imported in this file:

```tsx
          <div className="space-y-2">
            <Label htmlFor="mode">Engagement mode</Label>
            <Select
              id="mode"
              value={engagementMode}
              onChange={(e) =>
                setEngagementMode(e.target.value as "internal" | "external")
              }
            >
              <option value="internal">Internal — SAFE (pre-prod / owned)</option>
              <option value="external">External — NSFW (public / bug-bounty)</option>
            </Select>
            {engagementMode === "external" && (
              <div className="space-y-1 pt-2">
                <Label htmlFor="roe">Rules of Engagement (optional)</Label>
                <Input
                  id="roe"
                  type="file"
                  accept=".pdf,.md,.txt"
                  onChange={(e) => setRoeFile(e.target.files?.[0] ?? null)}
                />
                <p className="text-xs text-muted-foreground">
                  Empty = conservative default RoE (default_roe_v1) applies.
                </p>
                {roeWarning && (
                  <p className="text-xs text-amber-600">{roeWarning}</p>
                )}
              </div>
            )}
          </div>
```

- [ ] **Step 4: Type-check the frontend**

Run: `cd frontend && npm run build` (or `npx tsc --noEmit`)
Expected: build/type-check succeeds with no errors in `scan.tsx`, `api.ts`, `types/api.ts`.

- [ ] **Step 5: Manual smoke (optional but recommended)**

Start backend + frontend, open Create Scan, switch to External, confirm the file input appears and a `.md` upload then scan-start succeeds (network tab shows `POST /scan/roe` then `POST /scan/start` with `engagement_mode: "external"`).

- [ ] **Step 6: Commit**

```bash
git add frontend/src/types/api.ts frontend/src/lib/api.ts frontend/src/pages/scan.tsx
git commit -m "feat(ui): engagement-mode selector and RoE upload on scan-start"
```

---

## Task 9: Full regression + finish

- [ ] **Step 1: Run the whole backend suite**

Run: `pytest -q`
Expected: all tests pass (new + existing). Investigate any failure before proceeding.

- [ ] **Step 2: Confirm migration head is linear**

Run: `alembic heads`
Expected: a single head `0006`.

- [ ] **Step 3: Final commit (if any stragglers) and summary**

```bash
git add -A && git commit -m "test: engagement-mode end-to-end regression" || echo "nothing to commit"
```

---

## Self-Review Notes

- **Spec coverage:** enum/schema (T1,T5) · RoE upload + extraction_warning (T3,T4) · scan persistence + org-scope guard (T5) · versioned default RoE (T3 const lives in receiver T7; basis recorded T5) · webhook propagation (T6) · two builders + job naming (T7) · frontend selector + badge (T8). All spec sections mapped.
- **Type consistency:** `roe_basis` values `"document"` / `"default_roe_v1"` / `None` used identically in T5, T6, T7. `engagement_mode` string `"internal"`/`"external"` consistent across enum (T1), schema (T5), service (T5), webhook (T6), builder selection (T7), frontend (T8). Builder signatures in T7 tests match T7 implementation.
- **Known inspection points (not placeholders):** T5 Step 3d and T7 Step 3d require reading an adjacent function (`GET /scans/{id}` response model; `_trigger_exploration`) and threading fields through — exact code shown for everything else.
