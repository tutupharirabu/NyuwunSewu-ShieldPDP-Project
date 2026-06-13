# PDP Breach Notification Automation — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Otomatiskan alur breach notification Pasal 46 UU PDP — assess otomatis setelah scan, scheduler SLA 3×24 jam, dan frontend untuk melihat/menyalin/mengunduh dua varian surat.

**Architecture:** Hook di akhir `ScanRunner.run_scan` memanggil `persist_breach` (ekstraksi dari endpoint API) untuk membuat record `BreachNotification` + kirim Telegram alert internal. Sebuah asyncio task di FastAPI `lifespan` menjalankan `run_sla_monitor` yang mengingatkan berjenjang (48/24/6/1 jam) memakai fungsi murni `due_sla_alerts`. Frontend menambah panel di `compliance.tsx`.

**Tech Stack:** FastAPI, SQLAlchemy async, Alembic, pytest (asyncio_mode=auto), React 18 + Vite + TS + Tailwind + Radix.

Spec: `docs/superpowers/specs/2026-06-13-pdp-breach-automation-design.md`

---

## File Structure

- `app/core/config.py` — 4 setting baru.
- `app/models/agent.py` — 2 kolom baru di `BreachNotification`.
- `alembic/versions/<rev>_breach_sla_columns.py` — migrasi (baru).
- `app/services/breach_notification.py` — `generate_notification_text` (pakai setting), `generate_subject_notification_text` (baru), `persist_breach` (baru).
- `app/services/sla_monitor.py` — baru: `due_sla_alerts` + `run_sla_monitor` + `_tick`.
- `app/services/scan_service.py` — hook auto-trigger.
- `app/api/compliance.py` — `breach-create` pakai `persist_breach`; detail kembalikan kedua varian.
- `app/main.py` — start/stop SLA monitor.
- `frontend/src/lib/api.ts` — 4 method breach.
- `frontend/src/pages/compliance.tsx` — `BreachNotificationsPanel`.
- Tests: `tests/test_sla_monitor.py` (baru), `tests/test_breach_automation.py` (baru).

---

## Task 1: Config settings

**Files:**
- Modify: `app/core/config.py` (di dalam `class Settings`, dekat blok telegram baris ~44-48)

- [ ] **Step 1: Tambah setting**

Tambahkan setelah field telegram:

```python
    # Breach SLA automation (Pasal 46 UU PDP)
    enable_sla_monitor: bool = True
    sla_monitor_interval_seconds: int = 900  # 15 menit
    sla_alert_thresholds: list[int] = [48, 24, 6, 1]  # jam tersisa
    pdp_authority_name: str = "Kementerian Komunikasi dan Digital (Komdigi)"
```

- [ ] **Step 2: Verifikasi import**

Run: `python -c "from app.core.config import get_settings; s=get_settings(); print(s.pdp_authority_name, s.sla_alert_thresholds, s.enable_sla_monitor)"`
Expected: `Kementerian Komunikasi dan Digital (Komdigi) [48, 24, 6, 1] True`

- [ ] **Step 3: Commit**

```bash
git add app/core/config.py
git commit -m "feat(config): breach SLA automation settings"
```

---

## Task 2: DB columns + Alembic migration

**Files:**
- Modify: `app/models/agent.py` (class `BreachNotification`, setelah `compliance_evidence`, ~baris 148)
- Create: `alembic/versions/<rev>_breach_sla_columns.py`

- [ ] **Step 1: Tambah kolom model**

Setelah field `compliance_evidence`:

```python
    sla_alerts_sent: Mapped[list[str]] = mapped_column(
        JSON,
        default=list,
        nullable=False,
        comment="SLA alert thresholds already sent, e.g. ['48','24','overdue']",
    )
    notification_text_subject: Mapped[str | None] = mapped_column(
        Text,
        nullable=True,
        comment="Generated data-subject (pengguna) notification text per Pasal 46",
    )
```

- [ ] **Step 2: Generate migrasi autogenerate**

Run: `alembic revision --autogenerate -m "breach sla columns"`
Expected: file baru di `alembic/versions/` berisi `add_column('breach_notifications', ... 'sla_alerts_sent')` dan `'notification_text_subject'`.

- [ ] **Step 3: Periksa & rapikan migrasi**

Buka file revisi. Pastikan `upgrade()` menambah dua kolom dengan `server_default` aman untuk baris lama:

```python
def upgrade() -> None:
    op.add_column(
        "breach_notifications",
        sa.Column("sla_alerts_sent", sa.JSON(), nullable=False, server_default="[]"),
    )
    op.add_column(
        "breach_notifications",
        sa.Column("notification_text_subject", sa.Text(), nullable=True),
    )


def downgrade() -> None:
    op.drop_column("breach_notifications", "notification_text_subject")
    op.drop_column("breach_notifications", "sla_alerts_sent")
```

- [ ] **Step 4: Jalankan migrasi**

Run: `alembic upgrade head`
Expected: tanpa error; kolom terpasang.

- [ ] **Step 5: Commit**

```bash
git add app/models/agent.py alembic/versions/
git commit -m "feat(db): breach sla_alerts_sent + subject notification columns"
```

---

## Task 3: Two-variant letter generation

**Files:**
- Modify: `app/services/breach_notification.py` (`generate_notification_text` ~baris 215; tambah method baru)
- Test: `tests/test_breach_automation.py` (baru)

- [ ] **Step 1: Tulis failing test**

```python
# tests/test_breach_automation.py
from app.services.breach_notification import BreachAssessment, BreachNotificationService


def _assessment() -> BreachAssessment:
    return BreachAssessment(
        is_breach=True,
        severity="critical",
        finding_ids=["f1"],
        pii_types=["nik", "card_number"],
        breach_type="Financial data breach",
        description="contoh deskripsi",
        data_subjects_estimate=1000,
        requires_notification=True,
    )


class TestAuthorityLetter:
    def test_uses_configured_authority_name(self, monkeypatch):
        from app.core import config

        monkeypatch.setattr(
            config.get_settings(), "pdp_authority_name", "Kemkomdigi TEST", raising=False
        )
        text = BreachNotificationService.generate_notification_text(
            _assessment(), organization_name="PT Uji"
        )
        assert "Kemkomdigi TEST" in text
        assert "Badan Pelindungan Data Pribadi" not in text


class TestSubjectLetter:
    def test_subject_letter_is_layperson_with_actions(self):
        text = BreachNotificationService.generate_subject_notification_text(
            _assessment(), organization_name="PT Uji"
        )
        assert "Yth. Pengguna" in text or "Pelanggan" in text
        # imbauan tindakan konkret
        assert "kata sandi" in text.lower()
        assert "Nomor Induk Kependudukan (NIK)" in text  # label PII
```

- [ ] **Step 2: Run, verifikasi gagal**

Run: `pytest tests/test_breach_automation.py -v`
Expected: FAIL — `generate_subject_notification_text` belum ada; authority masih hardcode.

- [ ] **Step 3: Ganti baris hardcode di `generate_notification_text`**

Di dalam `generate_notification_text`, ganti baris:

```python
            "Kepada Yth. Badan Pelindungan Data Pribadi",
```
menjadi:

```python
            f"Kepada Yth. {get_settings().pdp_authority_name}",
```

(`get_settings` sudah di-import di file ini.)

- [ ] **Step 4: Tambah method varian subjek data**

Tambahkan setelah `generate_notification_text`:

```python
    @classmethod
    def generate_subject_notification_text(
        cls,
        breach_assessment: BreachAssessment,
        organization_name: str = "",
        contact_info: str = "",
    ) -> str:
        """Surat notifikasi untuk Subjek Data (pengguna), bahasa awam + imbauan.

        Pasal 46 ayat (1): subjek data wajib diberi tahu agar dapat melindungi diri.
        """
        now = datetime.now(timezone.utc).strftime("%d %B %Y %H:%M WIB")
        org = organization_name or "Kami"

        lines = [
            "PEMBERITAHUAN INSIDEN KEAMANAN DATA PRIBADI",
            "=" * 50,
            "",
            "Yth. Pengguna/Pelanggan,",
            "",
            f"{org} memberitahukan bahwa telah terjadi insiden yang berpotensi "
            "memengaruhi keamanan data pribadi Anda. Kami menyampaikan ini sesuai "
            "Pasal 46 UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi.",
            "",
            "DATA YANG BERPOTENSI TERDAMPAK:",
        ]
        if breach_assessment.pii_types:
            for pii_type in breach_assessment.pii_types:
                lines.append(f"  - {cls._get_pii_label(pii_type)}")
        else:
            lines.append("  - Sedang dalam penelaahan")

        lines.extend(
            [
                "",
                "LANGKAH YANG SEBAIKNYA ANDA LAKUKAN SEGERA:",
                "  1. Ganti kata sandi akun Anda, dan akun lain yang memakai kata sandi sama.",
                "  2. Aktifkan autentikasi dua faktor (2FA) bila tersedia.",
                "  3. Jika data kartu/rekening terdampak, hubungi bank Anda untuk "
                "pemblokiran/penggantian kartu dan pantau mutasi.",
                "  4. Waspadai upaya penipuan (phishing) via telepon, email, atau pesan "
                "yang mengatasnamakan kami.",
                "",
                "TINDAKAN YANG SEDANG KAMI LAKUKAN:",
                "  - Investigasi dan penanganan insiden sedang berlangsung.",
                "  - Langkah mitigasi dan peningkatan keamanan diterapkan.",
                "",
            ]
        )
        if contact_info:
            lines.extend(["CARA MENGHUBUNGI KAMI:", contact_info, ""])
        else:
            lines.extend(
                [
                    "CARA MENGHUBUNGI KAMI:",
                    f"Silakan hubungi {org} melalui saluran resmi yang tersedia.",
                    "",
                ]
            )
        lines.extend(
            [
                "=" * 50,
                f"Pemberitahuan ini dibuat pada {now}. Mohon maaf atas "
                "ketidaknyamanan ini dan terima kasih atas perhatian Anda.",
            ]
        )
        return "\n".join(lines)
```

- [ ] **Step 5: Run, verifikasi lulus**

Run: `pytest tests/test_breach_automation.py -v && pytest tests/test_breach_notification.py -q`
Expected: PASS semua (termasuk 20 test lama; cek tidak ada yang assert string "Badan Pelindungan Data Pribadi").

> Jika ada test lama yang assert "Badan Pelindungan Data Pribadi", perbarui agar assert `pdp_authority_name` default (Komdigi) — ini perubahan perilaku yang diinginkan spec.

- [ ] **Step 6: Commit**

```bash
git add app/services/breach_notification.py tests/test_breach_automation.py
git commit -m "feat(breach): configurable authority + data-subject letter variant"
```

---

## Task 4: `persist_breach` service method

**Files:**
- Modify: `app/services/breach_notification.py` (tambah classmethod async; tambah import)
- Test: `tests/test_breach_automation.py`

- [ ] **Step 1: Tulis failing test (DB)**

Tambahkan ke `tests/test_breach_automation.py`:

```python
import pytest
from app.database.session import get_sessionmaker
from app.models.agent import BreachNotification


@pytest.fixture
async def session():
    async with get_sessionmaker()() as s:
        yield s


class TestPersistBreach:
    async def test_creates_record_for_notifiable_findings(self, session):
        findings = [
            {
                "id": "find-1",
                "finding_type": "unauthenticated_pii_exposure",
                "severity": "critical",
                "title": "PII bocor",
                "evidence_summary": {"nik": "3201xxxx", "card_number": "4111"},
                "compliance": {},
            }
        ]
        breach = await BreachNotificationService.persist_breach(
            session, organization_id="org-xyz", finding_dicts=findings, org_name="PT Uji"
        )
        assert breach is not None
        assert breach.organization_id == "org-xyz"
        assert breach.notification_text  # varian otoritas
        assert breach.notification_text_subject  # varian subjek data
        assert breach.sla_deadline > breach.detected_at

    async def test_returns_none_for_non_notifiable(self, session):
        findings = [
            {
                "id": "find-2",
                "finding_type": "reflected_html_injection",
                "severity": "low",
                "title": "minor",
                "evidence_summary": {},
                "compliance": {},
            }
        ]
        breach = await BreachNotificationService.persist_breach(
            session, organization_id="org-xyz", finding_dicts=findings
        )
        assert breach is None
```

- [ ] **Step 2: Run, verifikasi gagal**

Run: `pytest tests/test_breach_automation.py -k PersistBreach -v`
Expected: FAIL — `persist_breach` belum ada.

- [ ] **Step 3: Implementasi**

Tambah import di atas file `breach_notification.py`:

```python
from datetime import datetime, timedelta, timezone
```
(sudah ada; pastikan `timedelta` ada). Tambah, di dalam blok `TYPE_CHECKING` atau import langsung yang aman dari circular:

```python
from sqlalchemy.ext.asyncio import AsyncSession
```

Tambahkan classmethod:

```python
    @classmethod
    async def persist_breach(
        cls,
        session: AsyncSession,
        organization_id: str,
        finding_dicts: list[dict[str, Any]],
        org_name: str = "",
        contact_info: str = "",
    ) -> "BreachNotification | None":
        """Assess findings; jika wajib lapor, buat record BreachNotification
        (mulai jam SLA 72 jam), generate kedua varian surat, commit, kembalikan
        record. Kembalikan None bila bukan breach wajib-lapor."""
        from app.models.agent import BreachNotification  # hindari circular import

        assessment = cls.detect_breach(finding_dicts)
        if not assessment.is_breach or not assessment.requires_notification:
            return None

        authority_text = cls.generate_notification_text(
            assessment, organization_name=org_name, contact_info=contact_info
        )
        subject_text = cls.generate_subject_notification_text(
            assessment, organization_name=org_name, contact_info=contact_info
        )

        now = datetime.now(timezone.utc)
        breach = BreachNotification(
            organization_id=organization_id,
            finding_ids=assessment.finding_ids,
            breach_title=assessment.breach_type or "Data breach assessment",
            description=assessment.description,
            breach_type=assessment.breach_type,
            severity=assessment.severity,
            status="assessing",
            detected_at=now,
            sla_deadline=now + timedelta(hours=cls.NOTIFICATION_DEADLINE_HOURS),
            pii_types_affected=assessment.pii_types,
            data_subjects_estimate=assessment.data_subjects_estimate,
            notification_text=authority_text,
            notification_text_subject=subject_text,
            actions_taken=["Automated breach assessment completed"],
            contact_info=contact_info,
            sla_alerts_sent=[],
            compliance_evidence={"assessment_reasons": assessment.reasons},
        )
        session.add(breach)
        await session.commit()
        await session.refresh(breach)
        return breach
```

- [ ] **Step 4: Run, verifikasi lulus**

Run: `pytest tests/test_breach_automation.py -k PersistBreach -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/services/breach_notification.py tests/test_breach_automation.py
git commit -m "feat(breach): persist_breach reusable orchestration"
```

---

## Task 5: Refactor API `breach-create` + return both letters in detail

**Files:**
- Modify: `app/api/compliance.py` (`create_breach_notification` ~baris 130; detail endpoint `breach/{breach_id}` ~baris 342)

- [ ] **Step 1: Ganti body `create_breach_notification`**

Ganti isi setelah fetch & validasi findings menjadi:

```python
    finding_dicts = [
        {
            "id": f.id,
            "finding_type": f.finding_type,
            "severity": f.severity,
            "title": f.title,
            "evidence_summary": f.evidence_summary,
            "compliance": f.compliance,
        }
        for f in findings
    ]

    org_stmt = select(Organization).where(Organization.id == user.organization_id)
    org = (await session.execute(org_stmt)).scalar_one_or_none()
    org_name = org.name if org else ""

    breach = await BreachNotificationService.persist_breach(
        session,
        organization_id=user.organization_id,
        finding_dicts=finding_dicts,
        org_name=org_name,
    )
    if breach is None:
        raise HTTPException(
            status_code=422,
            detail="Findings do not constitute a notifiable breach",
        )

    return {
        "breach_id": breach.id,
        "status": breach.status,
        "severity": breach.severity,
        "sla_deadline": breach.sla_deadline.isoformat(),
        "hours_remaining": BreachNotificationService.check_sla_compliance(
            breach.detected_at
        ).hours_remaining,
        "notification_preview": (breach.notification_text or "")[:500] + "...",
    }
```

- [ ] **Step 2: Tambahkan kedua varian surat di detail endpoint**

Di handler `GET /compliance/breach/{breach_id}`, pastikan response menyertakan:

```python
        "notification_text": breach.notification_text,
        "notification_text_subject": breach.notification_text_subject,
        "sla_alerts_sent": breach.sla_alerts_sent,
```
(tambahkan ke dict yang dikembalikan; sisanya biarkan.)

- [ ] **Step 3: Verifikasi import & regresi**

Run: `pytest tests/test_breach_notification.py tests/test_breach_automation.py -q`
Expected: PASS. Pastikan `from app.models import Organization` / `BreachNotification` tersedia di file (sudah dipakai sebelumnya).

- [ ] **Step 4: Commit**

```bash
git add app/api/compliance.py
git commit -m "refactor(api): breach-create uses persist_breach; detail returns both letters"
```

---

## Task 6: Auto-trigger di scan_service

**Files:**
- Modify: `app/services/scan_service.py` (setelah blok `COMPLETED`, ~baris 287-288)
- Test: `tests/test_breach_automation.py`

- [ ] **Step 1: Tulis failing test**

```python
class TestAutoTriggerHelper:
    async def test_assess_after_scan_creates_breach(self, session):
        from app.services.scan_service import assess_breach_after_scan

        findings = [
            {
                "id": "f-crit",
                "finding_type": "unauthenticated_pii_exposure",
                "severity": "critical",
                "title": "PII",
                "evidence_summary": {"nik": "3201"},
                "compliance": {},
            }
        ]
        breach = await assess_breach_after_scan(
            session, organization_id="org-auto", finding_dicts=findings, org_name="PT X"
        )
        assert breach is not None
        assert breach.notification_text_subject
```

- [ ] **Step 2: Run, verifikasi gagal**

Run: `pytest tests/test_breach_automation.py -k AutoTrigger -v`
Expected: FAIL — `assess_breach_after_scan` belum ada.

- [ ] **Step 3: Tambah helper modul-level di `scan_service.py`**

Tambahkan fungsi modul-level (di luar class `ScanRunner`), dengan import yang diperlukan di atas file:

```python
async def assess_breach_after_scan(
    session,
    organization_id: str,
    finding_dicts: list[dict],
    org_name: str = "",
):
    """Assess findings → buat BreachNotification + kirim Telegram alert internal.
    Mengembalikan record (atau None). Tidak melempar exception ke pemanggil."""
    from app.services.breach_notification import BreachNotificationService

    breach = await BreachNotificationService.persist_breach(
        session, organization_id=organization_id, finding_dicts=finding_dicts,
        org_name=org_name,
    )
    if breach is None:
        return None
    try:
        from app.services.breach_notification import BreachAssessment

        msg = BreachNotificationService.build_telegram_message(
            BreachAssessment(
                is_breach=True,
                severity=breach.severity,
                finding_ids=breach.finding_ids,
                pii_types=breach.pii_types_affected,
                breach_type=breach.breach_type,
                data_subjects_estimate=breach.data_subjects_estimate,
            ),
            organization_name=org_name,
        )
        result = await BreachNotificationService.send_telegram_notification(msg)
        if result.get("success"):
            breach.notification_channels = list(
                set([*breach.notification_channels, "telegram"])
            )
            await session.commit()
    except Exception:
        logger.exception("Telegram breach alert failed (non-fatal)")
    return breach
```

Pastikan `logger = logging.getLogger(__name__)` ada di file (tambah jika belum).

- [ ] **Step 4: Panggil dari `run_scan` setelah COMPLETED**

Di `run_scan`, setelah `await self._dispatch_webhooks(scan, "scan.completed")` (baris ~288), tambahkan blok terbungkus:

```python
            try:
                from app.models.finding import Finding
                from app.models.organization import Organization

                fstmt = select(Finding).where(Finding.scan_id == scan.id)
                scan_findings = (await self.session.execute(fstmt)).scalars().all()
                finding_dicts = [
                    {
                        "id": f.id,
                        "finding_type": f.finding_type,
                        "severity": f.severity,
                        "title": f.title,
                        "evidence_summary": f.evidence_summary,
                        "compliance": f.compliance,
                    }
                    for f in scan_findings
                ]
                org = await self.session.get(Organization, scan.organization_id)
                await assess_breach_after_scan(
                    self.session,
                    organization_id=scan.organization_id,
                    finding_dicts=finding_dicts,
                    org_name=org.name if org else "",
                )
            except Exception:
                logger.exception("Auto breach assessment failed (non-fatal)")
```

> Verifikasi nama modul/atribut: `Finding.scan_id`, `Finding.compliance`, `select` sudah di-import di scan_service. Sesuaikan import path bila berbeda (cek `app/models/finding.py`).

- [ ] **Step 5: Run, verifikasi lulus + regresi scan**

Run: `pytest tests/test_breach_automation.py -k AutoTrigger -v && pytest -q`
Expected: PASS; tidak ada regresi.

- [ ] **Step 6: Commit**

```bash
git add app/services/scan_service.py tests/test_breach_automation.py
git commit -m "feat(scan): auto-assess breach + telegram alert after scan completion"
```

---

## Task 7: `due_sla_alerts` pure function

**Files:**
- Create: `app/services/sla_monitor.py`
- Test: `tests/test_sla_monitor.py` (baru)

- [ ] **Step 1: Tulis failing test**

```python
# tests/test_sla_monitor.py
from app.services.sla_monitor import due_sla_alerts

THRESHOLDS = [48, 24, 6, 1]


def test_no_alert_when_far_from_deadline():
    assert due_sla_alerts(60.0, False, [], THRESHOLDS) == []


def test_fires_48_threshold():
    assert due_sla_alerts(47.0, False, [], THRESHOLDS) == ["48"]


def test_fires_multiple_uncrossed_at_once():
    # 5 jam tersisa → 48,24,6 sudah terlewati sekaligus jika belum dikirim
    assert due_sla_alerts(5.0, False, [], THRESHOLDS) == ["48", "24", "6"]


def test_respects_already_sent():
    assert due_sla_alerts(5.0, False, ["48", "24"], THRESHOLDS) == ["6"]


def test_overdue_once():
    assert due_sla_alerts(0.0, True, ["48", "24", "6", "1"], THRESHOLDS) == ["overdue"]
    assert due_sla_alerts(0.0, True, ["48", "24", "6", "1", "overdue"], THRESHOLDS) == []
```

- [ ] **Step 2: Run, verifikasi gagal**

Run: `pytest tests/test_sla_monitor.py -v`
Expected: FAIL — modul belum ada.

- [ ] **Step 3: Implementasi fungsi murni**

```python
# app/services/sla_monitor.py
"""SLA monitor untuk breach notification Pasal 46 (3x24 jam)."""

from __future__ import annotations

import asyncio
import logging

logger = logging.getLogger(__name__)


def due_sla_alerts(
    hours_remaining: float,
    is_overdue: bool,
    already_sent: list[str],
    thresholds: list[int],
) -> list[str]:
    """Kembalikan label ambang yang BARU harus dialertkan (anti-spam)."""
    sent = set(already_sent)
    new: list[str] = []
    for t in sorted(thresholds, reverse=True):  # 48,24,6,1
        label = str(t)
        if hours_remaining <= t and label not in sent:
            new.append(label)
    if is_overdue and "overdue" not in sent:
        new.append("overdue")
    return new
```

- [ ] **Step 4: Run, verifikasi lulus**

Run: `pytest tests/test_sla_monitor.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/services/sla_monitor.py tests/test_sla_monitor.py
git commit -m "feat(sla): due_sla_alerts threshold selection"
```

---

## Task 8: `run_sla_monitor` loop + `_tick`

**Files:**
- Modify: `app/services/sla_monitor.py`
- Test: `tests/test_sla_monitor.py`

- [ ] **Step 1: Tulis failing test untuk `_tick`**

```python
import pytest
from datetime import datetime, timedelta, timezone
from app.database.session import get_sessionmaker
from app.models.agent import BreachNotification
from app.services.sla_monitor import process_breach_alerts


@pytest.fixture
async def session():
    async with get_sessionmaker()() as s:
        yield s


class TestProcessBreachAlerts:
    async def test_marks_overdue_and_records_alert(self, session):
        now = datetime.now(timezone.utc)
        breach = BreachNotification(
            organization_id="org-sla",
            finding_ids=["f1"],
            breach_title="t",
            description="d",
            breach_type="x",
            severity="high",
            status="assessing",
            detected_at=now - timedelta(hours=100),  # sudah lewat 72 jam
            sla_deadline=now - timedelta(hours=28),
            sla_alerts_sent=[],
        )
        session.add(breach)
        await session.commit()

        fired = await process_breach_alerts(session, [48, 24, 6, 1], send=False)
        await session.refresh(breach)
        assert breach.status == "overdue"
        assert "overdue" in breach.sla_alerts_sent
        assert breach.id in fired
```

- [ ] **Step 2: Run, verifikasi gagal**

Run: `pytest tests/test_sla_monitor.py -k ProcessBreach -v`
Expected: FAIL — `process_breach_alerts` belum ada.

- [ ] **Step 3: Implementasi `process_breach_alerts`, `_tick`, `run_sla_monitor`**

Tambahkan ke `app/services/sla_monitor.py`:

```python
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession

from app.core.config import get_settings
from app.database.session import get_sessionmaker
from app.models.agent import BreachNotification
from app.services.breach_notification import BreachNotificationService


async def process_breach_alerts(
    session: AsyncSession, thresholds: list[int], send: bool = True
) -> dict[str, list[str]]:
    """Periksa semua breach aktif; kirim reminder/overdue yang baru; commit.
    Kembalikan map breach_id -> daftar label yang baru dialertkan."""
    stmt = select(BreachNotification).where(
        BreachNotification.status.notin_(["notified", "dismissed"])
    )
    breaches = (await session.execute(stmt)).scalars().all()
    fired: dict[str, list[str]] = {}

    for b in breaches:
        sla = BreachNotificationService.check_sla_compliance(b.detected_at)
        new = due_sla_alerts(
            sla.hours_remaining, sla.is_overdue, b.sla_alerts_sent, thresholds
        )
        if not new:
            continue
        if send:
            for label in new:
                try:
                    msg = (
                        f"⏰ <b>SLA Pasal 46</b> — {b.breach_title}\n"
                        f"Sisa: {sla.hours_remaining} jam"
                        + (" (OVERDUE)" if label == "overdue" else f" (ambang {label}j)")
                    )
                    await BreachNotificationService.send_telegram_notification(msg)
                except Exception:
                    logger.exception("SLA reminder telegram failed (non-fatal)")
        b.sla_alerts_sent = [*b.sla_alerts_sent, *new]
        if sla.is_overdue and b.status != "overdue":
            b.status = "overdue"
        fired[b.id] = new

    if fired:
        await session.commit()
    return fired


async def _tick() -> None:
    thresholds = get_settings().sla_alert_thresholds
    async with get_sessionmaker()() as session:
        await process_breach_alerts(session, thresholds, send=True)


async def run_sla_monitor(stop_event: asyncio.Event) -> None:
    interval = get_settings().sla_monitor_interval_seconds
    logger.info("SLA monitor started (interval=%ss)", interval)
    while not stop_event.is_set():
        try:
            await _tick()
        except Exception:
            logger.exception("SLA monitor tick failed")
        try:
            await asyncio.wait_for(stop_event.wait(), timeout=interval)
        except asyncio.TimeoutError:
            pass
    logger.info("SLA monitor stopped")
```

- [ ] **Step 4: Run, verifikasi lulus**

Run: `pytest tests/test_sla_monitor.py -v`
Expected: PASS.

- [ ] **Step 5: Commit**

```bash
git add app/services/sla_monitor.py tests/test_sla_monitor.py
git commit -m "feat(sla): process_breach_alerts + run_sla_monitor loop"
```

---

## Task 9: Wire SLA monitor ke `main.py` lifespan

**Files:**
- Modify: `app/main.py` (`lifespan`, baris ~17-28)

- [ ] **Step 1: Update lifespan**

```python
import asyncio
from app.services.sla_monitor import run_sla_monitor


@asynccontextmanager
async def lifespan(app: FastAPI):
    session_factory = get_sessionmaker()
    if get_settings().database_url.startswith("sqlite"):
        async with get_engine().begin() as connection:
            await connection.run_sync(Base.metadata.create_all)
    async with session_factory() as session:
        await seed_defaults(session)
    if not get_settings().use_celery:
        async with session_factory() as session:
            await mark_interrupted_scans(session)

    sla_task = None
    stop_event = asyncio.Event()
    if get_settings().enable_sla_monitor:
        sla_task = asyncio.create_task(run_sla_monitor(stop_event))
    try:
        yield
    finally:
        if sla_task is not None:
            stop_event.set()
            try:
                await asyncio.wait_for(sla_task, timeout=10)
            except (asyncio.TimeoutError, asyncio.CancelledError):
                sla_task.cancel()
```

- [ ] **Step 2: Smoke test startup/shutdown**

Run: `python -c "import asyncio; from app.main import app; print('import ok')"`
Expected: `import ok` tanpa error.

- [ ] **Step 3: Jalankan suite penuh**

Run: `pytest -q`
Expected: semua PASS.

- [ ] **Step 4: Commit**

```bash
git add app/main.py
git commit -m "feat(app): start/stop SLA monitor in lifespan"
```

---

## Task 10: Frontend API client

**Files:**
- Modify: `frontend/src/lib/api.ts` (dalam objek `api`, dekat `compliance`/`complianceRemediationMatrix` ~baris 114-124)

- [ ] **Step 1: Tambah method breach**

```typescript
  breaches: () => request<BreachListItem[]>("/compliance/breaches"),
  breach: (id: string) =>
    request<BreachDetail>(`/compliance/breach/${encodeURIComponent(id)}`),
  breachNotify: (id: string, channels: string[] = ["telegram"], contactInfo = "") =>
    request<{ status: string; sla_hours_remaining: number }>(
      "/compliance/breach-notify",
      {
        method: "POST",
        body: JSON.stringify({ breach_id: id, channels, contact_info: contactInfo }),
      },
    ),
  breachDismiss: (id: string, reason: string) =>
    request<{ status: string }>("/compliance/breach-dismiss", {
      method: "POST",
      body: JSON.stringify({ breach_id: id, reason }),
    }),
```

- [ ] **Step 2: Tambah tipe di `frontend/src/types/api.ts`**

```typescript
export interface BreachListItem {
  id: string;
  breach_title: string;
  severity: string;
  status: string;
  detected_at: string;
  sla_deadline: string;
  hours_remaining: number;
  data_subjects_estimate: number;
}

export interface BreachDetail extends BreachListItem {
  description: string;
  breach_type: string;
  pii_types_affected: string[];
  notification_text: string | null;
  notification_text_subject: string | null;
  sla_alerts_sent: string[];
  notified_at: string | null;
}
```

> Verifikasi: bentuk respons endpoint `breaches` & `breach/{id}` di `app/api/compliance.py` cocok dengan field di atas; sesuaikan nama field bila berbeda (mis. `breaches` mungkin mengembalikan subset — samakan).

- [ ] **Step 3: Type-check**

Run: `cd frontend && npx tsc --noEmit`
Expected: tanpa error.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/lib/api.ts frontend/src/types/api.ts
git commit -m "feat(fe): breach notification API client + types"
```

---

## Task 11: Frontend `BreachNotificationsPanel`

**Files:**
- Modify: `frontend/src/pages/compliance.tsx` (komponen baru + render dekat `BreachReadinessImpl` ~baris 770)

- [ ] **Step 1: Tambah komponen panel**

```tsx
function BreachNotificationsPanel() {
  const [items, setItems] = useState<BreachListItem[]>([]);
  const [selected, setSelected] = useState<BreachDetail | null>(null);
  const [variant, setVariant] = useState<"authority" | "subject">("authority");
  const [dismissing, setDismissing] = useState(false);
  const [reason, setReason] = useState("");
  const [error, setError] = useState<string | null>(null);

  const load = async () => {
    try {
      setItems(await api.breaches());
    } catch (e) {
      setError(e instanceof Error ? e.message : "Gagal memuat breach");
    }
  };
  useEffect(() => {
    void load();
  }, []);

  const open = async (id: string) => {
    setVariant("authority");
    setDismissing(false);
    setSelected(await api.breach(id));
  };

  const letter =
    variant === "authority"
      ? selected?.notification_text
      : selected?.notification_text_subject;

  const copy = () => letter && navigator.clipboard.writeText(letter);
  const download = () => {
    if (!letter || !selected) return;
    const blob = new Blob([letter], { type: "text/plain;charset=utf-8" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = `surat-${variant}-${selected.id}.txt`;
    a.click();
    URL.revokeObjectURL(url);
  };

  const notify = async () => {
    if (!selected) return;
    await api.breachNotify(selected.id);
    await open(selected.id);
    await load();
  };
  const dismiss = async () => {
    if (!selected || !reason.trim()) return;
    await api.breachDismiss(selected.id, reason.trim());
    setSelected(null);
    setReason("");
    setDismissing(false);
    await load();
  };

  const slaColor = (h: number, status: string) =>
    status === "overdue" || h <= 0
      ? "text-red-500"
      : h < 6
        ? "text-orange-500"
        : h < 24
          ? "text-amber-500"
          : "text-emerald-500";

  return (
    <section className="rounded-xl border border-border/60 p-4">
      <h3 className="mb-3 text-sm font-semibold">Breach Notifications (Pasal 46)</h3>
      {error && <p className="text-xs text-red-500">{error}</p>}
      {items.length === 0 && (
        <p className="text-xs text-muted-foreground">Belum ada breach terdeteksi.</p>
      )}
      <ul className="space-y-2">
        {items.map((b) => (
          <li key={b.id}>
            <button
              onClick={() => void open(b.id)}
              className="flex w-full items-center justify-between rounded-lg border border-border/50 px-3 py-2 text-left hover:bg-muted/40"
            >
              <span className="truncate">
                <span className="font-medium">{b.breach_title}</span>
                <span className="ml-2 text-xs uppercase opacity-70">{b.severity}</span>
              </span>
              <span className={`text-xs font-mono ${slaColor(b.hours_remaining, b.status)}`}>
                {b.status === "overdue" || b.hours_remaining <= 0
                  ? "OVERDUE"
                  : `${b.hours_remaining.toFixed(0)}j tersisa`}
              </span>
            </button>
          </li>
        ))}
      </ul>

      {selected && (
        <div className="mt-4 rounded-lg border border-border/60 p-3">
          <div className="mb-2 flex items-center gap-2">
            <button
              onClick={() => setVariant("authority")}
              className={`rounded px-2 py-1 text-xs ${variant === "authority" ? "bg-primary text-primary-foreground" : "bg-muted"}`}
            >
              Ke Otoritas
            </button>
            <button
              onClick={() => setVariant("subject")}
              className={`rounded px-2 py-1 text-xs ${variant === "subject" ? "bg-primary text-primary-foreground" : "bg-muted"}`}
            >
              Ke Subjek Data
            </button>
            <div className="ml-auto flex gap-2">
              <button onClick={copy} className="rounded bg-muted px-2 py-1 text-xs">
                Copy
              </button>
              <button onClick={download} className="rounded bg-muted px-2 py-1 text-xs">
                Download
              </button>
            </div>
          </div>
          <pre className="max-h-72 overflow-auto whitespace-pre-wrap rounded bg-muted/40 p-3 text-xs">
            {letter || "Surat belum tersedia."}
          </pre>
          <div className="mt-3 flex items-center gap-2">
            <button
              onClick={() => void notify()}
              disabled={selected.status === "notified"}
              className="rounded bg-emerald-600 px-3 py-1 text-xs text-white disabled:opacity-50"
            >
              {selected.status === "notified" ? "Sudah dinotifikasi" : "Tandai sudah dinotifikasi"}
            </button>
            {!dismissing ? (
              <button
                onClick={() => setDismissing(true)}
                className="rounded bg-muted px-3 py-1 text-xs"
              >
                Dismiss
              </button>
            ) : (
              <span className="flex items-center gap-2">
                <input
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder="Alasan dismiss"
                  className="rounded border px-2 py-1 text-xs"
                />
                <button
                  onClick={() => void dismiss()}
                  className="rounded bg-red-600 px-2 py-1 text-xs text-white"
                >
                  Konfirmasi
                </button>
                <button
                  onClick={() => setDismissing(false)}
                  className="rounded bg-muted px-2 py-1 text-xs"
                >
                  Batal
                </button>
              </span>
            )}
          </div>
        </div>
      )}
    </section>
  );
}
```

- [ ] **Step 2: Render panel di halaman**

Tambahkan `<BreachNotificationsPanel />` di area render dekat `BreachReadiness` (cari di JSX tempat `BreachReadinessImpl`/`BreachReadiness` dipakai, sisipkan setelahnya). Tambahkan import tipe di atas file:

```tsx
import type { BreachListItem, BreachDetail } from "../types/api";
```
(`api` & `useState`/`useEffect` sudah di-import di file ini.)

- [ ] **Step 3: Type-check & build**

Run: `cd frontend && npx tsc --noEmit && npm run build`
Expected: build sukses tanpa error TS.

- [ ] **Step 4: Commit**

```bash
git add frontend/src/pages/compliance.tsx
git commit -m "feat(fe): breach notifications panel with dual-letter view"
```

---

## Task 12: Verifikasi akhir

- [ ] **Step 1: Suite backend penuh**

Run: `pytest -q`
Expected: semua PASS (termasuk 20 test breach lama + test baru).

- [ ] **Step 2: Frontend build**

Run: `cd frontend && npx tsc --noEmit && npm run build`
Expected: sukses.

- [ ] **Step 3: Commit akhir bila ada sisa**

```bash
git add -A && git commit -m "chore: finalize pdp breach automation" || true
```

---

## Self-Review Notes (penyusun plan)

- **Spec coverage:** Fitur 1 (T4-6), Fitur 2 (T7-9), Fitur 3 (T10-11), config/db/migrasi (T1-2), dua varian surat + authority configurable (T3), error handling non-fatal (T6/T8), testing (tiap task). ✔
- **Asumsi yang harus diverifikasi saat eksekusi (ditandai inline):** path model `Finding` (`app/models/finding.py`) & field `scan_id`/`compliance`; bentuk respons endpoint `breaches`/`breach/{id}` agar cocok dengan tipe FE; nama komponen render `BreachReadiness` di `compliance.tsx`. Jika berbeda, sesuaikan tanpa mengubah desain.
- **Type consistency:** `persist_breach`, `assess_breach_after_scan`, `due_sla_alerts`, `process_breach_alerts`, `run_sla_monitor` dipakai konsisten lintas task.
