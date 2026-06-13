"""Tests for breach automation: letter variants, persist_breach, auto-trigger."""

import asyncio

from app.database.session import get_sessionmaker
from app.services.breach_notification import (
    BreachAssessment,
    BreachNotificationService,
)


def _run(coro):
    """Run an async coroutine in a fresh event loop (no pytest-asyncio dep)."""
    return asyncio.run(coro)


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
    def test_uses_configured_authority_name(self):
        text = BreachNotificationService.generate_notification_text(
            _assessment(), organization_name="PT Uji"
        )
        # Default authority per current Indonesian regulatory transition
        assert "Kementerian Komunikasi dan Digital" in text
        assert "Badan Pelindungan Data Pribadi" not in text


class TestSubjectLetter:
    def test_subject_letter_is_layperson_with_actions(self):
        text = BreachNotificationService.generate_subject_notification_text(
            _assessment(), organization_name="PT Uji"
        )
        assert "Pengguna" in text or "Pelanggan" in text
        # imbauan tindakan konkret
        assert "kata sandi" in text.lower()
        # label PII manusiawi
        assert "Nomor Induk Kependudukan (NIK)" in text


class TestPersistBreach:
    def test_creates_record_for_notifiable_findings(self):
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

        async def _do():
            async with get_sessionmaker()() as s:
                return await BreachNotificationService.persist_breach(
                    s,
                    organization_id="org-xyz",
                    finding_dicts=findings,
                    org_name="PT Uji",
                )

        breach = _run(_do())
        assert breach is not None
        assert breach.organization_id == "org-xyz"
        assert breach.notification_text  # varian otoritas
        assert breach.notification_text_subject  # varian subjek data
        assert breach.sla_deadline > breach.detected_at
        assert breach.sla_alerts_sent == []

    def test_returns_none_for_non_notifiable(self):
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

        async def _do():
            async with get_sessionmaker()() as s:
                return await BreachNotificationService.persist_breach(
                    s, organization_id="org-xyz", finding_dicts=findings
                )

        assert _run(_do()) is None


class TestAutoTriggerHelper:
    def test_assess_after_scan_creates_breach(self):
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

        async def _do():
            async with get_sessionmaker()() as s:
                return await assess_breach_after_scan(
                    s,
                    organization_id="org-auto",
                    finding_dicts=findings,
                    org_name="PT X",
                )

        breach = _run(_do())
        assert breach is not None
        assert breach.notification_text_subject
