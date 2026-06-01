"""Tests for the BreachNotificationService."""

from datetime import datetime, timedelta, timezone

from app.services.breach_notification import (
    BreachAssessment,
    BreachNotificationService,
    SLAStatus,
)


class TestSeverityNormalization:
    def test_lowercase_passthrough(self):
        assert BreachNotificationService._normalize_severity("critical") == "critical"
        assert BreachNotificationService._normalize_severity("high") == "high"
        assert BreachNotificationService._normalize_severity("medium") == "medium"

    def test_uppercase_to_lowercase(self):
        assert BreachNotificationService._normalize_severity("CRITICAL") == "critical"
        assert BreachNotificationService._normalize_severity("HIGH") == "high"

    def test_mixed_case(self):
        assert BreachNotificationService._normalize_severity("Critical") == "critical"
        assert BreachNotificationService._normalize_severity("High") == "high"

    def test_none_like(self):
        assert BreachNotificationService._normalize_severity(None) == "info"
        assert BreachNotificationService._normalize_severity("") == "info"


class TestShouldAssess:
    def test_always_assess_types(self):
        from app.services.breach_notification import ALWAYS_ASSESS_FINDING_TYPES
        for ft in ALWAYS_ASSESS_FINDING_TYPES:
            assert BreachNotificationService.should_assess(ft) is True

    def test_pii_in_type(self):
        assert BreachNotificationService.should_assess("pii_exposure") is True
        assert BreachNotificationService.should_assess("some_pii_stuff") is True

    def test_unrelated_type(self):
        assert BreachNotificationService.should_assess("xss_reflected") is False


class TestDetectBreach:
    def _make_finding(self, **kwargs):
        defaults = {
            "id": "test-1",
            "finding_type": "unauthenticated_pii_exposure",
            "severity": "high",
            "title": "Test",
            "evidence_summary": {"nik": "3175010101010001", "nama_lengkap": "Test"},
        }
        defaults.update(kwargs)
        return defaults

    def test_breach_detected_with_high_severity_and_pii(self):
        findings = [self._make_finding(id="f1", severity="high")]
        result = BreachNotificationService.detect_breach(findings)
        assert result.is_breach is True
        assert result.requires_notification is True
        assert result.severity in ("high", "critical")
        assert len(result.finding_ids) > 0

    def test_no_breach_for_low_severity(self):
        findings = [self._make_finding(id="f1", severity="low")]
        result = BreachNotificationService.detect_breach(findings)
        # Low severity without high/critical should not trigger breach
        # (depends on evidence having PII keywords)
        # This finding has PII in evidence but low severity
        # The service requires high/critical for breach detection
        assert result.is_breach is False

    def test_multiple_findings_aggregated(self):
        findings = [
            self._make_finding(id="f1", severity="high"),
            self._make_finding(id="f2", severity="critical", finding_type="bola"),
        ]
        result = BreachNotificationService.detect_breach(findings)
        assert result.is_breach is True
        assert result.severity == "critical"

    def test_empty_findings(self):
        result = BreachNotificationService.detect_breach([])
        assert result.is_breach is False
        assert result.requires_notification is False


class TestSLACompliance:
    def test_compliant_notification(self):
        detected = datetime.now(timezone.utc) - timedelta(hours=24)
        notified = datetime.now(timezone.utc) - timedelta(hours=25)
        sla = BreachNotificationService.check_sla_compliance(detected, notified)
        assert sla.is_compliant is True
        assert sla.is_overdue is False

    def test_overdue_notification(self):
        detected = datetime.now(timezone.utc) - timedelta(hours=80)
        notified = datetime.now(timezone.utc)
        sla = BreachNotificationService.check_sla_compliance(detected, notified)
        assert sla.is_compliant is False
        assert sla.is_overdue is True

    def test_pending_notification_with_time_left(self):
        detected = datetime.now(timezone.utc) - timedelta(hours=1)
        sla = BreachNotificationService.check_sla_compliance(detected, None)
        assert sla.is_compliant is True
        assert sla.hours_remaining > 0

    def test_pending_notification_overdue(self):
        detected = datetime.now(timezone.utc) - timedelta(hours=80)
        sla = BreachNotificationService.check_sla_compliance(detected, None)
        assert sla.is_compliant is False
        assert sla.is_overdue is True


class TestNotificationText:
    def test_generates_complete_text(self):
        assessment = BreachAssessment(
            is_breach=True,
            severity="critical",
            finding_ids=["f1", "f2"],
            pii_types=["nik", "card_number"],
            breach_type="Comprehensive data breach",
            description="Test breach description",
            data_subjects_estimate=500,
            requires_notification=True,
        )
        text = BreachNotificationService.generate_notification_text(
            assessment,
            organization_name="Test Bank",
            contact_info="privacy@testbank.com",
        )
        assert "NOTIFIKASI KEGAGALAN PELINDUNGAN DATA PRIBADI" in text
        assert "Test Bank" in text
        assert "NIK" in text
        assert "500" in text
        assert "privacy@testbank.com" in text
        assert "Pasal 46" in text

    def test_notification_has_all_5_sections(self):
        assessment = BreachAssessment(
            is_breach=True,
            severity="high",
            finding_ids=["f1"],
            pii_types=["email"],
            breach_type="Personal data exposure",
            description="Test",
            data_subjects_estimate=100,
            requires_notification=True,
        )
        text = BreachNotificationService.generate_notification_text(assessment)
        assert "1. DESKRIPSI" in text
        assert "2. JENIS DATA" in text
        assert "3. PERIODE" in text
        assert "4. TINDAKAN" in text
        assert "5. CARA MENGHUBUNGI" in text


class TestTelegramMessage:
    def test_builds_html_message(self):
        assessment = BreachAssessment(
            is_breach=True,
            severity="critical",
            finding_ids=["f1"],
            pii_types=["nik"],
            breach_type="Identity breach",
            description="Test",
            data_subjects_estimate=100,
            requires_notification=True,
        )
        msg = BreachNotificationService.build_telegram_message(assessment, "Test Org")
        assert "<b>BREACH NOTIFICATION REQUIRED</b>" in msg
        assert "Test Org" in msg
        assert "CRITICAL" in msg
        assert "72" in msg
        assert "3x24" in msg


class TestPIILabels:
    def test_all_known_types_have_labels(self):
        for pii_type in [
            "nik",
            "npwp",
            "card_number",
            "biometric",
            "bank_account_number",
            "transaction_history",
            "loan_data",
            "phone_number",
            "email",
        ]:
            label = BreachNotificationService._get_pii_label(pii_type)
            assert label, f"No label for {pii_type}"
            assert "[REDACTED]" not in label

    def test_unknown_type_returns_formatted_name(self):
        label = BreachNotificationService._get_pii_label("some_unknown_type")
        assert "Some Unknown Type" in label or "some_unknown_type" in label
