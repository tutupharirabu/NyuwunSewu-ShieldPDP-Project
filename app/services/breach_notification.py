"""Breach Notification Service per Pasal 46 UU PDP (3x24h SLA).

This service detects when findings constitute a notifiable data breach,
generates notification templates, tracks SLA compliance, and sends
notifications via available channels (Telegram, dashboard, email).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Any

from app.core.config import get_settings

logger = logging.getLogger(__name__)

# Pasal 46 UU PDP: notification within 3x24 hours (72 hours)
SLA_DEADLINE_HOURS = 72

# Data indicator keywords that signal personal data exposure.
# Includes standard PII types plus Vuln-Bank specific fields.
DATA_INDICATOR_MAP: dict[str, list[str]] = {
    # Standard Indonesian PII
    "nik": ["nik", "nomor_induk_kependudukan", "no_ktp", "identitas"],
    "npwp": ["npwp", "nomor_pokok_wajib_pajak"],
    "phone_number": ["phone", "no_hp", "telepon", "mobile", "handphone"],
    "email": ["email", "e_mail", "surat_elektronik"],
    "bank_account_number": [
        "rekening",
        "bank_account",
        "no_rek",
        "virtual_account",
        "bca",
        "mandiri",
        "bni",
        "bri",
        "cimb",
    ],
    # Vuln-Bank specific data types
    "card_number": ["card_number", "credit_card", "debit_card", "kartu_kredit", "pan"],
    "transaction_history": [
        "transaction_history",
        "riwayat_transaksi",
        "transactions",
        "mutasi",
        "payment_history",
    ],
    "loan_data": [
        "loan_data",
        "data_pinjaman",
        "plafon",
        "tenor",
        "interest_rate",
        "bunga",
        "cicilan",
        "installment",
    ],
    "biometric": ["biometric", "biometrik", "face_scan", "fingerprint", "wajah"],
    "customer_id": ["customer_id", "cust_id", "nasabah_id", "account_number"],
    "address": ["alamat", "address", "kota", "kecamatan", "kelurahan", "kode_pos"],
    "employment": [
        "pekerjaan",
        "employer",
        "jabatan",
        "posisi",
        "income",
        "penghasilan",
        "gaji",
    ],
    "health_data": [
        "health_data",
        "kesehatan",
        "medical",
        "asuransi",
        "insurance",
        "claim",
    ],
    # Generic sensitive fields
    "password": ["password", "passwd", "secret", "pwd", "kata_sandi"],
    "token": ["token", "bearer", "access_token", "refresh_token", "jwt"],
    "full_name": ["nama_lengkap", "full_name", "name", "beneficiary"],
}

# Finding types that always trigger breach assessment
ALWAYS_ASSESS_FINDING_TYPES = {
    "unauthenticated_pii_exposure",
    "unauthenticated_sensitive_api_exposure",
    "bola",
    "idor",
    "broken_access_control",
    "access_control_matrix",
    "pii_exposure",
    "sqli",
    "sql_injection",
    "data_leak",
    "sensitive_data_exposure",
}


@dataclass(slots=True)
class BreachAssessment:
    """Result of assessing whether findings constitute a notifiable breach."""

    is_breach: bool
    severity: str = "info"
    finding_ids: list[str] = field(default_factory=list)
    pii_types: list[str] = field(default_factory=list)
    breach_type: str = ""
    description: str = ""
    data_subjects_estimate: int = 0
    requires_notification: bool = False
    reasons: list[str] = field(default_factory=list)


@dataclass(slots=True)
class SLAStatus:
    """SLA compliance status for a breach notification."""

    breach_id: str
    detected_at: datetime
    sla_deadline: datetime
    notified_at: datetime | None
    is_compliant: bool
    hours_remaining: float
    is_overdue: bool


class BreachNotificationService:
    """Manage data breach notifications per Pasal 46 UU PDP."""

    NOTIFICATION_DEADLINE_HOURS = SLA_DEADLINE_HOURS  # 3 x 24 jam = 72 hours

    @classmethod
    def should_assess(cls, finding_type: str) -> bool:
        """Check if a finding type warrants breach assessment."""
        normalized = finding_type.lower()
        return normalized in ALWAYS_ASSESS_FINDING_TYPES or "pii" in normalized

    @classmethod
    def detect_breach(cls, findings: list[dict[str, Any]]) -> BreachAssessment:
        """Detect if findings constitute a data breach requiring notification.

        Criteria per Pasal 46:
        - Personal data exposure confirmed (high/critical severity)
        - Risk to data subjects assessed
        - Data was accessed or disclosed without authorization

        Args:
            findings: List of finding dicts (from SQLAlchemy Finding or API response).
                Each dict should have keys: id, finding_type, severity,
                evidence_summary, compliance, etc.
        """
        assessment = BreachAssessment(is_breach=False)
        pii_types_found: set[str] = set()
        critical_findings: list[dict[str, Any]] = []
        reasons: list[str] = []

        for f in findings:
            severity = cls._normalize_severity(f.get("severity", "info"))
            finding_type = f.get("finding_type", "").lower()
            finding_id = f.get("id", "")
            evidence = f.get("evidence_summary", {})

            # Check for PII in evidence
            detected_pii = cls._extract_pii_types(evidence, finding_type)
            pii_types_found.update(detected_pii)

            # High/critical findings with PII are breach candidates
            if severity in ("critical", "high") and detected_pii:
                critical_findings.append(f)
                assessment.finding_ids.append(finding_id)

            # Always assess certain finding types
            if cls.should_assess(finding_type) and severity in (
                "critical",
                "high",
                "medium",
            ):
                if finding_id not in assessment.finding_ids:
                    assessment.finding_ids.append(finding_id)

        # Determine breach status
        if critical_findings:
            assessment.is_breach = True
            assessment.requires_notification = True
            assessment.severity = (
                "critical"
                if any(
                    cls._normalize_severity(f.get("severity", "info")) == "critical"
                    for f in critical_findings
                )
                else "high"
            )
            assessment.pii_types = sorted(pii_types_found)
            assessment.breach_type = cls._classify_breach(
                pii_types_found, critical_findings
            )
            assessment.description = cls._build_description(
                critical_findings, pii_types_found
            )
            assessment.data_subjects_estimate = cls._estimate_subjects(
                critical_findings
            )
            reasons.append(
                f"{len(critical_findings)} high/critical finding(s) with PII exposure detected"
            )
            reasons.append(f"PII types affected: {', '.join(sorted(pii_types_found))}")

        assessment.reasons = reasons
        return assessment

    @classmethod
    def generate_notification_text(
        cls,
        breach_assessment: BreachAssessment,
        organization_name: str = "",
        contact_info: str = "",
    ) -> str:
        """Generate breach notification text per Pasal 46 UU PDP requirements.

        Must include:
        - Deskripsi kegagalan pelindungan data
        - Jenis data pribadi yang terpengaruh
        - Periode dan perkiraan jumlah data subjek
        - Tindakan yang telah/sedang dilakukan
        - Cara menghubungi controller
        """
        now = datetime.now(timezone.utc).strftime("%d %B %Y %H:%M WIB")

        sections = [
            "NOTIFIKASI KEGAGALAN PELINDUNGAN DATA PRIBADI",
            "=" * 50,
            "",
            "Kepada Yth. Badan Pelindungan Data Pribadi",
            "dengan hormat,",
            "",
            f"Bersama ini {organization_name or 'Kami'} menyampaikan notifikasi "
            f"kegagalan pelindungan data pribadi sesuai Pasal 46 UU No. 27 Tahun 2022.",
            "",
            "---",
            "1. DESKRIPSI KEGAGALAN PELINDUNGAN DATA",
            "---",
            f"{breach_assessment.description}",
            f"Jenis pelanggaran: {breach_assessment.breach_type}",
            f"Tingkat keparahan: {breach_assessment.severity.upper()}",
            "",
            "---",
            "2. JENIS DATA PRIBADI YANG TERPENGARUH",
            "---",
        ]

        if breach_assessment.pii_types:
            for pii_type in breach_assessment.pii_types:
                label = cls._get_pii_label(pii_type)
                sections.append(f"  - {label}")
        else:
            sections.append("  - Belum teridentifikasi secara detail")

        sections.extend(
            [
                "",
                "---",
                "3. PERIODE DAN ESTIMASI JUMLAH DATA SUBJEK",
                "---",
                f"Estimasi jumlah data subjek terdampak: "
                f"{breach_assessment.data_subjects_estimate} subjek",
                f"Waktu notifikasi dibuat: {now}",
                "",
                "---",
                "4. TINDAKAN YANG TELAH / SEDANG DILAKUKAN",
                "---",
                "  - Investigasi mendalam sedang berlangsung",
                "  - Langkah mitigasi segera diterapkan",
                "  - Monitoring sistem ditingkatkan",
                "  - Tim respons insiden telah diaktifkan",
            ]
        )

        if contact_info:
            sections.extend(
                [
                    "",
                    "---",
                    "5. CARA MENGHUBUNGI CONTROLLER",
                    "---",
                    contact_info,
                ]
            )
        else:
            sections.extend(
                [
                    "",
                    "---",
                    "5. CARA MENGHUBUNGI CONTROLLER",
                    "---",
                    f"Hubungi tim privasi data {organization_name or 'kami'} "
                    f"melalui saluran resmi yang tersedia.",
                ]
            )

        sections.extend(
            [
                "",
                "=" * 50,
                "Notifikasi ini dibuat secara otomatis oleh ShieldPDP (NyuunSewu) "
                f"pada {now} sebagai bagian dari kepatuhan UU PDP Pasal 46.",
            ]
        )

        return "\n".join(sections)

    @classmethod
    def check_sla_compliance(
        cls,
        detected_at: datetime,
        notified_at: datetime | None = None,
    ) -> SLAStatus:
        """Check if notification was sent within 3x24 jam SLA.

        Args:
            detected_at: When the breach was first detected.
            notified_at: When the notification was sent (None if not yet sent).

        Returns:
            SLAStatus with compliance information.
        """
        # Ensure timezone-aware datetimes
        if detected_at.tzinfo is None:
            detected_at = detected_at.replace(tzinfo=timezone.utc)

        sla_deadline = detected_at + timedelta(hours=cls.NOTIFICATION_DEADLINE_HOURS)
        now = datetime.now(timezone.utc)

        if notified_at is not None and notified_at.tzinfo is None:
            notified_at = notified_at.replace(tzinfo=timezone.utc)

        if notified_at is not None:
            is_compliant = notified_at <= sla_deadline
            hours_remaining = 0.0
        else:
            time_left = (sla_deadline - now).total_seconds() / 3600
            hours_remaining = max(0, time_left)
            is_compliant = hours_remaining > 0

        return SLAStatus(
            breach_id="",  # Will be filled by caller
            detected_at=detected_at,
            sla_deadline=sla_deadline,
            notified_at=notified_at,
            is_compliant=is_compliant,
            hours_remaining=round(hours_remaining, 1),
            is_overdue=not is_compliant,
        )

    @classmethod
    def build_telegram_message(
        cls,
        breach_assessment: BreachAssessment,
        organization_name: str = "",
    ) -> str:
        """Build a concise Telegram alert message for urgent breach notifications."""
        severity_emoji = {
            "critical": "🚨",
            "high": "⚠️",
            "medium": "⚡",
            "low": "ℹ️",
            "info": "📋",
        }
        emoji = severity_emoji.get(
            cls._normalize_severity(breach_assessment.severity), "📋"
        )

        lines = [
            f"{emoji} <b>BREACH NOTIFICATION REQUIRED</b>",
            "",
            f"<b>Organization:</b> {organization_name or 'N/A'}",
            f"<b>Severity:</b> {breach_assessment.severity.upper()}",
            f"<b>Type:</b> {breach_assessment.breach_type or 'Data breach'}",
            f"<b>Findings:</b> {len(breach_assessment.finding_ids)}",
            f"<b>PII Types:</b> {', '.join(breach_assessment.pii_types) or 'N/A'}",
            f"<b>Est. Subjects:</b> {breach_assessment.data_subjects_estimate}",
            "",
            f"⏰ <b>SLA:</b> {cls.NOTIFICATION_DEADLINE_HOURS} hours from detection",
            "",
            "<i>Per Pasal 46 UU PDP: Notifikasi wajib dalam 3x24 jam.</i>",
        ]
        return "\n".join(lines)

    @classmethod
    async def send_telegram_notification(
        cls,
        message: str,
        bot_token: str | None = None,
        chat_id: str | None = None,
    ) -> dict[str, Any]:
        """Send a breach notification via Telegram bot.

        Args:
            message: HTML-formatted message text.
            bot_token: Telegram bot token (falls back to config if None).
            chat_id: Telegram chat ID (falls back to config if None).

        Returns:
            Dict with success status and Telegram response data.
        """
        import aiohttp

        settings = get_settings()
        token = bot_token or settings.telegram_bot_token
        target_chat_id = chat_id or settings.telegram_chat_id

        if not token or not target_chat_id:
            logger.warning(
                "Telegram not configured: bot_token=%s, chat_id=%s",
                "set" if token else "missing",
                "set" if target_chat_id else "missing",
            )
            return {
                "success": False,
                "channel": "telegram",
                "error": "Telegram bot token or chat ID not configured",
            }

        url = f"https://api.telegram.org/bot{token}/sendMessage"
        payload = {
            "chat_id": target_chat_id,
            "text": message,
            "parse_mode": "HTML",
        }

        try:
            async with aiohttp.ClientSession() as session:
                async with session.post(
                    url, json=payload, timeout=aiohttp.ClientTimeout(total=15)
                ) as resp:
                    data = await resp.json()
                    if resp.status == 200:
                        logger.info("Telegram notification sent successfully")
                        return {
                            "success": True,
                            "channel": "telegram",
                            "response": data,
                        }
                    else:
                        logger.error("Telegram API error: %s - %s", resp.status, data)
                        return {
                            "success": False,
                            "channel": "telegram",
                            "error": f"Telegram API {resp.status}: {data}",
                        }
        except Exception as e:
            logger.error("Failed to send Telegram notification: %s", e)
            return {"success": False, "channel": "telegram", "error": str(e)}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _normalize_severity(severity: str) -> str:
        """Normalize severity to lowercase to match Severity enum values."""
        return (severity or "info").lower().strip()

    @classmethod
    def _extract_pii_types(
        cls, evidence: dict[str, Any], finding_type: str
    ) -> set[str]:
        """Extract PII types from evidence summary and finding type."""
        pii_types: set[str] = set()

        # Check finding type for PII hints
        if "pii" in finding_type.lower():
            pii_types.add("pii_general")

        # Search evidence for data indicators
        evidence_str = str(evidence).lower()
        for pii_type, keywords in DATA_INDICATOR_MAP.items():
            for keyword in keywords:
                if keyword.lower() in evidence_str:
                    pii_types.add(pii_type)
                    break

        return pii_types

    @staticmethod
    def _classify_breach(pii_types: set[str], findings: list[dict[str, Any]]) -> str:
        """Classify the breach type based on affected PII."""
        sensitive_types = {
            "nik",
            "npwp",
            "card_number",
            "biometric",
            "bank_account_number",
        }
        financial_types = {
            "card_number",
            "transaction_history",
            "loan_data",
            "bank_account_number",
        }

        if pii_types & sensitive_types and pii_types & financial_types:
            return "Comprehensive data breach (identity + financial)"
        if pii_types & sensitive_types:
            return "Sensitive identity data breach"
        if pii_types & financial_types:
            return "Financial data breach"
        if "password" in pii_types or "token" in pii_types:
            return "Credential exposure breach"
        if pii_types:
            return "Personal data exposure"
        return "Potential data breach"

    @staticmethod
    def _build_description(findings: list[dict[str, Any]], pii_types: set[str]) -> str:
        """Build a human-readable breach description."""
        count = len(findings)
        finding_types = list({f.get("finding_type", "unknown") for f in findings})
        pii_list = sorted(pii_types)

        description = (
            f"Terdeteksi {count} temuan kerentanan yang mengakibatkan "
            f"eksposur data pribadi. "
            f"Jenis kerentanan: {', '.join(finding_types[:5])}. "
            f"Jenis data pribadi yang terpengaruh: {', '.join(pii_list)}. "
            f"Eksposur ini berpotensi mengakibatkan akses tidak sah "
            f"terhadap data pribadi nasabah/pengguna."
        )
        return description

    @staticmethod
    def _estimate_subjects(findings: list[dict[str, Any]]) -> int:
        """Estimate the number of affected data subjects."""
        # Heuristic: based on evidence summary hints
        total = 0
        for f in findings:
            evidence = f.get("evidence_summary", {})
            # Look for explicit counts in evidence
            for key in ("affected_records", "records_count", "data_subjects", "count"):
                if key in evidence:
                    try:
                        total += int(evidence[key])
                    except (ValueError, TypeError):
                        pass

        # If no explicit count, estimate based on finding severity
        if total == 0:
            for f in findings:
                severity = f.get("severity", "info").lower()
                if severity == "critical":
                    total += 1000
                elif severity == "high":
                    total += 500
                elif severity == "medium":
                    total += 100

        return max(total, 1)

    @staticmethod
    def _get_pii_label(pii_type: str) -> str:
        """Get a human-readable label for a PII type."""
        labels = {
            "nik": "Nomor Induk Kependudukan (NIK)",
            "npwp": "Nomor Pokok Wajib Pajak (NPWP)",
            "phone_number": "Nomor Telepon",
            "email": "Alamat Email",
            "bank_account_number": "Nomor Rekening Bank",
            "card_number": "Nomor Kartu Kredit/Debit",
            "transaction_history": "Riwayat Transaksi",
            "loan_data": "Data Pinjaman/Kredit",
            "biometric": "Data Biometrik",
            "customer_id": "Identifikasi Nasabah",
            "address": "Alamat Tempat Tinggal",
            "employment": "Data Pekerjaan dan Penghasilan",
            "health_data": "Data Kesehatan/Asuransi",
            "password": "Kata Sandi",
            "token": "Token Akses",
            "full_name": "Nama Lengkap",
            "pii_general": "Data Pribadi (umum)",
            "uuid": "UUID Pengenal",
            "customer_identifier": "Identifikasi Pelanggan",
            "internal_metadata": "Metadata Internal",
            "api_key": "Kunci API",
            "access_token": "Token Akses",
            "jwt": "JWT Token",
        }
        return labels.get(pii_type, pii_type.replace("_", " ").title())
