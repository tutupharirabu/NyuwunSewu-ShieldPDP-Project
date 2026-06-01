import math
import re
from dataclasses import dataclass
from datetime import date

from app.utils.redaction import redact_text


@dataclass(slots=True)
class PIIDetection:
    pii_type: str
    sensitivity: str
    confidence: int
    excerpt: str
    reasoning: list[str]


class PIIDetectionEngine:
    INDONESIAN_PROVINCE_CODES = {
        11, 12, 13, 14, 15, 16, 17, 18, 19, 21,
        31, 32, 33, 34, 35, 36,
        51, 52, 53,
        61, 62, 63, 64, 65,
        71, 72, 73, 74, 75, 76,
        81, 82,
        91, 92, 93, 94, 95,
    }
    TEST_CARD_NUMBERS = {
        "4111111111111111",
        "4242424242424242",
        "4000000000000002",
        "5555555555554444",
        "5105105105105100",
        "378282246310005",
        "371449635398431",
        "6011111111111117",
    }
    DUMMY_NUMERIC_RE = re.compile(r"^(?:0+|1+|2+|3+|4+|5+|6+|7+|8+|9+|1234567890+|0123456789+)$")
    PATTERNS: list[tuple[str, re.Pattern[str], str, int]] = [
        ("email", re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.I), "MEDIUM", 72),
        ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\b"), "HIGH", 92),
        ("api_key", re.compile(r"(?i)\b(api[_-]?key|secret[_-]?key)[\"'\s:=]+([A-Za-z0-9_\-]{20,})"), "HIGH", 88),
        ("access_token", re.compile(r"(?i)\b(access[_-]?token|refresh[_-]?token|bearer)[\"'\s:=]+([A-Za-z0-9._\-]{20,})"), "HIGH", 90),
        ("uuid", re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}\b", re.I), "LOW", 55),
        ("nik", re.compile(r"\b[1-9][0-9]{15}\b"), "HIGH", 74),
        ("npwp", re.compile(r"\b\d{2}\.?\d{3}\.?\d{3}\.?\d[-.]?\d{3}\.?\d{3}\b"), "HIGH", 78),
        ("phone_number", re.compile(r"(?<!\d)(?:\+62|62|0)8[1-9][0-9]{7,11}(?!\d)"), "MEDIUM", 70),
        ("customer_identifier", re.compile(r"(?i)\b(customer|cust|member|client)[_-]?(id|number|no)[\"'\s:=#-]+([A-Za-z0-9\-]{5,})"), "MEDIUM", 68),
        ("internal_metadata", re.compile(r"(?i)\b(trace[_-]?id|request[_-]?id|x-env|x-service|build[_-]?id|commit[_-]?sha)[\"'\s:=]+([A-Za-z0-9._:/\-]{6,})"), "LOW", 62),
    ]
    BANK_PATTERN = re.compile(r"\b\d{10,18}\b")
    BANK_CONTEXT = re.compile(
        r"(?i)(rekening|account|acct|transfer|iban|virtual\s+account|va\b|bca|mandiri|bni|bri|cimb)"
    )

    def entropy(self, value: str) -> float:
        if not value:
            return 0.0
        frequencies = {char: value.count(char) for char in set(value)}
        return -sum((count / len(value)) * math.log2(count / len(value)) for count in frequencies.values())

    def detect(self, content: str) -> list[PIIDetection]:
        detections: list[PIIDetection] = []
        seen: set[tuple[str, str]] = set()
        for pii_type, pattern, sensitivity, base_confidence in self.PATTERNS:
            for match in pattern.finditer(content):
                value = match.group(0)
                confidence = base_confidence
                reasoning = [f"{pii_type} pattern matched"]
                if pii_type == "nik":
                    nik_reasons = self._nik_validation_reasons(value)
                    if not nik_reasons:
                        continue
                    confidence = 88
                    reasoning = nik_reasons
                if pii_type in {"api_key", "access_token"}:
                    token = match.group(match.lastindex or 0)
                    if self.entropy(token) > 3.5:
                        confidence += 6
                        reasoning.append("Token-like value has high entropy")
                if confidence < 50:
                    continue
                key = (pii_type, value)
                if key in seen:
                    continue
                seen.add(key)
                detections.append(
                    PIIDetection(
                        pii_type=pii_type,
                        sensitivity=sensitivity,
                        confidence=min(99, confidence),
                        excerpt=redact_text(value, max_length=120),
                        reasoning=reasoning,
                    )
                )

        for match in self.BANK_PATTERN.finditer(content):
            account_value = match.group(0)
            if self._is_dummy_numeric(account_value) or self._is_test_card(account_value):
                continue
            line_start = content.rfind("\n", 0, match.start()) + 1
            line_end = content.find("\n", match.end())
            if line_end == -1:
                line_end = len(content)
            context = content[line_start:line_end]
            if self.BANK_CONTEXT.search(context):
                detections.append(
                    PIIDetection(
                        pii_type="bank_account_number",
                        sensitivity="HIGH",
                        confidence=82,
                        excerpt=account_value[:3] + "[REDACTED]" + account_value[-2:],
                        reasoning=["Long numeric identifier appeared near bank-account context keywords"],
                    )
                )
        return detections

    def _looks_like_nik(self, value: str) -> bool:
        return bool(self._nik_validation_reasons(value))

    def _nik_validation_reasons(self, value: str) -> list[str]:
        if len(value) != 16 or not value.isdigit():
            return []
        if self._is_dummy_numeric(value) or self._is_test_card(value):
            return []
        province = int(value[:2])
        regency = int(value[2:4])
        district = int(value[4:6])
        day_raw = int(value[6:8])
        day = day_raw - 40 if day_raw > 40 else day_raw
        month = int(value[8:10])
        year = int(value[10:12])
        serial = int(value[12:16])
        if province not in self.INDONESIAN_PROVINCE_CODES:
            return []
        if regency <= 0 or district <= 0 or serial <= 0:
            return []
        if not self._valid_birth_date(day, month, year):
            return []
        return [
            "16-digit Indonesian NIK structure matched",
            "Province code is in the Indonesian administrative code range",
            "Birth date segment is calendar-valid, including female day offset when present",
            "Regency, district, and serial segments are non-zero",
        ]

    def _valid_birth_date(self, day: int, month: int, year: int) -> bool:
        if not (1 <= day <= 31 and 1 <= month <= 12):
            return False
        for century in (1900, 2000):
            try:
                candidate = date(century + year, month, day)
            except ValueError:
                continue
            if 1900 <= candidate.year <= date.today().year:
                return True
        return False

    def _is_dummy_numeric(self, value: str) -> bool:
        if len(set(value)) <= 2:
            return True
        if self.DUMMY_NUMERIC_RE.fullmatch(value):
            return True
        return value in {"1234567890123456", "0000000000000000", "9999999999999999"}

    def _is_test_card(self, value: str) -> bool:
        if value in self.TEST_CARD_NUMBERS:
            return True
        return value.startswith(("4", "5", "34", "37", "6011")) and self._luhn_valid(value)

    def _luhn_valid(self, value: str) -> bool:
        total = 0
        reverse_digits = [int(char) for char in reversed(value) if char.isdigit()]
        for index, digit in enumerate(reverse_digits):
            if index % 2:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        return bool(reverse_digits) and total % 10 == 0
