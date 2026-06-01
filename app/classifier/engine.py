import re
from dataclasses import dataclass
from urllib.parse import parse_qs, urlparse


@dataclass(slots=True)
class ClassificationResult:
    classification: str
    confidence: int
    risk: str
    risk_score: float
    reasoning: list[str]


class EndpointClassifier:
    RULES: dict[str, list[tuple[re.Pattern[str], int, str]]] = {
        "auth": [
            (re.compile(r"\b(login|logout|signin|signup|oauth|token|session|password|mfa)\b", re.I), 35, "Authentication keyword"),
            (re.compile(r"\b(jwt|refresh|otp)\b", re.I), 25, "Token lifecycle keyword"),
        ],
        "admin": [
            (re.compile(r"\b(admin|root|manage|superuser|privilege|role|permission)\b", re.I), 45, "Administrative path keyword"),
        ],
        "pii": [
            (re.compile(r"\b(profile|customer|user|member|identity|personal|address|phone|email|nik|npwp)\b", re.I), 34, "Personal data keyword"),
        ],
        "upload": [
            (re.compile(r"\b(upload|import|file|avatar|document|attachment|media)\b", re.I), 30, "File handling keyword"),
        ],
        "financial": [
            (re.compile(r"\b(payment|transfer|invoice|billing|wallet|bank|rekening|card|loan)\b", re.I), 45, "Financial workflow keyword"),
        ],
        "sensitive": [
            (re.compile(r"\b(secret|key|credential|config|backup|export|download|audit|report)\b", re.I), 36, "Sensitive data keyword"),
        ],
        "internal API": [
            (re.compile(r"\b(internal|private|debug|actuator|health|metrics|graphql)\b", re.I), 40, "Internal or operational API keyword"),
        ],
        "public API": [
            (re.compile(r"(^|/)api(/|$)|/v[0-9]+/", re.I), 24, "API route structure"),
        ],
    }

    def classify(self, url: str, method: str = "GET", forms: list[dict] | None = None) -> list[ClassificationResult]:
        parsed = urlparse(url)
        haystack = " ".join(
            [
                parsed.path,
                " ".join(parse_qs(parsed.query).keys()),
                method,
                " ".join(field.get("name", "") for form in (forms or []) for field in form.get("fields", [])),
            ]
        )

        results: list[ClassificationResult] = []
        for label, rules in self.RULES.items():
            score = 0
            reasoning: list[str] = []
            for pattern, weight, reason in rules:
                if pattern.search(haystack):
                    score += weight
                    reasoning.append(reason)

            if label in {"admin", "financial", "sensitive", "pii"} and method.upper() != "GET":
                score += 8
                reasoning.append("State-changing method increases endpoint sensitivity")
            if parse_qs(parsed.query):
                score += 6
                reasoning.append("Endpoint accepts query parameters")
            if forms:
                score += 8
                reasoning.append("Endpoint exposes HTML form inputs")

            if score > 0:
                confidence = min(99, score + 25)
                risk_score = min(100.0, score * 1.4)
                risk = "high" if risk_score >= 70 else "medium" if risk_score >= 40 else "low"
                results.append(ClassificationResult(label, confidence, risk, risk_score, reasoning))

        if not results:
            results.append(
                ClassificationResult(
                    "public API" if "/api/" in parsed.path.lower() else "public",
                    45,
                    "low",
                    15.0,
                    ["No sensitive heuristic matched; classified as public surface"],
                )
            )
        return sorted(results, key=lambda item: item.risk_score, reverse=True)

