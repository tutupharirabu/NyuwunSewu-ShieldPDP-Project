from dataclasses import dataclass


@dataclass(slots=True)
class ComplianceImpact:
    framework: str
    article_or_control: str
    privacy_risk: str
    legal_risk: str
    business_risk: str


class ComplianceMappingEngine:
    """Maps technical findings to audit-friendly control impact statements."""

    UU_PDP_SOURCE = "UU No. 27 Tahun 2022 tentang Pelindungan Data Pribadi"

    def map_finding(self, finding_type: str, pii_types: list[str] | None = None) -> list[ComplianceImpact]:
        normalized = finding_type.lower()
        impacts: list[ComplianceImpact] = []

        if (
            "bola" in normalized
            or "idor" in normalized
            or "broken access" in normalized
            or "access_control_matrix" in normalized
        ):
            impacts.extend(
                [
                    ComplianceImpact(
                        "UU PDP",
                        "Pasal 35",
                        "Personal data may be exposed through unauthorized access paths.",
                        "Potential failure to protect personal data security during processing.",
                        "Customer trust, regulatory inquiry, and breach notification exposure.",
                    ),
                    ComplianceImpact(
                        "OWASP ASVS",
                        "V4 Access Control",
                        "Authorization controls may not enforce object ownership.",
                        "Control evidence may be insufficient for access governance.",
                        "Horizontal privilege escalation risk on sensitive workflows.",
                    ),
                ]
            )
        if "unauthenticated_sensitive_api_exposure" in normalized:
            impacts.append(
                ComplianceImpact(
                    "OWASP ASVS",
                    "V4 Access Control",
                    "Guest-accessible financial and identity response fields indicate a missing access boundary.",
                    "Authorization evidence is inadequate for a regulated personal-data API.",
                    "Unauthorized financial data viewing can create material privacy and trust impact.",
                )
            )
        if "sqli" in normalized or "sql injection" in normalized:
            impacts.extend(
                [
                    ComplianceImpact(
                        "UU PDP",
                        "Pasal 35",
                        "Database-backed personal data could be processed or disclosed unlawfully.",
                        "Security safeguards around stored personal data may be inadequate.",
                        "Data breach, audit deficiency, and service disruption risk.",
                    ),
                    ComplianceImpact(
                        "OWASP ASVS",
                        "V5 Validation, Sanitization and Encoding",
                        "Input validation and query parameterization controls require remediation.",
                        "Application security control failure may affect audit posture.",
                        "High-impact compromise path if data stores contain regulated records.",
                    ),
                ]
            )
        if "path_traversal" in normalized or "path traversal" in normalized:
            impacts.extend(
                [
                    ComplianceImpact(
                        "UU PDP",
                        "Pasal 35",
                        "Server-side file disclosure may expose personal data or security configuration.",
                        "Security safeguards for protected data and supporting systems may be inadequate.",
                        "Disclosure of application or operating-system files can expand breach impact.",
                    ),
                    ComplianceImpact(
                        "OWASP ASVS",
                        "V5 Validation, Sanitization and Encoding / V8 Data Protection",
                        "Path input and file delivery boundaries require remediation.",
                        "Validated disclosure weakens application security control evidence.",
                        "Sensitive file exposure can enable further unauthorized access.",
                    ),
                ]
            )
        if "reflected_html" in normalized or "reflected html" in normalized:
            impacts.append(
                ComplianceImpact(
                    "OWASP ASVS",
                    "V5 Validation, Sanitization and Encoding",
                    "Unencoded response reflection may permit client-side injection risks.",
                    "Input and output encoding controls require validation evidence.",
                    "Session or user-interface trust could be affected if executable injection is possible.",
                )
            )
        if "pii" in normalized or pii_types:
            impacts.extend(
                [
                    ComplianceImpact(
                        "UU PDP",
                        "Pasal 35",
                        "Detected personal data exposure requires security control validation.",
                        "Exposure may indicate inadequate confidentiality safeguards.",
                        "Privacy incident response and remediation workload may increase.",
                    ),
                    ComplianceImpact(
                        "OWASP ASVS",
                        "V8 Data Protection",
                        "Sensitive data exposure controls need verification.",
                        "Privacy-by-design evidence may be incomplete.",
                        "Customer identifiers or regulated data may be overexposed.",
                    ),
                ]
            )
        if "jwt" in normalized or "auth" in normalized:
            impacts.extend(
                [
                    ComplianceImpact(
                        "OWASP ASVS",
                        "V2 Authentication / V3 Session Management",
                        "Authentication token handling may not meet session security expectations.",
                        "Weak session assurance affects audit readiness.",
                        "Account takeover or token replay could affect protected resources.",
                    )
                ]
            )
        if "cors_credentials_misconfiguration" in normalized:
            impacts.append(
                ComplianceImpact(
                    "OWASP ASVS",
                    "V14 Configuration / V8 Data Protection",
                    "Credentialed cross-origin access may expose protected application responses.",
                    "Origin trust configuration requires remediation evidence.",
                    "Untrusted web origins could read user data in an authenticated browser context.",
                )
            )
        if not impacts:
            impacts.append(
                ComplianceImpact(
                    "OWASP ASVS",
                    "V1 Architecture",
                    "Security requirement should be risk-reviewed.",
                    "Control mapping requires analyst confirmation.",
                    "Residual business risk depends on endpoint context.",
                )
            )
        return impacts
