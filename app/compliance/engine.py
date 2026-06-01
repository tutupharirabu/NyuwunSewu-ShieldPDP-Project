from dataclasses import dataclass

# Weighting for compliance scoring (Pasal 35 is the core security obligation).
COMPLIANCE_WEIGHTS: dict[str, float] = {
    "Pasal_20": 1.5,
    "Pasal_22": 1.5,
    "Pasal_35": 2.0,
    "Pasal_46": 1.5,
    "Pasal_57": 1.0,
    "Pasal_67": 1.0,
}

# Score ranges per highest severity finding for an article.
_SCORE_CRITICAL = (0, 20)
_SCORE_HIGH = (25, 45)
_SCORE_MEDIUM = (50, 65)
_SCORE_LOW = (70, 85)
_STATUS_CRITICAL = "non_compliant"
_STATUS_HIGH = "non_compliant"
_STATUS_MEDIUM = "partial"
_STATUS_LOW = "partial"
_STATUS_CLEAN = "compliant"


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

    # ------------------------------------------------------------------
    # Article-specific risk text helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _pasal20_impact(finding_type: str) -> ComplianceImpact:
        return ComplianceImpact(
            "UU PDP",
            "Pasal 20",
            "Processing personal data without valid consent due to broken authentication or authorization controls.",
            "Consent requirements for personal data processing may not be satisfied.",
            "Regulatory scrutiny over consent validity and potential invalidation of processing activities.",
        )

    @staticmethod
    def _pasal22_impact(finding_type: str) -> ComplianceImpact:
        return ComplianceImpact(
            "UU PDP",
            "Pasal 22",
            "Data subject rights to access, correct, or delete personal data may be compromised by broken access controls.",
            "Failure to uphold data subject rights under the Personal Data Protection law.",
            "Legal actions from data subjects whose rights cannot be effectively exercised.",
        )

    @staticmethod
    def _pasal35_impact(finding_type: str) -> ComplianceImpact:
        return ComplianceImpact(
            "UU PDP",
            "Pasal 35",
            "Security safeguards to protect personal data during processing are insufficient or misconfigured.",
            "Obligation to ensure personal data security during processing may not be met.",
            "Regulatory sanctions, audit failures, and loss of operational trust.",
        )

    @staticmethod
    def _pasal46_impact(finding_type: str) -> ComplianceImpact:
        return ComplianceImpact(
            "UU PDP",
            "Pasal 46",
            "Personal data exposure may constitute a data protection failure requiring notification to data subjects and authorities.",
            "Mandatory breach notification obligations may be triggered.",
            "Reputational damage and regulatory response costs from public disclosure of a data incident.",
        )

    @staticmethod
    def _pasal57_impact(finding_type: str) -> ComplianceImpact:
        return ComplianceImpact(
            "UU PDP",
            "Pasal 57",
            "Administrative sanctions may be imposed for non-compliance with personal data protection obligations.",
            "Risk of administrative penalties including written warnings, processing suspension, or data erasure orders.",
            "Operational disruption and compliance remediation costs from regulatory enforcement.",
        )

    @staticmethod
    def _pasal67_impact(finding_type: str) -> ComplianceImpact:
        return ComplianceImpact(
            "UU PDP",
            "Pasal 67",
            "Exposure of personal data may result in administrative fines up to 2% of annual revenue.",
            "High-severity findings involving personal data carry significant financial penalty exposure.",
            "Direct financial impact from regulatory fines proportional to organizational revenue.",
        )

    # ------------------------------------------------------------------
    # Finding-type classification helpers
    # ------------------------------------------------------------------

    @staticmethod
    def _is_access_control(normalized: str) -> bool:
        return (
            "bola" in normalized
            or "idor" in normalized
            or "broken access" in normalized
            or "access_control_matrix" in normalized
        )

    @staticmethod
    def _is_unauthenticated_api(normalized: str) -> bool:
        return "unauthenticated_sensitive_api_exposure" in normalized

    @staticmethod
    def _is_sqli(normalized: str) -> bool:
        return "sqli" in normalized or "sql injection" in normalized

    @staticmethod
    def _is_path_traversal(normalized: str) -> bool:
        return "path_traversal" in normalized or "path traversal" in normalized

    @staticmethod
    def _is_reflected_html(normalized: str) -> bool:
        return "reflected_html" in normalized or "reflected html" in normalized

    @staticmethod
    def _is_pii(normalized: str) -> bool:
        return "pii" in normalized

    @staticmethod
    def _is_jwt_auth(normalized: str) -> bool:
        return "jwt" in normalized or "auth" in normalized

    @staticmethod
    def _is_cors(normalized: str) -> bool:
        return "cors_credentials_misconfiguration" in normalized

    # ------------------------------------------------------------------
    # Main mapping logic
    # ------------------------------------------------------------------

    def map_finding(
        self, finding_type: str, pii_types: list[str] | None = None
    ) -> list[ComplianceImpact]:
        normalized = finding_type.lower()
        impacts: list[ComplianceImpact] = []

        has_pii_context = self._is_pii(normalized) or bool(pii_types)

        # --- Access control violations (BOLA/IDOR) ---
        if self._is_access_control(normalized):
            impacts.extend(
                [
                    self._pasal22_impact(normalized),
                    self._pasal35_impact(normalized),
                    self._pasal46_impact(normalized),
                    self._pasal57_impact(normalized),
                    ComplianceImpact(
                        "OWASP ASVS",
                        "V4 Access Control",
                        "Authorization controls may not enforce object ownership.",
                        "Control evidence may be insufficient for access governance.",
                        "Horizontal privilege escalation risk on sensitive workflows.",
                    ),
                ]
            )
            if has_pii_context:
                impacts.append(self._pasal67_impact(normalized))

        # --- Unauthenticated API exposure ---
        if self._is_unauthenticated_api(normalized):
            impacts.extend(
                [
                    self._pasal20_impact(normalized),
                    self._pasal35_impact(normalized),
                    self._pasal46_impact(normalized),
                    self._pasal57_impact(normalized),
                    ComplianceImpact(
                        "OWASP ASVS",
                        "V4 Access Control",
                        "Guest-accessible financial and identity response fields indicate a missing access boundary.",
                        "Authorization evidence is inadequate for a regulated personal-data API.",
                        "Unauthorized financial data viewing can create material privacy and trust impact.",
                    ),
                ]
            )
            if has_pii_context:
                impacts.append(self._pasal67_impact(normalized))

        # --- SQL Injection ---
        if self._is_sqli(normalized):
            impacts.extend(
                [
                    self._pasal35_impact(normalized),
                    self._pasal46_impact(normalized),
                    self._pasal57_impact(normalized),
                    ComplianceImpact(
                        "OWASP ASVS",
                        "V5 Validation, Sanitization and Encoding",
                        "Input validation and query parameterization controls require remediation.",
                        "Application security control failure may affect audit posture.",
                        "High-impact compromise path if data stores contain regulated records.",
                    ),
                ]
            )
            if has_pii_context:
                impacts.append(self._pasal67_impact(normalized))

        # --- Path Traversal ---
        if self._is_path_traversal(normalized):
            impacts.extend(
                [
                    self._pasal35_impact(normalized),
                    self._pasal46_impact(normalized),
                    self._pasal57_impact(normalized),
                    ComplianceImpact(
                        "OWASP ASVS",
                        "V5 Validation, Sanitization and Encoding / V8 Data Protection",
                        "Path input and file delivery boundaries require remediation.",
                        "Validated disclosure weakens application security control evidence.",
                        "Sensitive file exposure can enable further unauthorized access.",
                    ),
                ]
            )
            if has_pii_context:
                impacts.append(self._pasal67_impact(normalized))

        # --- Reflected HTML (XSS-style) ---
        if self._is_reflected_html(normalized):
            impacts.extend(
                [
                    self._pasal35_impact(normalized),
                    self._pasal57_impact(normalized),
                    ComplianceImpact(
                        "OWASP ASVS",
                        "V5 Validation, Sanitization and Encoding",
                        "Unencoded response reflection may permit client-side injection risks.",
                        "Input and output encoding controls require validation evidence.",
                        "Session or user-interface trust could be affected if executable injection is possible.",
                    ),
                ]
            )

        # --- PII exposure ---
        # Only add UU PDP article impacts if no other branch already covered them.
        # Always add the OWASP V8 mapping and Pasal 67 (when pii_types provided).
        if has_pii_context:
            # Determine which articles are already covered.
            covered_uu_pdp = {
                imp.article_or_control for imp in impacts if imp.framework == "UU PDP"
            }
            for article_impact in [
                self._pasal35_impact(normalized),
                self._pasal46_impact(normalized),
                self._pasal57_impact(normalized),
            ]:
                if article_impact.article_or_control not in covered_uu_pdp:
                    impacts.append(article_impact)
                    covered_uu_pdp.add(article_impact.article_or_control)
            impacts.append(
                ComplianceImpact(
                    "OWASP ASVS",
                    "V8 Data Protection",
                    "Sensitive data exposure controls need verification.",
                    "Privacy-by-design evidence may be incomplete.",
                    "Customer identifiers or regulated data may be overexposed.",
                )
            )
            if pii_types:
                pasal67 = "Pasal 67"
                if pasal67 not in covered_uu_pdp:
                    impacts.append(self._pasal67_impact(normalized))

        # --- JWT / Authentication ---
        if self._is_jwt_auth(normalized):
            impacts.extend(
                [
                    self._pasal20_impact(normalized),
                    self._pasal35_impact(normalized),
                    self._pasal57_impact(normalized),
                    ComplianceImpact(
                        "OWASP ASVS",
                        "V2 Authentication / V3 Session Management",
                        "Authentication token handling may not meet session security expectations.",
                        "Weak session assurance affects audit readiness.",
                        "Account takeover or token replay could affect protected resources.",
                    ),
                ]
            )

        # --- CORS misconfiguration ---
        if self._is_cors(normalized):
            impacts.extend(
                [
                    self._pasal20_impact(normalized),
                    self._pasal35_impact(normalized),
                    self._pasal46_impact(normalized),
                    self._pasal57_impact(normalized),
                    ComplianceImpact(
                        "OWASP ASVS",
                        "V14 Configuration / V8 Data Protection",
                        "Credentialed cross-origin access may expose protected application responses.",
                        "Origin trust configuration requires remediation evidence.",
                        "Untrusted web origins could read user data in an authenticated browser context.",
                    ),
                ]
            )

        # --- Fallback for unmapped finding types ---
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

    # ------------------------------------------------------------------
    # Compliance scoring
    # ------------------------------------------------------------------

    def calculate_compliance_score(self, findings: list[dict]) -> dict:
        """Calculate an overall compliance score from a list of findings.

        Each finding dict should contain at least:
            - "type": str — passed to ``map_finding`` to determine impacted articles
            - "severity": str — one of "critical", "high", "medium", "low", "info"

        Returns a dict with article-level and overall scores.
        """
        article_findings: dict[str, list[dict]] = {
            "Pasal_20": [],
            "Pasal_22": [],
            "Pasal_35": [],
            "Pasal_46": [],
            "Pasal_57": [],
            "Pasal_67": [],
        }

        for finding in findings:
            finding_type = finding.get("type", "")
            pii_types = finding.get("pii_types")
            impacts = self.map_finding(finding_type, pii_types)
            for impact in impacts:
                key = impact.article_or_control.replace(" ", "_")
                if key in article_findings:
                    article_findings[key].append(finding)

        article_scores: dict[str, dict] = {}
        for article, art_findings in article_findings.items():
            article_scores[article] = self._score_article(art_findings)

        # Overall score: weighted average of article scores.
        total_weight = 0.0
        weighted_sum = 0.0
        for article, score_info in article_scores.items():
            weight = COMPLIANCE_WEIGHTS.get(article, 1.0)
            weighted_sum += score_info["score"] * weight
            total_weight += weight

        overall_score = (
            round(weighted_sum / total_weight, 2) if total_weight > 0 else 100.0
        )

        compliant_count = sum(
            1 for s in article_scores.values() if s["status"] == "compliant"
        )
        non_compliant_count = sum(
            1 for s in article_scores.values() if s["status"] == "non_compliant"
        )

        return {
            "overall_score": overall_score,
            "article_scores": article_scores,
            "total_findings": len(findings),
            "compliant_articles": compliant_count,
            "non_compliant_articles": non_compliant_count,
        }

    @staticmethod
    def _score_article(art_findings: list[dict]) -> dict:
        """Score a single article based on the highest severity finding."""
        if not art_findings:
            return {
                "score": 100.0,
                "status": _STATUS_CLEAN,
                "finding_count": 0,
                "critical_count": 0,
            }

        severity_order = ["critical", "high", "medium", "low", "info"]
        highest = "info"
        for finding in art_findings:
            sev = finding.get("severity", "info").lower()
            if sev in severity_order and severity_order.index(
                sev
            ) < severity_order.index(highest):
                highest = sev

        critical_count = sum(
            1 for f in art_findings if f.get("severity", "info").lower() == "critical"
        )
        finding_count = len(art_findings)

        score_range, status = {
            "critical": (_SCORE_CRITICAL, _STATUS_CRITICAL),
            "high": (_SCORE_HIGH, _STATUS_HIGH),
            "medium": (_SCORE_MEDIUM, _STATUS_MEDIUM),
            "low": (_SCORE_LOW, _STATUS_LOW),
            "info": (_SCORE_LOW, _STATUS_LOW),
        }[highest]

        lo, hi = score_range
        score = round((lo + hi) / 2, 2)

        return {
            "score": score,
            "status": status,
            "finding_count": finding_count,
            "critical_count": critical_count,
        }
