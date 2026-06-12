from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from datetime import datetime, timezone
from http import HTTPStatus
from typing import Any
from urllib.parse import urlparse

from jinja2 import Environment, PackageLoader, select_autoescape

from app.core.security import stable_hash
from app.models import Finding, Report
from app.reporting.formatting import SEVERITY_ORDER, format_datetime
from app.reporting.pdf_builder import PDFReportBuilder
from app.utils.redaction import redact_headers, redact_text, sanitize_json

EXPLOIT_KEYWORDS = (
    "exploit",
    "jwt",
    "xss",
    "sqli",
    "bola",
    "idor",
    "ssrf",
    "cors",
    "graphql",
    "oauth",
    "webhook",
    "package",
    "pipeline",
    "virtual_card",
    "bill",
    "merchant",
    "token",
    "privilege",
    "enumeration",
)
DISCOVERY_ONLY_TYPES = {
    "internal_api_discovery",
    "protected_internal_surface",
    "segmentation_exposure",
    "graphql_schema_exposure",
    "modern_vuln_bank_attack_surface",
    "jwt_observed",
}
REGEX_ONLY_MODES = {
    "static_javascript_analysis",
    "passive_endpoint_discovery",
    "passive_metadata_discovery",
}
CONFIRMED_EXPLOIT_TYPES = {
    "jwt_privilege_escalation_execution",
    "jwt_claim_integrity_bypass",
    "jwt_forge_endpoint_exposed",
    "sqli_auth_bypass",
    "ssrf_inband_url_fetch",
    "negative_amount_business_logic",
}
HTTP_EVIDENCE_PREVIEW_LIMIT = 6000
NO_REQUEST_EVIDENCE = "No captured HTTP request evidence was stored for this finding."
NO_RESPONSE_EVIDENCE = "No captured HTTP response evidence was stored for this finding."


class ReportingEngine:
    def __init__(self):
        self.env = Environment(
            loader=PackageLoader("app", "templates"),
            autoescape=select_autoescape(["html", "xml"]),
        )
        self.env.filters["datetime"] = self._format_datetime
        self.env.filters["compact"] = self._compact_id
        self.env.filters["json_preview"] = self._json_preview

    def render_html(
        self,
        *,
        title: str,
        findings: list[Finding],
        report_type: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        report = self.build_report_data(
            title=title,
            findings=findings,
            report_type=report_type,
            context=context,
        )
        template = self.env.get_template("report.html")
        return template.render(**report)

    def render_pdf_from_context(
        self,
        *,
        title: str,
        findings: list[Finding],
        report_type: str,
        context: dict[str, Any] | None = None,
    ) -> str:
        report = self.build_report_data(
            title=title,
            findings=findings,
            report_type=report_type,
            context=context,
        )
        return PDFReportBuilder(report).render().decode("latin-1")

    def render_pdf(self, html: str) -> str:
        text = re.sub(r"<[^>]+>", " ", html)
        text = re.sub(r"\s+", " ", text).strip()
        report = {
            "title": "NyuwunSewu Report",
            "report_type": "Security Validation Report",
            "generated_at": datetime.now(timezone.utc),
            "summary": {
                "total_findings": 0,
                "endpoint_count": 0,
                "max_risk_score": 0,
                "compliance_control_count": 0,
                "critical_high_count": 0,
            },
            "severity_counts": {},
            "scope": {},
            "endpoint_rows": [],
            "exploit_findings": [],
            "compliance_rows": [],
            "remediation_matrix": [],
            "finding_details": [{"title": "Report Content", "description": text[:4000]}]
            if text
            else [],
        }
        return PDFReportBuilder(report).render().decode("latin-1")

    def build_report_data(
        self,
        *,
        title: str,
        findings: list[Finding],
        report_type: str,
        context: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        context = context or {}
        endpoints = list(context.get("endpoints") or [])
        endpoint_lookup = {endpoint.id: endpoint for endpoint in endpoints}
        evidence_by_finding_id = context.get("evidence_by_finding_id") or {}
        findings_by_endpoint: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            if finding.endpoint_id:
                findings_by_endpoint[finding.endpoint_id].append(finding)

        executive_findings = [
            finding for finding in findings if self._executive_eligible(finding)
        ]
        severity_counts = Counter(
            (finding.severity or "info").lower() for finding in executive_findings
        )
        compliance_rows = self._compliance_rows(findings)
        endpoint_rows = self._endpoint_rows(endpoints, findings_by_endpoint)
        finding_details = self._finding_details(
            findings, endpoint_lookup, evidence_by_finding_id
        )
        exploit_findings = [
            detail for detail in finding_details if self._is_exploit_finding(detail)
        ]
        remediation_matrix = self._build_remediation_matrix(findings)
        max_risk = max(
            (float(finding.risk_score or 0) for finding in executive_findings),
            default=0.0,
        )
        avg_confidence = (
            sum(float(finding.confidence or 0) for finding in executive_findings)
            / len(executive_findings)
            if executive_findings
            else 0.0
        )
        scope = self._scope(context, endpoint_rows, findings)

        return {
            "title": title,
            "report_type": report_type,
            "generated_at": datetime.now(timezone.utc),
            "summary": {
                "total_findings": len(executive_findings),
                "all_findings": len(findings),
                "endpoint_count": len(endpoints),
                "parameter_count": sum(len(row["parameters"]) for row in endpoint_rows),
                "max_risk_score": round(max_risk, 1),
                "average_confidence": round(avg_confidence, 1),
                "critical_high_count": severity_counts["critical"]
                + severity_counts["high"],
                "exploit_count": len(exploit_findings),
                "compliance_control_count": len(compliance_rows),
            },
            "severity_counts": {
                severity: severity_counts.get(severity, 0)
                for severity in SEVERITY_ORDER
            },
            "scope": scope,
            "endpoint_rows": endpoint_rows,
            "endpoint_row_limit": 500,
            "exploit_findings": exploit_findings,
            "compliance_rows": compliance_rows,
            "remediation_matrix": remediation_matrix,
            "finding_details": finding_details,
            "severity_order": SEVERITY_ORDER,
        }

    def build_report_row(
        self,
        *,
        organization_id: str,
        project_id: str,
        scan_id: str | None,
        generated_by_id: str | None,
        report_type: str,
        export_format: str,
        title: str,
        content: str,
    ) -> Report:
        return Report(
            organization_id=organization_id,
            project_id=project_id,
            scan_id=scan_id,
            generated_by_id=generated_by_id,
            report_type=report_type,
            export_format=export_format,
            title=title,
            content=content,
            report_hash=stable_hash(
                {"title": title, "content": content, "type": report_type}
            ),
        )

    def _scope(
        self,
        context: dict[str, Any],
        endpoint_rows: list[dict[str, Any]],
        findings: list[Finding],
    ) -> dict[str, Any]:
        project = context.get("project")
        target = context.get("target")
        scan = context.get("scan")
        policy = context.get("policy")
        generated_by = context.get("generated_by")
        stats = getattr(scan, "stats", None) or {}
        unique_paths = sorted({row["path"] for row in endpoint_rows})
        return {
            "project_name": getattr(project, "name", "Project aggregate")
            if project
            else "Project aggregate",
            "project_id": getattr(project, "id", None),
            "target_url": getattr(target, "base_url", None),
            "allowed_domains": getattr(target, "allowed_domains", []) if target else [],
            "scan_id": getattr(scan, "id", None),
            "scan_status": getattr(scan, "status", None),
            "scan_started_at": getattr(scan, "started_at", None),
            "scan_finished_at": getattr(scan, "finished_at", None),
            "scan_created_at": getattr(scan, "created_at", None),
            "scan_error": getattr(scan, "error", None),
            "generated_by": getattr(generated_by, "email", None)
            or getattr(generated_by, "full_name", None),
            "policy_name": getattr(policy, "name", None),
            "policy": {
                "max_requests_per_second": getattr(
                    policy, "max_requests_per_second", None
                ),
                "max_depth": getattr(policy, "max_depth", None),
                "max_pages": getattr(policy, "max_pages", None),
                "allow_sqli_validation": getattr(policy, "allow_sqli_validation", None),
                "allow_auth_validation": getattr(policy, "allow_auth_validation", None),
                "allow_timing_validation": getattr(
                    policy, "allow_timing_validation", None
                ),
                "excluded_paths": getattr(policy, "excluded_paths", [])
                if policy
                else [],
                "forbidden_paths": getattr(policy, "forbidden_paths", [])
                if policy
                else [],
                "scope_boundaries": getattr(policy, "scope_boundaries", [])
                if policy
                else [],
            },
            "stats": stats,
            "paths": unique_paths,
            "path_count": len(unique_paths),
            "finding_types": sorted({finding.finding_type for finding in findings}),
        }

    def _endpoint_rows(
        self,
        endpoints: list[Any],
        findings_by_endpoint: dict[str, list[Finding]],
    ) -> list[dict[str, Any]]:
        rows: list[dict[str, Any]] = []
        severity_rank = {
            severity: score
            for score, severity in enumerate(SEVERITY_ORDER[::-1], start=1)
        }
        for endpoint in endpoints:
            endpoint_findings = findings_by_endpoint.get(endpoint.id, [])
            highest = max(
                (finding.severity for finding in endpoint_findings),
                key=lambda value: severity_rank.get((value or "").lower(), 0),
                default=None,
            )
            parsed = urlparse(endpoint.url)
            path = parsed.path or "/"
            if parsed.query:
                path = f"{path}?{parsed.query}"
            rows.append(
                {
                    "id": endpoint.id,
                    "method": endpoint.method,
                    "url": endpoint.url,
                    "path": path,
                    "status_code": endpoint.status_code,
                    "content_type": endpoint.content_type,
                    "risk_score": round(float(endpoint.risk_score or 0), 1),
                    "parameters": list(endpoint.query_parameters or []),
                    "form_count": len(endpoint.forms or []),
                    "tech_stack": list(endpoint.tech_stack or [])[:8],
                    "classifications": [
                        str(item.get("classification") or "")
                        for item in (endpoint.classifications or [])[:4]
                        if item.get("classification")
                    ],
                    "finding_count": len(endpoint_findings),
                    "highest_severity": highest,
                    "finding_titles": [
                        finding.title for finding in endpoint_findings[:4]
                    ],
                    "finding_types": sorted(
                        {finding.finding_type for finding in endpoint_findings}
                    ),
                }
            )
        return sorted(
            rows,
            key=lambda row: (row["finding_count"], row["risk_score"], row["path"]),
            reverse=True,
        )

    def _finding_details(
        self,
        findings: list[Finding],
        endpoint_lookup: dict[str, Any],
        evidence_by_finding_id: dict[str, Any] | None = None,
    ) -> list[dict[str, Any]]:
        severity_rank = {
            severity: index for index, severity in enumerate(SEVERITY_ORDER)
        }
        ordered = sorted(
            findings,
            key=lambda finding: (
                severity_rank.get((finding.severity or "").lower(), 99),
                -float(finding.risk_score or 0),
                finding.title,
            ),
        )
        details: list[dict[str, Any]] = []
        evidence_by_finding_id = evidence_by_finding_id or {}
        for finding in ordered:
            endpoint = endpoint_lookup.get(finding.endpoint_id or "")
            evidence = finding.evidence_summary or {}
            compliance = self._finding_compliance_items(finding)
            description, impact = self._description_and_impact(
                finding.description, finding.severity
            )
            evidence_record = self._evidence_record_for(
                finding, evidence_by_finding_id
            )
            http_evidence = self._http_evidence(
                evidence=evidence,
                evidence_record=evidence_record,
            )
            deep_compliance = self._deep_compliance_analysis(
                finding=finding,
                endpoint=endpoint,
                compliance=compliance,
                description=description,
                http_evidence=http_evidence,
            )
            details.append(
                {
                    "id": finding.id,
                    "title": finding.title,
                    "finding_type": finding.finding_type,
                    "severity": (finding.severity or "info").lower(),
                    "status": finding.status,
                    "confidence": round(float(finding.confidence or 0), 1),
                    "risk_score": round(float(finding.risk_score or 0), 1),
                    "description": description,
                    "impact": impact,
                    "technical_finding": description or finding.title,
                    "reasoning": list(finding.reasoning or []),
                    "remediation": finding.remediation_guidance,
                    "remediation_steps": self._remediation_steps(
                        finding.remediation_guidance
                    ),
                    "secure_code_example": self._secure_code_example(finding),
                    "compliance": compliance,
                    "compliance_controls": self._compliance_controls(compliance),
                    "compliance_analysis": deep_compliance["summary"],
                    "deep_compliance": deep_compliance,
                    "evidence": evidence,
                    "evidence_id": http_evidence.get("evidence_id"),
                    "evidence_hash": http_evidence.get("evidence_hash"),
                    "http_request": http_evidence["request_text"],
                    "http_response": http_evidence["response_text"],
                    "has_http_request": http_evidence["has_request"],
                    "has_http_response": http_evidence["has_response"],
                    "validation_mode": evidence.get("validation_mode"),
                    "payload": evidence.get("payload"),
                    "endpoint_url": getattr(endpoint, "url", None),
                    "endpoint_path": getattr(endpoint, "normalized_path", None),
                    "method": getattr(endpoint, "method", None),
                    "created_at": finding.created_at,
                    "confidence_level": evidence.get("confidence_level"),
                    "exploitability_assessment": evidence.get(
                        "exploitability_assessment"
                    ),
                    "reproduction_stability": evidence.get("reproduction_stability"),
                    "evidence_quality": evidence.get("evidence_quality"),
                    "false_positive_likelihood": evidence.get(
                        "false_positive_likelihood"
                    ),
                }
            )
        return details

    def _evidence_record_for(
        self, finding: Finding, evidence_by_finding_id: dict[str, Any]
    ) -> Any | None:
        finding_id = getattr(finding, "id", None)
        if finding_id in evidence_by_finding_id:
            return evidence_by_finding_id[finding_id]
        return evidence_by_finding_id.get(str(finding_id))

    def _http_evidence(
        self,
        *,
        evidence: dict[str, Any],
        evidence_record: Any | None,
    ) -> dict[str, Any]:
        record_request = getattr(evidence_record, "raw_request", None) or {}
        record_response = getattr(evidence_record, "raw_response", None) or {}
        summary_request = self._summary_http_part(evidence, "request")
        summary_response = self._summary_http_part(evidence, "response")

        request = record_request or summary_request
        response = record_response or summary_response
        evidence_id = (
            getattr(evidence_record, "immutable_id", None)
            or evidence.get("evidence_id")
        )
        evidence_hash = (
            getattr(evidence_record, "evidence_hash", None)
            or evidence.get("evidence_hash")
        )

        has_request = bool(request)
        has_response = bool(response)
        return {
            "evidence_id": evidence_id,
            "evidence_hash": evidence_hash,
            "has_request": has_request,
            "has_response": has_response,
            "request_text": self._format_http_request(request)
            if has_request
            else NO_REQUEST_EVIDENCE,
            "response_text": self._format_http_response(response)
            if has_response
            else NO_RESPONSE_EVIDENCE,
        }

    def _summary_http_part(
        self, evidence: dict[str, Any], key: str
    ) -> dict[str, Any]:
        direct = evidence.get(key)
        if isinstance(direct, dict):
            return sanitize_json(direct)

        raw = evidence.get(f"raw_{key}")
        if isinstance(raw, dict):
            return sanitize_json(raw)

        nested = evidence.get("evidence")
        if isinstance(nested, dict) and isinstance(nested.get(key), dict):
            return sanitize_json(nested[key])
        return {}

    def _format_http_request(self, request: dict[str, Any]) -> str:
        method = str(request.get("method") or "GET").upper()
        url = str(request.get("url") or request.get("uri") or request.get("path") or "")
        target, host = self._request_target_and_host(url)
        version = str(request.get("http_version") or "HTTP/1.1")
        headers = self._safe_headers(request.get("headers"))
        if host and not any(str(key).lower() == "host" for key in headers):
            headers = {"host": host, **headers}

        lines = [f"{method} {target} {version}"]
        lines.extend(f"{str(key).lower()}: {value}" for key, value in headers.items())
        body = self._body_preview(
            request.get("body")
            if request.get("body") is not None
            else request.get("body_sample")
        )
        if body:
            lines.extend(["", body])
        return "\n".join(lines)

    def _format_http_response(self, response: dict[str, Any]) -> str:
        version = str(response.get("http_version") or "HTTP/1.1")
        status = response.get("status") or response.get("status_code") or "N/A"
        reason = str(response.get("reason") or self._reason_phrase(status))
        status_line = f"{version} {status} {reason}".strip()
        headers = self._safe_headers(response.get("headers"))

        lines = [status_line]
        lines.extend(f"{str(key).lower()}: {value}" for key, value in headers.items())
        body = self._body_preview(
            response.get("body_sample")
            if response.get("body_sample") is not None
            else response.get("body")
        )
        if body:
            lines.extend(["", body])
        return "\n".join(lines)

    def _request_target_and_host(self, url: str) -> tuple[str, str]:
        parsed = urlparse(url)
        if parsed.scheme and parsed.netloc:
            target = parsed.path or "/"
            if parsed.query:
                target = f"{target}?{parsed.query}"
            return target, parsed.netloc
        if url:
            return url, ""
        return "/", ""

    def _safe_headers(self, headers: Any) -> dict[str, str]:
        if not isinstance(headers, dict):
            return {}
        return {
            str(key): str(value)
            for key, value in redact_headers(headers).items()
            if value is not None
        }

    def _body_preview(self, value: Any) -> str:
        if value in (None, ""):
            return ""
        if isinstance(value, (dict, list)):
            text = json.dumps(sanitize_json(value), indent=2, sort_keys=True)
        else:
            text = str(value)
        preview = redact_text(text, max_length=HTTP_EVIDENCE_PREVIEW_LIMIT)
        if len(text) > HTTP_EVIDENCE_PREVIEW_LIMIT:
            preview = f"{preview}\n...[truncated for report]"
        return preview

    def _reason_phrase(self, status: Any) -> str:
        try:
            return HTTPStatus(int(status)).phrase
        except (TypeError, ValueError):
            return ""

    def _description_and_impact(
        self, description: str, severity: str | None
    ) -> tuple[str, str]:
        text = str(description or "").strip()
        parts = re.split(r"\n*\s*Business impact:\s*", text, maxsplit=1, flags=re.I)
        if len(parts) == 2:
            return parts[0].strip(), parts[1].strip()
        return text, self._default_impact(severity)

    def _default_impact(self, severity: str | None) -> str:
        severity = (severity or "info").lower()
        impacts = {
            "critical": (
                "Immediate executive attention; confirmed exploitability may allow "
                "unauthorized access, privilege escalation, or regulated data exposure."
            ),
            "high": (
                "High-priority remediation; the issue can materially affect protected "
                "resources, tenant boundaries, or security assurance."
            ),
            "medium": (
                "Remediation should be scheduled; the issue increases attack surface "
                "or weakens expected controls."
            ),
            "low": (
                "Track and remediate as part of hardening to reduce cumulative security risk."
            ),
        }
        return impacts.get(severity, "Informational finding captured for audit context.")

    def _remediation_steps(self, remediation: str) -> list[str]:
        text = str(remediation or "").strip()
        if not text:
            return []

        lines = [
            re.sub(r"^\s*(?:\d+[\.)]|[-*])\s*", "", line).strip()
            for line in text.splitlines()
            if line.strip()
        ]
        if len(lines) > 1:
            return lines[:8]

        sentences = [part.strip() for part in re.split(r"(?<=[.!?])\s+", text)]
        sentences = [part for part in sentences if part]
        return sentences[:8] if sentences else [text]

    def _finding_compliance_items(self, finding: Finding) -> list[dict[str, Any]]:
        base = list(getattr(finding, "compliance", None) or [])
        items = [*base, *self._iso27001_mappings(finding)]
        deduped: list[dict[str, Any]] = []
        seen: set[tuple[str, str]] = set()
        for item in items:
            key = (
                str(item.get("framework") or "Unknown"),
                str(item.get("article_or_control") or "N/A"),
            )
            if key in seen:
                continue
            seen.add(key)
            deduped.append(item)
        return deduped

    def _deep_compliance_analysis(
        self,
        *,
        finding: Finding,
        endpoint: Any,
        compliance: list[dict[str, Any]],
        description: str,
        http_evidence: dict[str, Any],
    ) -> dict[str, Any]:
        finding_type = str(getattr(finding, "finding_type", "") or "")
        severity = str(getattr(finding, "severity", "info") or "info").lower()
        confidence = float(getattr(finding, "confidence", 0) or 0)
        evidence = getattr(finding, "evidence_summary", None) or {}
        endpoint_text = (
            getattr(endpoint, "url", None)
            or getattr(endpoint, "normalized_path", None)
            or getattr(finding, "endpoint", None)
            or "the affected endpoint"
        )
        evidence_level, evidence_justification = self._compliance_confidence(
            finding_type=finding_type,
            severity=severity,
            confidence=confidence,
            evidence=evidence,
            http_evidence=http_evidence,
        )
        data_impact = self._potential_data_impact(
            finding=finding,
            endpoint=endpoint,
            description=description,
            http_evidence=http_evidence,
        )
        business_impact = self._business_impact_items(finding)
        affected_assets = self._affected_assets(finding, endpoint)
        gap = self._compliance_gap(finding, description)
        remediation_priority = self._remediation_priority(
            severity=severity,
            finding_type=finding_type,
            evidence_level=evidence_level,
            evidence=evidence,
        )
        regulatory = [
            self._regulatory_analysis_item(
                item=item,
                finding=finding,
                observed=gap["observed"],
                evidence_level=evidence_level,
                status=self._compliance_status(severity, evidence_level),
            )
            for item in compliance
        ]
        attack_scenario = self._attack_scenario(finding, endpoint_text)
        worst_case = self._worst_case_scenario(finding)

        executive_summary = self._executive_risk_summary(
            finding=finding,
            data_impact=data_impact,
            regulatory=regulatory,
            remediation_priority=remediation_priority,
        )
        summary = (
            f"{gap['gap']} {data_impact['summary']} "
            f"Compliance status is assessed as {self._compliance_status(severity, evidence_level)} "
            f"with {evidence_level.lower()} confidence."
        )
        return {
            "summary": summary,
            "executive_risk_summary": executive_summary,
            "confirmed_technical_evidence": gap["observed"],
            "potential_data_protection_impact": data_impact,
            "business_impact": business_impact,
            "affected_assets": affected_assets,
            "gap_analysis": gap,
            "regulatory_analysis": regulatory,
            "attack_scenario": attack_scenario,
            "worst_case_scenario": worst_case,
            "compliance_confidence": {
                "level": evidence_level,
                "justification": evidence_justification,
            },
            "remediation_priority": remediation_priority,
        }

    def _iso27001_mappings(self, finding: Finding) -> list[dict[str, str]]:
        combined = self._finding_text(finding)
        controls: list[tuple[str, str]] = []
        if self._is_auth_finding(combined):
            controls.extend(
                [
                    ("Annex A 5.15 Access Control", "Authentication or authorization controls may not enforce intended access boundaries."),
                    ("Annex A 5.16 Identity Management", "Identity and role attributes may not be governed consistently."),
                    ("Annex A 8.5 Secure Authentication", "Secure authentication controls may be bypassed or weakened."),
                ]
            )
        if self._is_sqli_finding(combined):
            controls.extend(
                [
                    ("Annex A 8.28 Secure Coding", "Authentication logic may accept unsanitized user input."),
                    ("Annex A 8.25 Secure Development Lifecycle", "Secure design and verification activities may not prevent injection flaws."),
                ]
            )
        if self._is_data_exposure_finding(combined):
            controls.extend(
                [
                    ("Annex A 5.34 Privacy and Protection of PII", "PII protection controls may be affected if protected records are reachable."),
                    ("Annex A 5.12 Classification of Information", "Information classification and handling controls may be insufficient for exposed data."),
                ]
            )
        if self._is_session_finding(combined):
            controls.extend(
                [
                    ("Annex A 8.5 Secure Authentication", "Session and token assurance may not be enforced consistently."),
                    ("Annex A 5.15 Access Control", "Access control decisions may rely on untrusted session state."),
                ]
            )
        if "ssrf" in combined or "server-side request" in combined:
            controls.extend(
                [
                    ("Annex A 8.20 Networks Security", "Server-side network egress may not be restricted to trusted destinations."),
                    ("Annex A 8.22 Segregation of Networks", "Application servers may be able to reach internal network resources unexpectedly."),
                    ("Annex A 8.28 Secure Coding", "URL fetch logic may not validate destinations safely."),
                ]
            )
        if "negative_amount" in combined or "business_logic" in combined or "transfer" in combined:
            controls.extend(
                [
                    ("Annex A 8.28 Secure Coding", "Financial workflow invariants may not be validated server-side."),
                    ("Annex A 5.15 Access Control", "Transaction authorization and business rule enforcement may be incomplete."),
                ]
            )
        if "rate_limit" in combined or "quota" in combined:
            controls.extend(
                [
                    ("Annex A 8.6 Capacity Management", "Rate-limit capacity controls may not distinguish user contexts correctly."),
                    ("Annex A 8.15 Logging", "Quota and role enforcement events may be audited under the wrong identity."),
                ]
            )
        if not controls:
            controls.append(
                (
                    "Annex A 5.8 Information Security in Project Management",
                    "The finding should be reviewed against project security requirements.",
                )
            )

        return [
            {
                "framework": "ISO/IEC 27001:2022",
                "article_or_control": control,
                "privacy_risk": reason,
                "legal_risk": "Control non-conformance may require risk treatment and management review.",
                "business_risk": "Residual risk can affect audit readiness and control assurance.",
            }
            for control, reason in controls
        ]

    def _potential_data_impact(
        self,
        *,
        finding: Finding,
        endpoint: Any,
        description: str,
        http_evidence: dict[str, Any],
    ) -> dict[str, Any]:
        haystack = " ".join(
            [
                self._finding_text(finding),
                str(description or ""),
                str(getattr(endpoint, "url", "") or ""),
                str(getattr(endpoint, "normalized_path", "") or ""),
                str(http_evidence.get("request_text") or ""),
                str(http_evidence.get("response_text") or ""),
            ]
        ).lower()

        personal = self._category_matches(
            haystack,
            {
                "Name": ("name", "full_name", "customer", "profile"),
                "Email": ("email", "mail"),
                "Phone Number": ("phone", "mobile", "tel"),
                "National ID": ("nik", "national", "identity", "npwp"),
                "Address": ("address", "alamat"),
            },
        )
        financial = self._category_matches(
            haystack,
            {
                "Account Number": ("account_number", "accountnumber", "rekening", "account"),
                "Transaction History": ("transaction", "transfer", "payment", "invoice"),
                "Balance": ("balance", "saldo"),
                "Card or Payment Data": ("card", "virtual_card", "payment"),
            },
        )
        auth = self._category_matches(
            haystack,
            {
                "Credentials": ("password", "credential"),
                "Authorization Claims": ("role", "is_admin", "admin", "permission"),
            },
        )
        session = self._category_matches(
            haystack,
            {
                "Authentication Tokens": ("token", "jwt", "bearer", "access_token"),
                "Session Data": ("session", "cookie", "set-cookie"),
            },
        )

        combined = self._finding_text(finding)
        if self._is_auth_finding(combined):
            personal = self._merge_unique(personal, ["Name", "Email", "Account Number"])
            auth = self._merge_unique(auth, ["Authorization Claims"])
            session = self._merge_unique(session, ["Authentication Tokens", "Session Data"])
        if self._is_sqli_finding(combined):
            personal = self._merge_unique(personal, ["Name", "Email", "National ID"])
            financial = self._merge_unique(financial, ["Account Number", "Transaction History"])
            auth = self._merge_unique(auth, ["Credentials"])
        if "ssrf" in combined:
            session = self._merge_unique(session, ["Authentication Tokens", "Session Data"])
            auth = self._merge_unique(auth, ["Internal Service Credentials"])
        if "negative_amount" in combined or "transfer" in combined:
            financial = self._merge_unique(financial, ["Account Number", "Transaction History", "Balance"])

        if not any([personal, financial, auth, session]):
            personal = ["Personal data categories are not confirmed by evidence"]

        summary = (
            "Based on the affected function and evidence, exploitation could result in "
            "unauthorized access to the listed data categories. This is a potential impact "
            "assessment and does not state that data exposure occurred."
        )
        return {
            "summary": summary,
            "personal_data": personal,
            "authentication_data": auth,
            "financial_data": financial,
            "session_or_token_data": session,
        }

    def _business_impact_items(self, finding: Finding) -> list[str]:
        combined = self._finding_text(finding)
        if self._is_sqli_finding(combined):
            return [
                "Could allow unauthorized database-backed authentication or data access.",
                "May enable data manipulation or integrity loss in affected workflows.",
                "Could create financial loss, service disruption, and regulatory investigation costs.",
            ]
        if self._is_auth_finding(combined):
            return [
                "Could allow account takeover or unauthorized access to protected resources.",
                "May increase fraud risk and customer trust degradation.",
                "Could require incident response, forced session rotation, and audit remediation.",
            ]
        if "ssrf" in combined:
            return [
                "Could expand attacker reach to internal services or administrative interfaces.",
                "May disclose internal service responses through the application.",
                "Could increase investigation scope and infrastructure hardening costs.",
            ]
        if "negative_amount" in combined or "business_logic" in combined:
            return [
                "Could cause incorrect financial movement or reconciliation failures.",
                "May create fraud opportunities in payment, transfer, or refund workflows.",
                "Could require transaction review, customer support, and financial correction.",
            ]
        if "rate_limit" in combined or "quota" in combined:
            return [
                "Could weaken abuse prevention or deny legitimate users incorrectly.",
                "May reduce audit reliability for quota and identity enforcement.",
                "Could increase operational support and monitoring workload.",
            ]
        if self._is_data_exposure_finding(combined):
            return [
                "Could expand reconnaissance opportunities and enable targeted attacks.",
                "May increase privacy review scope and customer notification analysis.",
                "Could reduce trust in data handling controls.",
            ]
        return [
            "Could increase operational security risk for the affected asset.",
            "May require control review and remediation planning before audit closure.",
        ]

    def _affected_assets(self, finding: Finding, endpoint: Any) -> list[dict[str, str]]:
        combined = self._finding_text(finding)
        assets: list[dict[str, str]] = []
        if self._is_auth_finding(combined):
            assets.extend(
                [
                    {"asset": "Customer Accounts", "impact": "Unauthorized Access"},
                    {"asset": "Authentication System", "impact": "Integrity Compromise"},
                    {"asset": "Administrative Portal", "impact": "Privilege Escalation Risk"},
                ]
            )
        if self._is_sqli_finding(combined):
            assets.extend(
                [
                    {"asset": "Authentication Database", "impact": "Query Manipulation Risk"},
                    {"asset": "Personal Data Repository", "impact": "Potential Disclosure"},
                    {"asset": "Transaction Database", "impact": "Potential Manipulation"},
                ]
            )
        if "ssrf" in combined:
            assets.extend(
                [
                    {"asset": "Server-Side Fetch Workflow", "impact": "Destination Validation Bypass"},
                    {"asset": "Internal Services", "impact": "Potential Reachability from Application Server"},
                ]
            )
        if "negative_amount" in combined or "business_logic" in combined or "transfer" in combined:
            assets.extend(
                [
                    {"asset": "Transaction Workflow", "impact": "Business Rule Bypass"},
                    {"asset": "Customer Balances", "impact": "Potential Incorrect Movement"},
                ]
            )
        if "rate_limit" in combined or "quota" in combined:
            assets.extend(
                [
                    {"asset": "Rate Limiting System", "impact": "Role Bucket Misclassification"},
                    {"asset": "Audit and Monitoring", "impact": "Incorrect Identity Context"},
                ]
            )
        endpoint_label = getattr(endpoint, "normalized_path", None) or getattr(endpoint, "url", None)
        if endpoint_label:
            assets.append({"asset": str(endpoint_label), "impact": "Affected Endpoint"})
        return assets or [{"asset": "Application Control Surface", "impact": "Control Review Required"}]

    def _compliance_gap(self, finding: Finding, description: str) -> dict[str, Any]:
        combined = self._finding_text(finding)
        if self._is_sqli_finding(combined):
            return {
                "observed": [
                    "Authentication or database-backed input accepted SQL control characters.",
                    "Validation evidence indicated query manipulation or authentication state change.",
                ],
                "expected": [
                    "Parameterized queries or ORM-bound parameters for all database access.",
                    "Secure authentication validation that cannot be altered by user input.",
                    "Generic error handling that does not disclose database behavior.",
                ],
                "gap": "Authentication and input validation controls do not adequately prevent manipulation of database queries.",
            }
        if self._is_auth_finding(combined):
            return {
                "observed": [
                    description or "Authentication or authorization behavior deviated from expected access control.",
                    "Evidence indicates protected behavior may be reachable without the intended trust boundary.",
                ],
                "expected": [
                    "Server-side verification of identity, session integrity, and role authorization on every request.",
                    "Sensitive claims and roles validated against a trusted server-side source.",
                ],
                "gap": "Authentication and authorization controls do not fully enforce the expected access boundary.",
            }
        if "ssrf" in combined:
            return {
                "observed": [
                    "A user-controlled URL-like input was accepted by a server-side fetch workflow.",
                    "In-band evidence may show the application can fetch non-public or canary resources.",
                ],
                "expected": [
                    "Destination allowlisting and IP range validation before every server-side fetch.",
                    "Blocking of loopback, metadata, and internal ranges unless explicitly approved for a lab.",
                ],
                "gap": "Server-side fetch controls do not adequately constrain caller-supplied destinations.",
            }
        if "negative_amount" in combined or "business_logic" in combined:
            return {
                "observed": [
                    "A financial or quantity-changing workflow may accept invalid business values.",
                    "Evidence may show state movement inconsistent with normal transaction direction.",
                ],
                "expected": [
                    "Server-side validation rejecting negative, zero, NaN, and overflow values.",
                    "Invariant checks around debit, credit, refund, and balance movement.",
                ],
                "gap": "Business rule enforcement does not adequately validate transaction invariants before state change.",
            }
        if "rate_limit" in combined or "quota" in combined:
            return {
                "observed": [
                    "Rate-limit or quota metadata may classify authenticated and anonymous contexts incorrectly.",
                    "Evidence compares role/bucket handling without request flooding.",
                ],
                "expected": [
                    "Rate-limit buckets bound to the authenticated principal and role.",
                    "Separate anonymous and authenticated quotas with auditable enforcement decisions.",
                ],
                "gap": "Rate-limit enforcement may not consistently bind quota decisions to the authenticated identity.",
            }
        return {
            "observed": [description or "A security control weakness was discovered."],
            "expected": ["Defined security control behavior should be enforced consistently."],
            "gap": "The observed implementation does not fully satisfy the expected security control behavior.",
        }

    def _regulatory_analysis_item(
        self,
        *,
        item: dict[str, Any],
        finding: Finding,
        observed: list[str],
        evidence_level: str,
        status: str,
    ) -> dict[str, str]:
        framework = str(item.get("framework") or "Control")
        control = str(item.get("article_or_control") or "N/A")
        requirement = self._regulatory_requirement(framework, control)
        potential = (
            str(item.get("privacy_risk") or "").strip()
            or str(item.get("business_risk") or "").strip()
            or "The finding may affect control conformance for the mapped requirement."
        )
        return {
            "framework": framework,
            "control": control,
            "requirement": requirement,
            "observed": " ".join(observed[:2]),
            "potential_impact": potential,
            "status": status,
            "confidence": evidence_level,
            "reason": self._regulatory_reason(finding, evidence_level),
        }

    def _regulatory_requirement(self, framework: str, control: str) -> str:
        text = f"{framework} {control}".lower()
        if "pasal 35" in text:
            return "Personal data must be protected against unauthorized access, disclosure, alteration, misuse, destruction, or loss."
        if "pasal 20" in text:
            return "Personal data processing must have a lawful basis and respect consent requirements where applicable."
        if "pasal 22" in text:
            return "Data subject rights must remain enforceable through reliable and secure processing controls."
        if "pasal 46" in text:
            return "Potential personal data protection failures must be assessed for notification obligations."
        if "pasal 57" in text:
            return "Non-compliance with personal data protection obligations may require administrative remediation."
        if "pasal 67" in text:
            return "High-impact personal data failures may create administrative fine exposure."
        if "v2" in text or "v3" in text:
            return "Authentication and session management controls must verify identity and preserve session integrity."
        if "v4" in text:
            return "Access control must enforce least privilege and object-level authorization."
        if "v5" in text:
            return "Input validation, sanitization, and output encoding must prevent injection and unsafe data handling."
        if "v8" in text:
            return "Sensitive data must be protected according to classification and privacy requirements."
        if "v12" in text or "v14" in text:
            return "Resource handling, network access, and security configuration must prevent unsafe exposure."
        if "5.15" in text:
            return "Access control rules must restrict access to information and associated assets."
        if "5.16" in text:
            return "Identity lifecycle and identity attributes must be managed consistently."
        if "8.5" in text:
            return "Secure authentication mechanisms must prevent unauthorized access."
        if "8.28" in text:
            return "Secure coding practices must prevent common implementation vulnerabilities."
        if "8.25" in text:
            return "Secure development lifecycle controls must reduce vulnerabilities before deployment."
        if "5.34" in text:
            return "Privacy and protection of personally identifiable information must be maintained."
        if "5.12" in text:
            return "Information must be classified and handled according to sensitivity."
        if "8.20" in text or "8.22" in text:
            return "Network security and segmentation must limit unintended access paths."
        if "8.6" in text:
            return "Capacity and abuse-prevention controls must be planned and enforced."
        if "8.15" in text:
            return "Logs must capture security-relevant activity accurately for monitoring and audit."
        return "The mapped control requires implementation evidence and risk treatment for the affected security requirement."

    def _compliance_confidence(
        self,
        *,
        finding_type: str,
        severity: str,
        confidence: float,
        evidence: dict[str, Any],
        http_evidence: dict[str, Any],
    ) -> tuple[str, str]:
        exploitability = str(evidence.get("exploitability_assessment") or "")
        if (
            exploitability == "CONFIRMED_EXPLOIT"
            or finding_type in CONFIRMED_EXPLOIT_TYPES
            or evidence.get("attack_status") in {200, 201, 202}
            or (confidence >= 90 and http_evidence.get("has_request") and http_evidence.get("has_response"))
        ):
            return (
                "High",
                "Exploitability or protected-state impact was validated with reproducible HTTP evidence.",
            )
        if confidence >= 65 or severity in {"high", "medium"}:
            return (
                "Medium",
                "Impact is partially validated or inferred from strong endpoint and control evidence.",
            )
        return (
            "Low",
            "Impact is speculative and should be reviewed manually before compliance conclusions are finalized.",
        )

    def _compliance_status(self, severity: str, evidence_level: str) -> str:
        if evidence_level == "High" and severity in {"critical", "high"}:
            return "Non-Compliant"
        if severity in {"critical", "high", "medium"}:
            return "Potential Non-Compliant"
        return "Potential Non-Compliant" if evidence_level != "Low" else "Compliant"

    def _regulatory_reason(self, finding: Finding, evidence_level: str) -> str:
        if evidence_level == "High":
            return "Conclusion is supported by reproducible technical evidence in the report."
        if evidence_level == "Medium":
            return "Conclusion is based on partial validation and endpoint context; legal review may be required."
        return "Conclusion is a conservative risk indicator and requires manual confirmation."

    def _attack_scenario(self, finding: Finding, endpoint_text: str) -> list[str]:
        combined = self._finding_text(finding)
        if self._is_sqli_finding(combined):
            return [
                f"Attacker accesses {endpoint_text}.",
                "Attacker submits crafted SQL control characters into an authentication or query field.",
                "The application processes the input inside database logic.",
                "Authentication or data access behavior may be altered.",
                "A session or protected response may become accessible.",
                "Personal or financial records could be viewed or modified if they are reachable behind the same control.",
            ]
        if self._is_auth_finding(combined):
            return [
                f"Attacker targets {endpoint_text}.",
                "Attacker manipulates authentication, session, or authorization context.",
                "The application accepts the altered context or fails to enforce server-side authorization.",
                "Protected resources become accessible outside the intended trust boundary.",
                "Customer, administrative, or transaction data could be accessed depending on the route.",
            ]
        if "ssrf" in combined:
            return [
                f"Attacker submits a URL-like value to {endpoint_text}.",
                "The server fetches the supplied destination.",
                "The request may reach loopback or internal services from the server network.",
                "The application returns or stores the fetched result in-band.",
                "Internal data or service behavior could become visible through the application.",
            ]
        if "negative_amount" in combined or "business_logic" in combined:
            return [
                f"Attacker accesses a financial workflow at {endpoint_text}.",
                "Attacker submits a negative or malformed amount.",
                "Server-side business rules fail to reject the invalid value.",
                "Balances, refunds, quantities, or ledger entries may move in an unintended direction.",
                "Financial reconciliation and customer account integrity could be affected.",
            ]
        if "rate_limit" in combined or "quota" in combined:
            return [
                f"Attacker reviews quota or rate-limit behavior at {endpoint_text}.",
                "Authenticated and anonymous contexts are compared.",
                "The application may assign the wrong quota bucket or role label.",
                "Abuse prevention or audit attribution could become unreliable.",
            ]
        return [
            f"Attacker identifies the affected endpoint: {endpoint_text}.",
            "Attacker interacts with the weak control using crafted input or altered context.",
            "The application may return behavior outside the expected security boundary.",
            "Additional access or reconnaissance opportunities could become available.",
        ]

    def _worst_case_scenario(self, finding: Finding) -> list[str]:
        combined = self._finding_text(finding)
        if self._is_auth_finding(combined) or self._is_sqli_finding(combined):
            return [
                "Unauthorized access to customer accounts or administrative functions.",
                "Potential access to personal data repositories if reachable through the compromised context.",
                "Potential transaction manipulation or fraud in connected financial workflows.",
                "Regulatory investigation, mandatory assessment of notification obligations, and reputational damage.",
            ]
        if "ssrf" in combined:
            return [
                "Application server reaches internal administrative or data services.",
                "Internal responses or service metadata could become visible through the application.",
                "Network segmentation gaps require urgent infrastructure and application review.",
                "Regulatory and customer impact assessment may be required if personal data systems are reachable.",
            ]
        if "negative_amount" in combined or "business_logic" in combined:
            return [
                "Incorrect movement of funds or balances in customer-facing workflows.",
                "Financial reconciliation errors and possible fraud scenarios.",
                "Customer trust degradation, incident response costs, and audit findings.",
            ]
        return [
            "Expanded attack surface and increased likelihood of targeted follow-on attacks.",
            "Control non-conformance requiring remediation before audit closure.",
            "Potential privacy, operational, and reputational consequences depending on affected data.",
        ]

    def _executive_risk_summary(
        self,
        *,
        finding: Finding,
        data_impact: dict[str, Any],
        regulatory: list[dict[str, str]],
        remediation_priority: dict[str, str],
    ) -> str:
        controls = ", ".join(
            f"{item['framework']} {item['control']}" for item in regulatory[:3]
        )
        data_summary = data_impact["summary"]
        return (
            f"{finding.title} affects a security control that may allow unauthorized access "
            f"or misuse of protected functionality. {data_summary} "
            f"The issue may affect compliance with {controls or 'mapped security controls'} "
            f"and should be treated with {remediation_priority['level'].lower()} remediation priority."
        )

    def _remediation_priority(
        self,
        *,
        severity: str,
        finding_type: str,
        evidence_level: str,
        evidence: dict[str, Any],
    ) -> dict[str, str]:
        confirmed = evidence_level == "High" or evidence.get("attack_status") in {200, 201, 202}
        if severity == "critical" or (confirmed and finding_type in CONFIRMED_EXPLOIT_TYPES):
            return {
                "level": "Immediate",
                "reason": "Confirmed high-impact exploitability or direct protected-resource access requires urgent remediation.",
            }
        if severity == "high" or evidence_level == "High":
            return {
                "level": "High",
                "reason": "Strong evidence indicates material security and compliance risk.",
            }
        if severity == "medium" or evidence_level == "Medium":
            return {
                "level": "Medium",
                "reason": "Impact is partially validated or materially plausible and should be scheduled for remediation.",
            }
        return {
            "level": "Low",
            "reason": "Residual risk should be tracked through normal hardening and control review.",
        }

    def _category_matches(
        self, haystack: str, mapping: dict[str, tuple[str, ...]]
    ) -> list[str]:
        return [
            category
            for category, terms in mapping.items()
            if any(term in haystack for term in terms)
        ]

    def _merge_unique(self, left: list[str], right: list[str]) -> list[str]:
        merged: list[str] = []
        for item in [*left, *right]:
            if item not in merged:
                merged.append(item)
        return merged

    def _finding_text(self, finding: Finding) -> str:
        return " ".join(
            [
                str(getattr(finding, "finding_type", "") or ""),
                str(getattr(finding, "title", "") or ""),
                str(getattr(finding, "description", "") or ""),
            ]
        ).lower()

    def _is_auth_finding(self, text: str) -> bool:
        return any(
            token in text
            for token in (
                "auth",
                "jwt",
                "session",
                "token",
                "privilege",
                "access_control",
                "missing_authorization",
                "bola",
                "idor",
            )
        )

    def _is_sqli_finding(self, text: str) -> bool:
        return "sqli" in text or "sql injection" in text or "sql" in text

    def _is_session_finding(self, text: str) -> bool:
        return "session" in text or "jwt" in text or "token" in text

    def _is_data_exposure_finding(self, text: str) -> bool:
        return any(
            token in text
            for token in (
                "pii",
                "exposure",
                "disclosure",
                "personal",
                "sensitive",
                "data",
            )
        )

    def _compliance_controls(self, compliance: list[dict[str, Any]]) -> list[str]:
        controls: list[str] = []
        for item in compliance:
            framework = str(item.get("framework") or "Control")
            control = str(item.get("article_or_control") or "N/A")
            controls.append(f"{framework} {control}")
        return controls

    def _compliance_analysis(self, compliance: list[dict[str, Any]]) -> str:
        if not compliance:
            return (
                "No mapped legal or control reference was generated for this finding; "
                "review manually if the affected asset processes personal data."
            )

        parts: list[str] = []
        for item in compliance[:4]:
            control = f"{item.get('framework', 'Control')} {item.get('article_or_control', 'N/A')}"
            risks = [
                str(item.get("business_risk") or "").strip(),
                str(item.get("privacy_risk") or "").strip(),
                str(item.get("legal_risk") or "").strip(),
            ]
            risk_text = " ".join(risk for risk in risks if risk)
            parts.append(f"{control}: {risk_text}" if risk_text else control)
        return " ".join(parts)

    def _secure_code_example(self, finding: Finding) -> str:
        combined = f"{finding.finding_type} {finding.title}".lower()
        if any(keyword in combined for keyword in ("jwt", "token", "session")):
            return (
                'claims = jwt.decode(token, public_key, algorithms=["RS256"])\n'
                'user = db.get_user(claims["user_id"])\n\n'
                'if user.role == "admin":\n'
                "    allow_access()\n"
                "else:\n"
                "    deny_access()"
            )
        if any(keyword in combined for keyword in ("bola", "idor", "access", "privilege", "auth")):
            return (
                "resource = db.get_resource(resource_id)\n\n"
                "if resource.owner_id != current_user.id and not current_user.is_admin:\n"
                "    deny_access()\n\n"
                "return resource"
            )
        if any(keyword in combined for keyword in ("sqli", "sql", "injection")):
            return (
                'query = "SELECT * FROM users WHERE id = :user_id"\n'
                "user = db.execute(query, {\"user_id\": user_id}).one_or_none()"
            )
        if any(keyword in combined for keyword in ("xss", "reflected", "html")):
            return (
                "safe_value = html.escape(user_supplied_value)\n"
                "return render_template(\"profile.html\", value=safe_value)"
            )
        if "cors" in combined:
            return (
                "allowed_origins = {\"https://app.example.com\"}\n\n"
                "if request.origin in allowed_origins:\n"
                "    set_cors_origin(request.origin)"
            )
        if any(keyword in combined for keyword in ("path_traversal", "traversal", "file")):
            return (
                "base = Path(\"/srv/app/uploads\").resolve()\n"
                "target = (base / requested_name).resolve()\n\n"
                "if not target.is_relative_to(base):\n"
                "    deny_access()"
            )
        return (
            "policy = load_security_policy(endpoint)\n\n"
            "if not policy.allows(current_user, request):\n"
            "    deny_access()\n\n"
            "return handle_request(request)"
        )

    def _compliance_rows(self, findings: list[Finding]) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for finding in findings:
            for item in self._finding_compliance_items(finding):
                key = (
                    str(item.get("framework", "Unknown")),
                    str(item.get("article_or_control", "N/A")),
                )
                row = grouped.setdefault(
                    key,
                    {
                        "framework": key[0],
                        "article_or_control": key[1],
                        "finding_count": 0,
                        "severity": "info",
                        "privacy_risk": item.get("privacy_risk", ""),
                        "legal_risk": item.get("legal_risk", ""),
                        "business_risk": item.get("business_risk", ""),
                        "findings": [],
                    },
                )
                row["finding_count"] += 1
                row["findings"].append(finding.title)
                row["severity"] = self._stronger_severity(
                    row["severity"], finding.severity
                )
        return sorted(
            grouped.values(),
            key=lambda row: (
                SEVERITY_ORDER.index(row["severity"])
                if row["severity"] in SEVERITY_ORDER
                else 99,
                row["framework"],
                row["article_or_control"],
            ),
        )

    # ------------------------------------------------------------------
    # Remediation Matrix
    # ------------------------------------------------------------------

    # Finding types grouped by remediation domain
    _REMEDIATION_DOMAINS: dict[str, dict[str, Any]] = {
        "Access Control": {
            "keywords": [
                "bola",
                "idor",
                "access",
                "privilege",
                "auth",
                "authorization",
            ],
            "effort": "Moderate",
            "effort_days": "3-7",
            "timeline": "Short-term (7-30 days)",
        },
        "Input Validation": {
            "keywords": [
                "sqli",
                "injection",
                "path_traversal",
                "traversal",
                "reflected",
                "xss",
            ],
            "effort": "Moderate",
            "effort_days": "3-7",
            "timeline": "Short-term (7-30 days)",
        },
        "Data Protection": {
            "keywords": [
                "pii",
                "exposure",
                "encryption",
                "data_leak",
                "sensitive_data",
            ],
            "effort": "Complex",
            "effort_days": "7-14",
            "timeline": "Medium-term (30-90 days)",
        },
        "Configuration Security": {
            "keywords": ["cors", "jwt", "misconfiguration", "token", "session"],
            "effort": "Simple",
            "effort_days": "1-3",
            "timeline": "Immediate (0-7 days)",
        },
        "API Security": {
            "keywords": [
                "unauthenticated",
                "api_exposure",
                "graphql",
                "oauth",
                "webhook",
            ],
            "effort": "Moderate",
            "effort_days": "3-7",
            "timeline": "Short-term (7-30 days)",
        },
        "Network Security": {
            "keywords": [
                "ssrf",
                "internal",
                "network",
                "debug",
                "proxy",
                "segmentation",
            ],
            "effort": "Complex",
            "effort_days": "7-14",
            "timeline": "Medium-term (30-90 days)",
        },
    }

    _REMEDIATION_ACTIONS: dict[str, str] = {
        "Access Control": (
            "Implement proper authorization checks on all endpoints. "
            "Enforce object-level ownership validation (BOLA/IDOR prevention). "
            "Apply RBAC/ABAC consistently across API routes."
        ),
        "Input Validation": (
            "Use parameterized queries for all database operations. "
            "Implement input sanitization and output encoding. "
            "Deploy WAF rules for common injection patterns."
        ),
        "Data Protection": (
            "Encrypt personal data at rest using AES-256. "
            "Implement field-level encryption for sensitive PII (NIK, NPWP, etc.). "
            "Establish data retention and deletion policies per UU PDP."
        ),
        "Configuration Security": (
            "Fix CORS policies to restrict allowed origins. "
            "Implement proper JWT validation (expiry, audience, signature). "
            "Set secure cookie flags (HttpOnly, Secure, SameSite)."
        ),
        "API Security": (
            "Add authentication middleware to all sensitive endpoints. "
            "Implement rate limiting and API key rotation. "
            "Review OAuth flows and redirect URI validation."
        ),
        "Network Security": (
            "Implement network segmentation between public and internal services. "
            "Block SSRF vectors with egress filtering. "
            "Remove or restrict debug endpoints in production."
        ),
    }

    def _classify_finding_domain(self, finding: Finding) -> str:
        """Classify a finding into a remediation domain based on its type."""
        finding_type = (finding.finding_type or "").lower()
        title = (finding.title or "").lower()
        combined = f"{finding_type} {title}"
        for domain, config in self._REMEDIATION_DOMAINS.items():
            for keyword in config["keywords"]:
                if keyword in combined:
                    return domain
        return "General Security"

    def _effort_score(self, finding: Finding) -> float:
        """Calculate a priority score for a finding based on severity and risk."""
        severity_weight = {
            "critical": 4.0,
            "high": 3.0,
            "medium": 2.0,
            "low": 1.0,
            "info": 0.5,
        }
        sev = (finding.severity or "info").lower()
        weight = severity_weight.get(sev, 0.5)
        risk = float(finding.risk_score or 0)
        confidence = float(finding.confidence or 0) / 100.0
        return round(weight * 10 + risk * 0.5 + confidence * 5, 1)

    def _determine_timeline(self, findings: list[Finding]) -> str:
        """Determine the recommended timeline based on highest severity."""
        severities = {(f.severity or "info").lower() for f in findings}
        if "critical" in severities:
            return "Immediate (0-7 days)"
        if "high" in severities:
            return "Short-term (7-30 days)"
        if "medium" in severities:
            return "Medium-term (30-90 days)"
        return "Long-term (90+ days)"

    def _build_remediation_matrix(
        self, findings: list[Finding]
    ) -> list[dict[str, Any]]:
        """Build an aggregated, prioritized remediation action plan.

        Groups findings by remediation domain and produces actionable items
        with priority ranking, effort estimates, and timeline recommendations.
        """
        # Group findings by domain
        domain_findings: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            domain = self._classify_finding_domain(finding)
            domain_findings[domain].append(finding)

        matrix: list[dict[str, Any]] = []
        priority_counter = 1

        for domain, domain_finding_list in domain_findings.items():
            # Calculate aggregate stats
            severity_counts = Counter(
                (f.severity or "info").lower() for f in domain_finding_list
            )
            max_risk = max(float(f.risk_score or 0) for f in domain_finding_list)
            total_effort_score = sum(self._effort_score(f) for f in domain_finding_list)
            affected_endpoints = sorted(
                {f.endpoint_id for f in domain_finding_list if f.endpoint_id}
            )
            affected_endpoints = [
                e[:8] + "..." if len(e) > 8 else e for e in affected_endpoints[:5]
            ]

            # Get domain config
            domain_config = self._REMEDIATION_DOMAINS.get(
                domain,
                {
                    "effort": "Moderate",
                    "effort_days": "3-7",
                    "timeline": "Short-term (7-30 days)",
                },
            )

            # Determine timeline based on findings
            timeline = self._determine_timeline(domain_finding_list)

            # Build action item
            action = self._REMEDIATION_ACTIONS.get(
                domain,
                "Review and remediate identified security issues. "
                "Follow industry best practices and UU PDP requirements.",
            )

            # Determine priority level
            if severity_counts.get("critical", 0) > 0:
                priority_level = "P1 - Critical"
            elif severity_counts.get("high", 0) > 0:
                priority_level = "P2 - High"
            elif severity_counts.get("medium", 0) > 0:
                priority_level = "P3 - Medium"
            else:
                priority_level = "P4 - Low"

            matrix.append(
                {
                    "priority_rank": priority_counter,
                    "priority_level": priority_level,
                    "domain": domain,
                    "action": action,
                    "finding_count": len(domain_finding_list),
                    "severity_breakdown": {
                        s: severity_counts.get(s, 0) for s in SEVERITY_ORDER
                    },
                    "max_risk_score": round(max_risk, 1),
                    "total_effort_score": round(total_effort_score, 1),
                    "effort_estimate": domain_config.get("effort", "Moderate"),
                    "effort_days": domain_config.get("effort_days", "3-7"),
                    "recommended_timeline": timeline,
                    "affected_endpoints": affected_endpoints,
                    "finding_titles": [f.title for f in domain_finding_list[:6]],
                    "finding_types": sorted(
                        {f.finding_type for f in domain_finding_list}
                    ),
                    "compliance_impact": sorted(
                        {
                            item.get("article_or_control", "")
                            for f in domain_finding_list
                            for item in (f.compliance or [])
                            if item.get("framework") == "UU PDP"
                        }
                    ),
                }
            )
            priority_counter += 1

        # Sort by total effort score (highest priority first)
        matrix.sort(key=lambda x: x["total_effort_score"], reverse=True)
        # Re-assign priority ranks after sorting
        for i, item in enumerate(matrix, start=1):
            item["priority_rank"] = i

        return matrix

    def _stronger_severity(self, left: str, right: str) -> str:
        left = (left or "info").lower()
        right = (right or "info").lower()
        left_rank = SEVERITY_ORDER.index(left) if left in SEVERITY_ORDER else 99
        right_rank = SEVERITY_ORDER.index(right) if right in SEVERITY_ORDER else 99
        return right if right_rank < left_rank else left

    def _executive_eligible(self, finding: Finding) -> bool:
        evidence = getattr(finding, "evidence_summary", None) or {}
        finding_type = str(getattr(finding, "finding_type", "") or "")
        confidence = float(getattr(finding, "confidence", 0) or 0)
        if finding_type in DISCOVERY_ONLY_TYPES:
            return False
        if confidence < 70:
            return False
        if evidence.get("confidence_level") == "LOW_CONFIDENCE":
            return False
        if evidence.get("false_positive_likelihood") == "HIGH":
            return False
        if evidence.get("exploitability_assessment") in {
            "HEURISTIC_SIGNAL",
            "ATTACK_SURFACE_IDENTIFIED",
        }:
            return False
        if evidence.get("validation_mode") in REGEX_ONLY_MODES:
            return False
        return True

    def _is_exploit_finding(self, detail: dict[str, Any]) -> bool:
        exploitability = detail.get("exploitability_assessment")
        if not exploitability and detail.get("finding_type") in CONFIRMED_EXPLOIT_TYPES:
            exploitability = "CONFIRMED_EXPLOIT"
        return (
            detail.get("finding_type") in CONFIRMED_EXPLOIT_TYPES
            and exploitability == "CONFIRMED_EXPLOIT"
            and detail.get("false_positive_likelihood") != "HIGH"
        )

    def _format_datetime(self, value: Any) -> str:
        return format_datetime(value)

    def _compact_id(self, value: Any) -> str:
        text = str(value or "")
        return text if len(text) <= 14 else f"{text[:8]}...{text[-4:]}"

    def _json_preview(self, value: Any) -> str:
        try:
            return json.dumps(value, indent=2, sort_keys=True, default=str)[:1800]
        except TypeError:
            return str(value)[:1800]

