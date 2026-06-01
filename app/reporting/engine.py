from __future__ import annotations

from collections import Counter, defaultdict
from datetime import datetime, timezone
import json
import re
import textwrap
from typing import Any
from urllib.parse import urlparse

from jinja2 import Environment, PackageLoader, select_autoescape

from app.core.security import stable_hash
from app.models import Finding, Report


SEVERITY_ORDER = ("critical", "high", "medium", "low", "info")
SEVERITY_COLORS = {
    "critical": (0.86, 0.15, 0.15),
    "high": (0.92, 0.31, 0.18),
    "medium": (0.86, 0.54, 0.13),
    "low": (0.08, 0.58, 0.53),
    "info": (0.15, 0.39, 0.92),
}
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
}


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
        return _PDFReportBuilder(report).render().decode("latin-1")

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
            "finding_details": [{"title": "Report Content", "description": text[:4000]}] if text else [],
        }
        return _PDFReportBuilder(report).render().decode("latin-1")

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
        findings_by_endpoint: dict[str, list[Finding]] = defaultdict(list)
        for finding in findings:
            if finding.endpoint_id:
                findings_by_endpoint[finding.endpoint_id].append(finding)

        executive_findings = [finding for finding in findings if self._executive_eligible(finding)]
        severity_counts = Counter((finding.severity or "info").lower() for finding in executive_findings)
        compliance_rows = self._compliance_rows(findings)
        endpoint_rows = self._endpoint_rows(endpoints, findings_by_endpoint)
        finding_details = self._finding_details(findings, endpoint_lookup)
        exploit_findings = [detail for detail in finding_details if self._is_exploit_finding(detail)]
        max_risk = max((float(finding.risk_score or 0) for finding in executive_findings), default=0.0)
        avg_confidence = (
            sum(float(finding.confidence or 0) for finding in executive_findings) / len(executive_findings)
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
                "critical_high_count": severity_counts["critical"] + severity_counts["high"],
                "exploit_count": len(exploit_findings),
                "compliance_control_count": len(compliance_rows),
            },
            "severity_counts": {severity: severity_counts.get(severity, 0) for severity in SEVERITY_ORDER},
            "scope": scope,
            "endpoint_rows": endpoint_rows,
            "endpoint_row_limit": 500,
            "exploit_findings": exploit_findings,
            "compliance_rows": compliance_rows,
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
            report_hash=stable_hash({"title": title, "content": content, "type": report_type}),
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
            "project_name": getattr(project, "name", "Project aggregate") if project else "Project aggregate",
            "project_id": getattr(project, "id", None),
            "target_url": getattr(target, "base_url", None),
            "allowed_domains": getattr(target, "allowed_domains", []) if target else [],
            "scan_id": getattr(scan, "id", None),
            "scan_status": getattr(scan, "status", None),
            "scan_started_at": getattr(scan, "started_at", None),
            "scan_finished_at": getattr(scan, "finished_at", None),
            "scan_created_at": getattr(scan, "created_at", None),
            "scan_error": getattr(scan, "error", None),
            "generated_by": getattr(generated_by, "email", None) or getattr(generated_by, "full_name", None),
            "policy_name": getattr(policy, "name", None),
            "policy": {
                "max_requests_per_second": getattr(policy, "max_requests_per_second", None),
                "max_depth": getattr(policy, "max_depth", None),
                "max_pages": getattr(policy, "max_pages", None),
                "allow_sqli_validation": getattr(policy, "allow_sqli_validation", None),
                "allow_auth_validation": getattr(policy, "allow_auth_validation", None),
                "allow_timing_validation": getattr(policy, "allow_timing_validation", None),
                "excluded_paths": getattr(policy, "excluded_paths", []) if policy else [],
                "forbidden_paths": getattr(policy, "forbidden_paths", []) if policy else [],
                "scope_boundaries": getattr(policy, "scope_boundaries", []) if policy else [],
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
        severity_rank = {severity: score for score, severity in enumerate(SEVERITY_ORDER[::-1], start=1)}
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
                    "finding_titles": [finding.title for finding in endpoint_findings[:4]],
                    "finding_types": sorted({finding.finding_type for finding in endpoint_findings}),
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
    ) -> list[dict[str, Any]]:
        severity_rank = {severity: index for index, severity in enumerate(SEVERITY_ORDER)}
        ordered = sorted(
            findings,
            key=lambda finding: (
                severity_rank.get((finding.severity or "").lower(), 99),
                -float(finding.risk_score or 0),
                finding.title,
            ),
        )
        details: list[dict[str, Any]] = []
        for finding in ordered:
            endpoint = endpoint_lookup.get(finding.endpoint_id or "")
            evidence = finding.evidence_summary or {}
            details.append(
                {
                    "id": finding.id,
                    "title": finding.title,
                    "finding_type": finding.finding_type,
                    "severity": (finding.severity or "info").lower(),
                    "status": finding.status,
                    "confidence": round(float(finding.confidence or 0), 1),
                    "risk_score": round(float(finding.risk_score or 0), 1),
                    "description": finding.description,
                    "reasoning": list(finding.reasoning or []),
                    "remediation": finding.remediation_guidance,
                    "compliance": list(finding.compliance or []),
                    "evidence": evidence,
                    "validation_mode": evidence.get("validation_mode"),
                    "payload": evidence.get("payload"),
                    "endpoint_url": getattr(endpoint, "url", None),
                    "endpoint_path": getattr(endpoint, "normalized_path", None),
                    "method": getattr(endpoint, "method", None),
                    "created_at": finding.created_at,
                    "confidence_level": evidence.get("confidence_level"),
                    "exploitability_assessment": evidence.get("exploitability_assessment"),
                    "reproduction_stability": evidence.get("reproduction_stability"),
                    "evidence_quality": evidence.get("evidence_quality"),
                    "false_positive_likelihood": evidence.get("false_positive_likelihood"),
                }
            )
        return details

    def _compliance_rows(self, findings: list[Finding]) -> list[dict[str, Any]]:
        grouped: dict[tuple[str, str], dict[str, Any]] = {}
        for finding in findings:
            for item in finding.compliance or []:
                key = (str(item.get("framework", "Unknown")), str(item.get("article_or_control", "N/A")))
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
                row["severity"] = self._stronger_severity(row["severity"], finding.severity)
        return sorted(
            grouped.values(),
            key=lambda row: (
                SEVERITY_ORDER.index(row["severity"]) if row["severity"] in SEVERITY_ORDER else 99,
                row["framework"],
                row["article_or_control"],
            ),
        )

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
        if evidence.get("exploitability_assessment") in {"HEURISTIC_SIGNAL", "ATTACK_SURFACE_IDENTIFIED"}:
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
        if not value:
            return "N/A"
        if isinstance(value, datetime):
            return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
        return str(value)

    def _compact_id(self, value: Any) -> str:
        text = str(value or "")
        return text if len(text) <= 14 else f"{text[:8]}...{text[-4:]}"

    def _json_preview(self, value: Any) -> str:
        try:
            return json.dumps(value, indent=2, sort_keys=True, default=str)[:1800]
        except TypeError:
            return str(value)[:1800]


class _PDFReportBuilder:
    def __init__(self, report: dict[str, Any]):
        self.report = report
        self.width = 595
        self.height = 842
        self.margin = 42
        self.y = self.height - self.margin
        self.pages: list[str] = []
        self.ops: list[str] = []
        self.page_number = 0

    def render(self) -> bytes:
        self._new_page(cover=True)
        self._cover()
        self._new_page()
        self._section("Executive Summary")
        summary = self.report["summary"]
        self._metric_row(
            [
                ("Findings", str(summary["total_findings"]), "Total validated issues"),
                ("Critical/High", str(summary["critical_high_count"]), "Prioritized exposure"),
                ("Endpoints", str(summary["endpoint_count"]), "Discovered affected items"),
                ("Risk", str(summary["max_risk_score"]), "Maximum risk score"),
            ]
        )
        self._paragraph(
            "This report consolidates scan scope, discovered paths, validated vulnerabilities, "
            "exploit-chain outcomes, compliance impact, and remediation guidance from NyuwunSewu."
        )
        self._severity_distribution()

        self._section("Scan Scope")
        scope = self.report["scope"]
        self._key_values(
            [
                ("Project", scope.get("project_name")),
                ("Target", scope.get("target_url") or "Project aggregate"),
                ("Scan ID", scope.get("scan_id") or "Multiple / project aggregate"),
                ("Scan Status", scope.get("scan_status") or "N/A"),
                ("Started", ReportingEngine()._format_datetime(scope.get("scan_started_at"))),
                ("Finished", ReportingEngine()._format_datetime(scope.get("scan_finished_at"))),
                ("Policy", scope.get("policy_name") or "N/A"),
                ("Allowed Domains", ", ".join(scope.get("allowed_domains") or []) or "Default target host"),
            ]
        )

        self._section("Affected Items")
        endpoint_rows = self.report["endpoint_rows"][:45]
        if endpoint_rows:
            for row in endpoint_rows:
                self._endpoint_row(row)
        else:
            self._paragraph("No endpoint inventory was available for this report.")

        self._section("Confirmed Exploits")
        exploits = self.report["exploit_findings"][:20]
        if exploits:
            for item in exploits:
                self._finding_brief(item)
        else:
            self._paragraph("No confirmed exploit execution was recorded in this report scope.")

        self._section("Compliance Matrix")
        compliance = self.report["compliance_rows"][:30]
        if compliance:
            for row in compliance:
                self._compliance_row(row)
        else:
            self._paragraph("No compliance mappings were generated for the current findings.")

        self._section("Finding Details")
        details = self.report["finding_details"][:35]
        if details:
            for detail in details:
                self._finding_detail(detail)
        else:
            self._paragraph("No findings in scope.")

        self._finish_page()
        return self._build_pdf()

    def _cover(self) -> None:
        self._fill_rect(0, self.height - 210, self.width, 210, (0.05, 0.45, 0.46))
        self._fill_rect(0, self.height - 210, self.width, 58, (0.12, 0.49, 0.91))
        self._text(46, 760, "NyuwunSewu", 15, "F2", (1, 1, 1))
        self._text(46, 728, self._clean(self.report["title"])[:72], 25, "F2", (1, 1, 1))
        self._text(46, 696, self._clean(self.report["report_type"]), 12, "F1", (0.87, 0.97, 0.98))
        scope = self.report["scope"]
        target = scope.get("target_url") or "Project aggregate"
        self._text(46, 654, f"Target: {self._clean(target)[:78]}", 11, "F1", (1, 1, 1))
        self._text(
            46,
            634,
            f"Generated: {ReportingEngine()._format_datetime(self.report['generated_at'])}",
            10,
            "F1",
            (0.88, 0.97, 0.98),
        )
        self.y = 560
        summary = self.report["summary"]
        self._metric_row(
            [
                ("Findings", str(summary["total_findings"]), "validated"),
                ("Exploits", str(summary["exploit_count"]), "confirmed execution"),
                ("Paths", str(scope.get("path_count", 0)), "discovered"),
                ("Controls", str(summary["compliance_control_count"]), "mapped"),
            ]
        )

    def _new_page(self, *, cover: bool = False) -> None:
        if self.ops:
            self._finish_page()
        self.page_number += 1
        self.ops = []
        self.y = self.height - self.margin
        self._fill_rect(0, 0, self.width, self.height, (0.98, 0.99, 1.0))
        if not cover:
            self._fill_rect(0, self.height - 58, self.width, 58, (0.05, 0.45, 0.46))
            self._text(42, 808, "NyuwunSewu Security Validation Report", 10, "F2", (1, 1, 1))
            self._text(430, 808, f"Page {self.page_number}", 9, "F1", (0.88, 0.97, 0.98))
            self.y = self.height - 86

    def _finish_page(self) -> None:
        if self.ops:
            self._text(42, 24, "Confidential - generated from scoped scan evidence", 8, "F1", (0.38, 0.45, 0.55))
            self.pages.append("\n".join(self.ops))
            self.ops = []

    def _section(self, title: str) -> None:
        self._ensure(54)
        self.y -= 12
        self._text(self.margin, self.y, title, 15, "F2", (0.07, 0.12, 0.20))
        self.y -= 11
        self._fill_rect(self.margin, self.y, 125, 2, (0.05, 0.58, 0.53))
        self.y -= 22

    def _metric_row(self, metrics: list[tuple[str, str, str]]) -> None:
        self._ensure(88)
        gap = 10
        card_w = (self.width - (self.margin * 2) - gap * (len(metrics) - 1)) / len(metrics)
        x = self.margin
        for label, value, caption in metrics:
            self._fill_rect(x, self.y - 62, card_w, 62, (1, 1, 1))
            self._stroke_rect(x, self.y - 62, card_w, 62, (0.84, 0.88, 0.92))
            self._text(x + 10, self.y - 20, self._clean(value)[:16], 17, "F2", (0.05, 0.45, 0.46))
            self._text(x + 10, self.y - 38, self._clean(label)[:24], 9, "F2", (0.07, 0.12, 0.20))
            self._text(x + 10, self.y - 52, self._clean(caption)[:30], 7, "F1", (0.39, 0.45, 0.55))
            x += card_w + gap
        self.y -= 82

    def _severity_distribution(self) -> None:
        counts = self.report["severity_counts"]
        self._ensure(66)
        self._text(self.margin, self.y, "Severity Distribution", 11, "F2", (0.07, 0.12, 0.20))
        self.y -= 18
        total = max(sum(counts.values()), 1)
        for severity in SEVERITY_ORDER:
            count = counts.get(severity, 0)
            color = SEVERITY_COLORS.get(severity, (0.4, 0.45, 0.55))
            self._text(self.margin, self.y, severity.title(), 8, "F2", color)
            self._fill_rect(self.margin + 70, self.y - 7, 270, 8, (0.90, 0.93, 0.96))
            self._fill_rect(self.margin + 70, self.y - 7, max(4, 270 * count / total), 8, color)
            self._text(self.margin + 355, self.y, str(count), 8, "F1", (0.07, 0.12, 0.20))
            self.y -= 15
        self.y -= 10

    def _key_values(self, items: list[tuple[str, Any]]) -> None:
        for key, value in items:
            self._ensure(24)
            self._text(self.margin, self.y, self._clean(key), 8, "F2", (0.39, 0.45, 0.55))
            self._wrapped_text(self.margin + 118, self.y, self._clean(value or "N/A"), 350, 8, "F1")
            self.y -= 8
        self.y -= 8

    def _endpoint_row(self, row: dict[str, Any]) -> None:
        self._ensure(50)
        severity = row.get("highest_severity") or "info"
        color = SEVERITY_COLORS.get(str(severity).lower(), (0.39, 0.45, 0.55))
        self._fill_rect(self.margin, self.y - 38, self.width - self.margin * 2, 38, (1, 1, 1))
        self._fill_rect(self.margin, self.y - 38, 4, 38, color)
        self._stroke_rect(self.margin, self.y - 38, self.width - self.margin * 2, 38, (0.86, 0.89, 0.93))
        self._text(self.margin + 10, self.y - 14, f"{row['method']} {self._clean(row['path'])[:72]}", 8, "F2", (0.07, 0.12, 0.20))
        meta = f"status {row.get('status_code') or 'N/A'} | risk {row.get('risk_score')} | findings {row.get('finding_count')}"
        self._text(self.margin + 10, self.y - 29, meta, 7, "F1", (0.39, 0.45, 0.55))
        self.y -= 45

    def _finding_brief(self, item: dict[str, Any]) -> None:
        self._ensure(58)
        color = SEVERITY_COLORS.get(item.get("severity"), (0.39, 0.45, 0.55))
        self._text(self.margin, self.y, item["severity"].upper(), 8, "F2", color)
        self._wrapped_text(self.margin + 76, self.y, item["title"], 400, 9, "F2")
        self._wrapped_text(
            self.margin + 76,
            self.y - 13,
            f"{item.get('method') or 'GET'} {item.get('endpoint_path') or item.get('endpoint_url') or 'N/A'}",
            400,
            7,
            "F1",
            (0.39, 0.45, 0.55),
        )
        if item.get("validation_mode"):
            self._text(self.margin + 76, self.y - 27, f"mode: {item['validation_mode']}", 7, "F1", (0.05, 0.45, 0.46))
        self.y -= 48

    def _compliance_row(self, row: dict[str, Any]) -> None:
        self._ensure(50)
        text = f"{row['framework']} {row['article_or_control']} - {row['finding_count']} finding(s)"
        self._text(self.margin, self.y, text[:92], 8, "F2", (0.07, 0.12, 0.20))
        risk = row.get("business_risk") or row.get("privacy_risk") or row.get("legal_risk") or ""
        self._wrapped_text(self.margin + 16, self.y - 13, risk, 460, 7, "F1", (0.39, 0.45, 0.55))
        self.y -= 38

    def _finding_detail(self, detail: dict[str, Any]) -> None:
        self._ensure(118)
        color = SEVERITY_COLORS.get(detail.get("severity"), (0.39, 0.45, 0.55))
        self._fill_rect(self.margin, self.y - 20, self.width - self.margin * 2, 20, color)
        self._text(self.margin + 8, self.y - 13, detail["severity"].upper(), 8, "F2", (1, 1, 1))
        self._wrapped_text(self.margin + 82, self.y - 13, detail["title"], 390, 8, "F2", (1, 1, 1))
        self.y -= 31
        self._wrapped_text(self.margin, self.y, f"Endpoint: {detail.get('endpoint_url') or 'N/A'}", 500, 7, "F1", (0.39, 0.45, 0.55))
        self._wrapped_text(self.margin, self.y - 13, self._clean(detail.get("description", ""))[:520], 500, 7, "F1")
        self.y -= 54
        if detail.get("reasoning"):
            self._text(self.margin, self.y, "Evidence reasoning", 8, "F2", (0.07, 0.12, 0.20))
            self.y -= 12
            for reason in detail["reasoning"][:3]:
                self._wrapped_text(self.margin + 10, self.y, f"- {reason}", 475, 7, "F1")
                self.y -= 12
        self._text(self.margin, self.y, "Remediation", 8, "F2", (0.07, 0.12, 0.20))
        self._wrapped_text(self.margin + 10, self.y - 12, self._clean(detail.get("remediation", ""))[:360], 475, 7, "F1")
        self.y -= 46

    def _paragraph(self, text: str) -> None:
        self._wrapped_text(self.margin, self.y, self._clean(text), self.width - self.margin * 2, 9, "F1")
        self.y -= 18

    def _wrapped_text(
        self,
        x: float,
        y: float,
        text: str,
        width: float,
        size: int,
        font: str = "F1",
        color: tuple[float, float, float] = (0.07, 0.12, 0.20),
    ) -> int:
        text = self._clean(text)
        max_chars = max(18, int(width / (size * 0.48)))
        lines = textwrap.wrap(text, width=max_chars) or [""]
        cursor = y
        for line in lines[:8]:
            self._text(x, cursor, line, size, font, color)
            cursor -= size + 3
        return len(lines)

    def _ensure(self, needed: int) -> None:
        if self.y - needed < self.margin + 20:
            self._new_page()

    def _text(
        self,
        x: float,
        y: float,
        text: str,
        size: int,
        font: str,
        color: tuple[float, float, float],
    ) -> None:
        r, g, b = color
        self.ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg")
        self.ops.append(f"BT /{font} {size} Tf {x:.1f} {y:.1f} Td ({self._escape(text)}) Tj ET")

    def _fill_rect(self, x: float, y: float, w: float, h: float, color: tuple[float, float, float]) -> None:
        r, g, b = color
        self.ops.append(f"{r:.3f} {g:.3f} {b:.3f} rg {x:.1f} {y:.1f} {w:.1f} {h:.1f} re f")

    def _stroke_rect(self, x: float, y: float, w: float, h: float, color: tuple[float, float, float]) -> None:
        r, g, b = color
        self.ops.append(f"{r:.3f} {g:.3f} {b:.3f} RG 0.8 w {x:.1f} {y:.1f} {w:.1f} {h:.1f} re S")

    def _build_pdf(self) -> bytes:
        objects: list[bytes] = [
            b"<< /Type /Catalog /Pages 2 0 R >>",
            f"<< /Type /Pages /Kids [{' '.join(f'{3 + i} 0 R' for i in range(len(self.pages)))}] /Count {len(self.pages)} >>".encode(),
        ]
        page_objects: list[bytes] = []
        content_objects: list[bytes] = []
        font_object_id = 3 + len(self.pages) * 2
        for index, stream_text in enumerate(self.pages):
            page_id = 3 + index
            content_id = 3 + len(self.pages) + index
            stream = stream_text.encode("latin-1", errors="replace")
            page_objects.append(
                (
                    f"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 {self.width} {self.height}] "
                    f"/Resources << /Font << /F1 {font_object_id} 0 R /F2 {font_object_id + 1} 0 R >> >> "
                    f"/Contents {content_id} 0 R >>"
                ).encode()
            )
            content_objects.append(
                b"<< /Length " + str(len(stream)).encode() + b" >>\nstream\n" + stream + b"\nendstream"
            )
        objects.extend(page_objects)
        objects.extend(content_objects)
        objects.extend(
            [
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
                b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold >>",
            ]
        )
        pdf = bytearray(b"%PDF-1.4\n")
        offsets = [0]
        for index, obj in enumerate(objects, start=1):
            offsets.append(len(pdf))
            pdf.extend(f"{index} 0 obj\n".encode())
            pdf.extend(obj)
            pdf.extend(b"\nendobj\n")
        xref_offset = len(pdf)
        pdf.extend(f"xref\n0 {len(objects) + 1}\n".encode())
        pdf.extend(b"0000000000 65535 f \n")
        for offset in offsets[1:]:
            pdf.extend(f"{offset:010d} 00000 n \n".encode())
        pdf.extend(
            f"trailer << /Size {len(objects) + 1} /Root 1 0 R >>\n"
            f"startxref\n{xref_offset}\n%%EOF\n".encode()
        )
        return bytes(pdf)

    def _clean(self, value: Any) -> str:
        text = re.sub(r"\s+", " ", str(value or "")).strip()
        return text.replace("–", "-").replace("—", "-").replace("•", "-")

    def _escape(self, value: Any) -> str:
        text = self._clean(value)
        return text.replace("\\", "\\\\").replace("(", "\\(").replace(")", "\\)")
