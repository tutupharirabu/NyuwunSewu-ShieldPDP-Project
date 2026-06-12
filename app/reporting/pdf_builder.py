"""Low-level PDF report builder (hand-rolled PDF primitives).

Extracted from ``engine`` so the ~580-line drawing layer (cover, pages,
rects, text wrapping, byte assembly) lives apart from report data
orchestration. Depends only on ``formatting`` — never back on ``engine``.
"""

from __future__ import annotations

import re
import textwrap
from typing import Any

from app.reporting.formatting import SEVERITY_COLORS, SEVERITY_ORDER, format_datetime


class PDFReportBuilder:
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
                (
                    "Critical/High",
                    str(summary["critical_high_count"]),
                    "Prioritized exposure",
                ),
                (
                    "Endpoints",
                    str(summary["endpoint_count"]),
                    "Discovered affected items",
                ),
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
                (
                    "Started",
                    format_datetime(scope.get("scan_started_at")),
                ),
                (
                    "Finished",
                    format_datetime(scope.get("scan_finished_at")),
                ),
                ("Policy", scope.get("policy_name") or "N/A"),
                (
                    "Allowed Domains",
                    ", ".join(scope.get("allowed_domains") or [])
                    or "Default target host",
                ),
            ]
        )

        self._section("Affected Items / Discovered Paths")
        endpoint_rows = self.report["endpoint_rows"][:45]
        if endpoint_rows:
            for row in endpoint_rows:
                self._endpoint_row(row)
        else:
            self._paragraph("No endpoint inventory was available for this report.")

        self._section("Confirmed Exploits and Attack Chains")
        exploits = self.report["exploit_findings"][:20]
        if exploits:
            for item in exploits:
                self._finding_brief(item)
        else:
            self._paragraph(
                "No confirmed exploit execution was recorded in this report scope."
            )

        self._section("Remediation Matrix")
        remediation = self.report.get("remediation_matrix") or []
        if remediation:
            for item in remediation[:15]:
                self._remediation_item(item)
        else:
            self._paragraph(
                "No remediation items were generated for the current findings."
            )

        self._section("Compliance Matrix")
        compliance = self.report["compliance_rows"][:30]
        if compliance:
            for row in compliance:
                self._compliance_row(row)
        else:
            self._paragraph(
                "No compliance mappings were generated for the current findings."
            )

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
        self._text(
            46,
            696,
            self._clean(self.report["report_type"]),
            12,
            "F1",
            (0.87, 0.97, 0.98),
        )
        scope = self.report["scope"]
        target = scope.get("target_url") or "Project aggregate"
        self._text(46, 654, f"Target: {self._clean(target)[:78]}", 11, "F1", (1, 1, 1))
        self._text(
            46,
            634,
            f"Generated: {format_datetime(self.report['generated_at'])}",
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
            self._text(
                42, 808, "NyuwunSewu Security Validation Report", 10, "F2", (1, 1, 1)
            )
            self._text(
                430, 808, f"Page {self.page_number}", 9, "F1", (0.88, 0.97, 0.98)
            )
            self.y = self.height - 86

    def _finish_page(self) -> None:
        if self.ops:
            self._text(
                42,
                24,
                "Confidential - generated from scoped scan evidence",
                8,
                "F1",
                (0.38, 0.45, 0.55),
            )
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
        card_w = (self.width - (self.margin * 2) - gap * (len(metrics) - 1)) / len(
            metrics
        )
        x = self.margin
        for label, value, caption in metrics:
            self._fill_rect(x, self.y - 62, card_w, 62, (1, 1, 1))
            self._stroke_rect(x, self.y - 62, card_w, 62, (0.84, 0.88, 0.92))
            self._text(
                x + 10,
                self.y - 20,
                self._clean(value)[:16],
                17,
                "F2",
                (0.05, 0.45, 0.46),
            )
            self._text(
                x + 10,
                self.y - 38,
                self._clean(label)[:24],
                9,
                "F2",
                (0.07, 0.12, 0.20),
            )
            self._text(
                x + 10,
                self.y - 52,
                self._clean(caption)[:30],
                7,
                "F1",
                (0.39, 0.45, 0.55),
            )
            x += card_w + gap
        self.y -= 82

    def _severity_distribution(self) -> None:
        counts = self.report["severity_counts"]
        self._ensure(66)
        self._text(
            self.margin, self.y, "Severity Distribution", 11, "F2", (0.07, 0.12, 0.20)
        )
        self.y -= 18
        total = max(sum(counts.values()), 1)
        for severity in SEVERITY_ORDER:
            count = counts.get(severity, 0)
            color = SEVERITY_COLORS.get(severity, (0.4, 0.45, 0.55))
            self._text(self.margin, self.y, severity.title(), 8, "F2", color)
            self._fill_rect(self.margin + 70, self.y - 7, 270, 8, (0.90, 0.93, 0.96))
            self._fill_rect(
                self.margin + 70, self.y - 7, max(4, 270 * count / total), 8, color
            )
            self._text(
                self.margin + 355, self.y, str(count), 8, "F1", (0.07, 0.12, 0.20)
            )
            self.y -= 15
        self.y -= 10

    def _key_values(self, items: list[tuple[str, Any]]) -> None:
        for key, value in items:
            self._ensure(24)
            self._text(
                self.margin, self.y, self._clean(key), 8, "F2", (0.39, 0.45, 0.55)
            )
            self._wrapped_text(
                self.margin + 118, self.y, self._clean(value or "N/A"), 350, 8, "F1"
            )
            self.y -= 8
        self.y -= 8

    def _endpoint_row(self, row: dict[str, Any]) -> None:
        self._ensure(50)
        severity = row.get("highest_severity") or "info"
        color = SEVERITY_COLORS.get(str(severity).lower(), (0.39, 0.45, 0.55))
        self._fill_rect(
            self.margin, self.y - 38, self.width - self.margin * 2, 38, (1, 1, 1)
        )
        self._fill_rect(self.margin, self.y - 38, 4, 38, color)
        self._stroke_rect(
            self.margin,
            self.y - 38,
            self.width - self.margin * 2,
            38,
            (0.86, 0.89, 0.93),
        )
        self._text(
            self.margin + 10,
            self.y - 14,
            f"{row['method']} {self._clean(row['path'])[:72]}",
            8,
            "F2",
            (0.07, 0.12, 0.20),
        )
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
            self._text(
                self.margin + 76,
                self.y - 27,
                f"mode: {item['validation_mode']}",
                7,
                "F1",
                (0.05, 0.45, 0.46),
            )
        self.y -= 48

    def _compliance_row(self, row: dict[str, Any]) -> None:
        self._ensure(50)
        text = f"{row['framework']} {row['article_or_control']} - {row['finding_count']} finding(s)"
        self._text(self.margin, self.y, text[:92], 8, "F2", (0.07, 0.12, 0.20))
        risk = (
            row.get("business_risk")
            or row.get("privacy_risk")
            or row.get("legal_risk")
            or ""
        )
        self._wrapped_text(
            self.margin + 16, self.y - 13, risk, 460, 7, "F1", (0.39, 0.45, 0.55)
        )
        self.y -= 38

    def _remediation_item(self, item: dict[str, Any]) -> None:
        """Render a single remediation matrix item in the PDF."""
        self._ensure(100)
        priority = item.get("priority_level", "")
        domain = item.get("domain", "")
        timeline = item.get("recommended_timeline", "")
        effort = item.get("effort_estimate", "")
        effort_days = item.get("effort_days", "")
        finding_count = item.get("finding_count", 0)
        max_risk = item.get("max_risk_score", 0)
        action = item.get("action", "")
        finding_types = item.get("finding_types", [])
        compliance_impact = item.get("compliance_impact", [])

        # Priority badge
        p_color = {
            "P1 - Critical": (0.86, 0.15, 0.15),
            "P2 - High": (0.92, 0.31, 0.18),
            "P3 - Medium": (0.86, 0.54, 0.13),
            "P4 - Low": (0.08, 0.58, 0.53),
        }.get(priority, (0.39, 0.45, 0.55))

        rank = item.get("priority_rank", 0)
        self._fill_rect(self.margin, self.y - 18, 28, 18, p_color)
        self._text(self.margin + 4, self.y - 12, f"#{rank}", 10, "F2", (1, 1, 1))

        # Domain and priority
        self._text(self.margin + 34, self.y - 12, domain, 10, "F2", (0.07, 0.12, 0.20))
        self._text(
            self.margin + 34,
            self.y - 26,
            f"{priority} | {finding_count} findings | risk {max_risk}",
            7,
            "F1",
            (0.39, 0.45, 0.55),
        )
        self.y -= 30

        # Timeline and effort
        self._text(
            self.margin + 10,
            self.y,
            f"Timeline: {timeline} | Effort: {effort} ({effort_days} days)",
            7,
            "F2",
            (0.05, 0.45, 0.46),
        )
        self.y -= 14

        # Action description
        self._wrapped_text(
            self.margin + 10, self.y, action, 480, 7, "F1", (0.07, 0.12, 0.20)
        )
        self.y -= 14

        # Finding types
        if finding_types:
            types_str = ", ".join(finding_types[:5])
            self._text(
                self.margin + 10,
                self.y,
                f"Types: {types_str[:100]}",
                6,
                "F1",
                (0.39, 0.45, 0.55),
            )
            self.y -= 10

        # Compliance impact
        if compliance_impact:
            comp_str = ", ".join(compliance_impact[:4])
            self._text(
                self.margin + 10,
                self.y,
                f"UU PDP: {comp_str[:100]}",
                6,
                "F1",
                (0.39, 0.45, 0.55),
            )
            self.y -= 10

        self.y -= 6

    def _finding_detail(self, detail: dict[str, Any]) -> None:
        self._ensure(132)
        severity = str(detail.get("severity") or "info").lower()
        color = SEVERITY_COLORS.get(severity, (0.39, 0.45, 0.55))
        self._fill_rect(
            self.margin, self.y - 20, self.width - self.margin * 2, 20, color
        )
        self._text(
            self.margin + 8, self.y - 13, severity.upper(), 8, "F2", (1, 1, 1)
        )
        self._wrapped_text(
            self.margin + 82,
            self.y - 13,
            detail.get("title") or "Finding",
            390,
            8,
            "F2",
            (1, 1, 1),
        )
        self.y -= 31
        self._wrapped_text(
            self.margin,
            self.y,
            f"Endpoint: {detail.get('endpoint_url') or detail.get('endpoint_path') or 'N/A'}",
            500,
            7,
            "F1",
            (0.39, 0.45, 0.55),
        )
        self.y -= 20
        self._detail_block("Impact", detail.get("impact", ""), max_chars=520)
        if detail.get("reasoning"):
            self._detail_block(
                "Reasoning",
                " ".join(f"- {reason}" for reason in detail["reasoning"][:4]),
                max_chars=760,
            )
        self._detail_block(
            "HTTP Evidence Request",
            detail.get("http_request", ""),
            size=6,
            max_chars=1100,
        )
        self._detail_block(
            "HTTP Evidence Response",
            detail.get("http_response", ""),
            size=6,
            max_chars=1100,
        )

        compliance = detail.get("deep_compliance") or {}
        self._detail_block(
            "Executive Risk Summary",
            compliance.get("executive_risk_summary", ""),
            max_chars=900,
        )
        self._detail_block(
            "Potential Data Protection Impact",
            self._format_data_impact(
                compliance.get("potential_data_protection_impact") or {}
            ),
            max_chars=900,
        )
        self._detail_block(
            "Business Impact",
            self._format_list(compliance.get("business_impact") or []),
            max_chars=760,
        )
        self._detail_block(
            "Affected Assets",
            self._format_assets(compliance.get("affected_assets") or []),
            max_chars=760,
        )
        self._detail_block(
            "Compliance Gap Analysis",
            self._format_gap(compliance.get("gap_analysis") or {}),
            max_chars=1000,
        )
        self._detail_block(
            "Regulatory and Control Analysis",
            self._format_regulatory(compliance.get("regulatory_analysis") or []),
            max_chars=1500,
        )
        self._detail_block(
            "Attack Scenario",
            self._format_list(compliance.get("attack_scenario") or []),
            max_chars=1000,
        )
        self._detail_block(
            "Worst Case Scenario",
            self._format_list(compliance.get("worst_case_scenario") or []),
            max_chars=900,
        )
        confidence = compliance.get("compliance_confidence") or {}
        priority = compliance.get("remediation_priority") or {}
        self._detail_block(
            "Compliance Confidence",
            f"{confidence.get('level', 'N/A')} - {confidence.get('justification', '')}",
            max_chars=520,
        )
        self._detail_block(
            "Remediation Priority",
            f"{priority.get('level', 'N/A')} - {priority.get('reason', '')}",
            max_chars=520,
        )

        remediation_steps = detail.get("remediation_steps") or []
        if remediation_steps:
            remediation_text = " ".join(
                f"{index}. {step}"
                for index, step in enumerate(remediation_steps[:6], start=1)
            )
        else:
            remediation_text = detail.get("remediation", "")
        self._detail_block("Remediation", remediation_text, max_chars=760)
        self._detail_block(
            "Contoh Code Aman",
            detail.get("secure_code_example", ""),
            size=6,
            max_chars=760,
        )
        self.y -= 8

    def _detail_block(
        self,
        label: str,
        text: Any,
        *,
        size: int = 7,
        max_chars: int = 700,
    ) -> None:
        self._ensure(54)
        self._text(self.margin, self.y, label, 8, "F2", (0.07, 0.12, 0.20))
        self.y -= 12
        line_count = self._wrapped_text(
            self.margin + 10,
            self.y,
            self._clean(text)[:max_chars],
            475,
            size,
            "F1",
            (0.07, 0.12, 0.20),
        )
        self.y -= min(line_count, 8) * (size + 3) + 8

    def _format_list(self, items: list[Any]) -> str:
        return " ".join(f"{index}. {self._clean(item)}" for index, item in enumerate(items, start=1))

    def _format_data_impact(self, impact: dict[str, Any]) -> str:
        parts = [str(impact.get("summary") or "")]
        labels = [
            ("Personal", impact.get("personal_data") or []),
            ("Authentication", impact.get("authentication_data") or []),
            ("Financial", impact.get("financial_data") or []),
            ("Session/Token", impact.get("session_or_token_data") or []),
        ]
        for label, values in labels:
            if values:
                parts.append(f"{label}: {', '.join(str(value) for value in values)}")
        return " | ".join(part for part in parts if part)

    def _format_assets(self, assets: list[dict[str, Any]]) -> str:
        return " ".join(
            f"{index}. {item.get('asset', 'Asset')} -> {item.get('impact', 'Impact')}"
            for index, item in enumerate(assets, start=1)
        )

    def _format_gap(self, gap: dict[str, Any]) -> str:
        observed = self._format_list(gap.get("observed") or [])
        expected = self._format_list(gap.get("expected") or [])
        return (
            f"Observed: {observed} Expected: {expected} "
            f"Gap: {gap.get('gap', '')}"
        )

    def _format_regulatory(self, rows: list[dict[str, Any]]) -> str:
        rendered: list[str] = []
        for row in rows[:8]:
            rendered.append(
                f"{row.get('framework')} {row.get('control')} | "
                f"Status: {row.get('status')} | Confidence: {row.get('confidence')} | "
                f"Requirement: {row.get('requirement')} | Observed: {row.get('observed')} | "
                f"Potential Impact: {row.get('potential_impact')}"
            )
        return " ".join(rendered)

    def _paragraph(self, text: str) -> None:
        self._wrapped_text(
            self.margin,
            self.y,
            self._clean(text),
            self.width - self.margin * 2,
            9,
            "F1",
        )
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
        self.ops.append(
            f"BT /{font} {size} Tf {x:.1f} {y:.1f} Td ({self._escape(text)}) Tj ET"
        )

    def _fill_rect(
        self, x: float, y: float, w: float, h: float, color: tuple[float, float, float]
    ) -> None:
        r, g, b = color
        self.ops.append(
            f"{r:.3f} {g:.3f} {b:.3f} rg {x:.1f} {y:.1f} {w:.1f} {h:.1f} re f"
        )

    def _stroke_rect(
        self, x: float, y: float, w: float, h: float, color: tuple[float, float, float]
    ) -> None:
        r, g, b = color
        self.ops.append(
            f"{r:.3f} {g:.3f} {b:.3f} RG 0.8 w {x:.1f} {y:.1f} {w:.1f} {h:.1f} re S"
        )

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
                b"<< /Length "
                + str(len(stream)).encode()
                + b" >>\nstream\n"
                + stream
                + b"\nendstream"
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
