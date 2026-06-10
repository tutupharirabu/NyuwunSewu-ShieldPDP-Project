from __future__ import annotations

import time
from urllib.parse import urljoin

import httpx

from app.validation.data_rights.base import DataRightsTestResult


class RightToAccessMixin:
    async def test_right_to_access(
        self,
        target: str,
        auth_headers: dict[str, str] | None = None,
        access_endpoint: str | None = None,
    ) -> DataRightsTestResult:
        """
        Test right to access (Pasal 22 UU PDP) — personal data access.

        Runs four checks: endpoint discovery, data completeness,
        data format usability, and response time.
        """
        findings: list[dict] = []
        tests_passed = 0
        tests_run = 0
        score = 0.0
        evidence: dict = {}
        response_time_ms: float | None = None

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            # Test 1: Data Export Endpoint Discovery (25 points)
            tests_run += 1
            found_endpoint: str | None = None

            if access_endpoint:
                full_url = urljoin(
                    target.rstrip("/") + "/", access_endpoint.lstrip("/")
                )
                if not self.scope_guard or await self.scope_guard.is_url_allowed(
                    full_url
                ):
                    found_endpoint = access_endpoint

            if not found_endpoint:
                for pattern in self.ACCESS_ENDPOINTS:
                    url = self._resolve_endpoint(target, pattern)
                    if self.scope_guard and not await self.scope_guard.is_url_allowed(
                        url
                    ):
                        continue
                    try:
                        resp = await client.head(url, headers=auth_headers)
                        if resp.status_code in {200, 204, 405}:
                            found_endpoint = pattern
                            evidence["discovered_endpoint"] = pattern
                            break
                    except (
                        httpx.HTTPError,
                        httpx.TimeoutException,
                        httpx.NetworkError,
                    ):
                        continue

            if found_endpoint:
                tests_passed += 1
                score += 25
                findings.append(
                    {
                        "test_name": "data_export_endpoint_discovery",
                        "status": "passed",
                        "details": f"Found data access endpoint: {found_endpoint}",
                    }
                )
            else:
                findings.append(
                    {
                        "test_name": "data_export_endpoint_discovery",
                        "status": "failed",
                        "details": "No data export endpoint discovered",
                    }
                )
                return DataRightsTestResult(
                    right_type="right_to_access",
                    status=self._determine_status(score),
                    score=score,
                    tests_run=tests_run,
                    tests_passed=tests_passed,
                    tests_failed=tests_run - tests_passed,
                    findings=findings,
                    evidence=evidence,
                )

            # Perform the actual GET request for subsequent tests
            access_url = self._resolve_endpoint(target, found_endpoint)
            access_response: httpx.Response | None = None
            if not self.scope_guard or await self.scope_guard.is_url_allowed(
                access_url
            ):
                try:
                    start = time.perf_counter()
                    access_response = await self._make_request(
                        client, "GET", access_url, auth_headers
                    )
                    response_time_ms = (time.perf_counter() - start) * 1000
                    evidence["access_response_time_ms"] = response_time_ms
                    if access_response:
                        evidence["access_response_status"] = access_response.status_code
                except Exception:
                    pass

            # Test 2: Data Completeness (25 points)
            tests_run += 1
            if access_response and access_response.status_code == 200:
                body = access_response.text
                body_lower = body.lower()
                found_pii_fields = {f for f in self.PII_FIELDS if f in body_lower}
                pii_count = len(found_pii_fields)

                if pii_count >= 3:
                    tests_passed += 1
                    score += 25
                    evidence["pii_fields_found"] = sorted(found_pii_fields)
                    findings.append(
                        {
                            "test_name": "data_completeness",
                            "status": "passed",
                            "details": f"Comprehensive personal data returned ({pii_count} PII fields found)",
                        }
                    )
                elif pii_count >= 1:
                    score += 12
                    evidence["pii_fields_found"] = sorted(found_pii_fields)
                    findings.append(
                        {
                            "test_name": "data_completeness",
                            "status": "partial",
                            "details": f"Partial personal data returned ({pii_count} PII fields found)",
                        }
                    )
                else:
                    findings.append(
                        {
                            "test_name": "data_completeness",
                            "status": "failed",
                            "details": "No recognizable personal data fields found in response",
                        }
                    )
            else:
                findings.append(
                    {
                        "test_name": "data_completeness",
                        "status": "failed",
                        "details": "Could not retrieve data to check completeness",
                    }
                )

            # Test 3: Data Format Usability (25 points)
            tests_run += 1
            if access_response and access_response.status_code == 200:
                content_type = access_response.headers.get("content-type", "").lower()
                body = access_response.text.strip()

                if "json" in content_type or body.startswith(("{", "[")):
                    tests_passed += 1
                    score += 25
                    evidence["data_format"] = "json"
                    findings.append(
                        {
                            "test_name": "data_format_usability",
                            "status": "passed",
                            "details": "Data returned in JSON format (highly usable)",
                        }
                    )
                elif "csv" in content_type or body.startswith(("id,", '"')):
                    tests_passed += 1
                    score += 25
                    evidence["data_format"] = "csv"
                    findings.append(
                        {
                            "test_name": "data_format_usability",
                            "status": "passed",
                            "details": "Data returned in CSV format (usable)",
                        }
                    )
                elif (
                    "xml" in content_type
                    or body.startswith("<?xml")
                    or body.startswith("<")
                ):
                    score += 15
                    evidence["data_format"] = "xml"
                    findings.append(
                        {
                            "test_name": "data_format_usability",
                            "status": "partial",
                            "details": "Data returned in XML format (acceptable)",
                        }
                    )
                elif "html" in content_type:
                    findings.append(
                        {
                            "test_name": "data_format_usability",
                            "status": "failed",
                            "details": "Data returned in HTML format only (poor usability)",
                        }
                    )
                else:
                    findings.append(
                        {
                            "test_name": "data_format_usability",
                            "status": "failed",
                            "details": f"Unknown data format (content-type: {content_type})",
                        }
                    )
            else:
                findings.append(
                    {
                        "test_name": "data_format_usability",
                        "status": "failed",
                        "details": "Could not retrieve data to check format",
                    }
                )

            # Test 4: Response Time (25 points)
            tests_run += 1
            if response_time_ms is not None:
                if response_time_ms < 5000:
                    tests_passed += 1
                    score += 25
                    findings.append(
                        {
                            "test_name": "response_time",
                            "status": "passed",
                            "details": f"Excellent response time: {response_time_ms:.0f}ms (< 5s)",
                        }
                    )
                elif response_time_ms < 30000:
                    tests_passed += 1
                    score += 25
                    findings.append(
                        {
                            "test_name": "response_time",
                            "status": "passed",
                            "details": f"Good response time: {response_time_ms:.0f}ms (< 30s)",
                        }
                    )
                else:
                    findings.append(
                        {
                            "test_name": "response_time",
                            "status": "failed",
                            "details": f"Poor response time: {response_time_ms:.0f}ms (> 30s)",
                        }
                    )
            else:
                findings.append(
                    {
                        "test_name": "response_time",
                        "status": "not_testable",
                        "details": "Could not measure response time",
                    }
                )

        status = self._determine_status(score)

        return DataRightsTestResult(
            right_type="right_to_access",
            status=status,
            score=score,
            tests_run=tests_run,
            tests_passed=tests_passed,
            tests_failed=tests_run - tests_passed,
            findings=findings,
            response_time_ms=response_time_ms,
            evidence=evidence,
        )

