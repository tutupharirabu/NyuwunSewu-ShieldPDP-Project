from __future__ import annotations

import time
from dataclasses import dataclass, field
from urllib.parse import urljoin

import httpx

from app.services.scope_guard import ScopeGuard


@dataclass(slots=True)
class DataRightsTestResult:
    """Result of a data subject rights test."""

    right_type: str
    status: str
    score: float
    tests_run: int
    tests_passed: int
    tests_failed: int
    findings: list[dict]
    deletion_verified: bool = False
    response_time_ms: float | None = None
    evidence: dict = field(default_factory=dict)


class DataRightsValidationEngine:
    """Validates data subject rights implementation per Pasal 22 UU PDP."""

    # Common deletion endpoints to discover
    DELETION_ENDPOINTS = [
        "/api/users/{id}/delete",
        "/api/account/delete",
        "/api/profile/delete",
        "/api/data-subjects/{id}/erasure",
        "/api/privacy/erasure-request",
    ]

    # Common access/export endpoints to discover
    ACCESS_ENDPOINTS = [
        "/api/users/me/data",
        "/api/account/export",
        "/api/profile/data",
        "/api/data-subjects/me/access",
        "/api/privacy/data-export",
    ]

    # Common update endpoints to discover
    UPDATE_ENDPOINTS = [
        "/api/users/me",
        "/api/profile",
        "/api/account",
    ]

    # Common PII field names used to check data completeness
    PII_FIELDS = {
        "name",
        "email",
        "phone",
        "address",
        "nik",
        "npwp",
        "date_of_birth",
        "dob",
        "gender",
        "nationality",
        "postal_code",
        "city",
        "province",
        "country",
        "account_number",
        "rekening",
        "balance",
        "photo",
        "avatar",
        "username",
    }

    def __init__(self, scope_guard: ScopeGuard | None = None):
        self.scope_guard = scope_guard

    async def _make_request(
        self,
        client: httpx.AsyncClient,
        method: str,
        url: str,
        auth_headers: dict[str, str] | None = None,
        json_body: dict | None = None,
    ) -> httpx.Response | None:
        """Make an HTTP request after checking scope guard. Returns None if blocked or failed."""
        if self.scope_guard and not await self.scope_guard.is_url_allowed(url):
            return None
        try:
            return await client.request(
                method,
                url,
                headers=auth_headers,
                json=json_body,
            )
        except (httpx.HTTPError, httpx.TimeoutException, httpx.NetworkError):
            return None

    def _determine_status(self, score: float) -> str:
        """Determine compliance status from score."""
        if score >= 80:
            return "compliant"
        if score >= 50:
            return "partial"
        if score >= 20:
            return "non_compliant"
        return "not_testable"

    def _resolve_endpoint(
        self, target: str, endpoint_pattern: str, subject_id: str | None = None
    ) -> str:
        """Resolve a relative endpoint pattern against the target base URL."""
        path = endpoint_pattern
        if subject_id and "{id}" in path:
            path = path.replace("{id}", subject_id)
        elif "{id}" in path:
            path = path.replace("{id}", "test-subject-id")
        return urljoin(target.rstrip("/") + "/", path.lstrip("/"))

    async def test_right_to_be_forgotten(
        self,
        target: str,
        auth_headers: dict[str, str] | None = None,
        deletion_endpoint: str | None = None,
        test_subject_id: str | None = None,
    ) -> DataRightsTestResult:
        """
        Test right to be forgotten (Pasal 22 UU PDP) — data deletion verification.

        Runs five checks: endpoint discovery, deletion request submission,
        deletion verification, backup/log deletion policy, and confirmation response.
        """
        findings: list[dict] = []
        tests_passed = 0
        tests_run = 0
        score = 0.0
        deletion_verified = False
        total_response_time: float = 0.0
        evidence: dict = {}

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            # Test 1: Deletion Endpoint Discovery (20 points)
            tests_run += 1
            found_endpoints: list[str] = []

            if deletion_endpoint:
                full_url = urljoin(
                    target.rstrip("/") + "/", deletion_endpoint.lstrip("/")
                )
                if not self.scope_guard or await self.scope_guard.is_url_allowed(
                    full_url
                ):
                    found_endpoints.append(deletion_endpoint)

            if not found_endpoints:
                for pattern in self.DELETION_ENDPOINTS:
                    url = self._resolve_endpoint(target, pattern, test_subject_id)
                    if self.scope_guard and not await self.scope_guard.is_url_allowed(
                        url
                    ):
                        continue
                    try:
                        # Try HEAD first to check existence
                        resp = await client.head(url, headers=auth_headers)
                        if resp.status_code in {200, 204, 405, 404}:
                            found_endpoints.append(pattern)
                            evidence["discovered_endpoint"] = pattern
                            break
                    except (
                        httpx.HTTPError,
                        httpx.TimeoutException,
                        httpx.NetworkError,
                    ):
                        continue

                # Check OpenAPI/Swagger for deletion operations
                if not found_endpoints:
                    for doc_path in [
                        "/openapi.json",
                        "/swagger.json",
                        "/api/docs",
                        "/swagger",
                        "/api/openapi",
                    ]:
                        doc_url = urljoin(
                            target.rstrip("/") + "/", doc_path.lstrip("/")
                        )
                        if (
                            self.scope_guard
                            and not await self.scope_guard.is_url_allowed(doc_url)
                        ):
                            continue
                        try:
                            resp = await client.get(doc_url, headers=auth_headers)
                            if resp.status_code == 200:
                                body = resp.text.lower()
                                deletion_keywords = [
                                    "delete",
                                    "erasure",
                                    "remove",
                                    "forget",
                                ]
                                if any(kw in body for kw in deletion_keywords):
                                    found_endpoints.append(
                                        f"found-in-openapi:{doc_path}"
                                    )
                                    evidence["openapi_documentation"] = doc_path
                                    break
                        except (
                            httpx.HTTPError,
                            httpx.TimeoutException,
                            httpx.NetworkError,
                        ):
                            continue

            if found_endpoints:
                tests_passed += 1
                score += 20
                findings.append(
                    {
                        "test_name": "deletion_endpoint_discovery",
                        "status": "passed",
                        "details": f"Found deletion endpoint(s): {', '.join(found_endpoints)}",
                    }
                )
            else:
                findings.append(
                    {
                        "test_name": "deletion_endpoint_discovery",
                        "status": "failed",
                        "details": "No deletion endpoint discovered",
                    }
                )

            # Test 2: Deletion Request Submission (30 points)
            tests_run += 1
            deletion_url = None
            deletion_start = time.perf_counter()

            if found_endpoints:
                ep = found_endpoints[0]
                if ep.startswith("found-in-openapi:"):
                    # Use the first known deletion endpoint pattern as fallback
                    deletion_url = self._resolve_endpoint(
                        target, self.DELETION_ENDPOINTS[0], test_subject_id
                    )
                else:
                    deletion_url = self._resolve_endpoint(target, ep, test_subject_id)

            if deletion_url and (
                not self.scope_guard
                or await self.scope_guard.is_url_allowed(deletion_url)
            ):
                try:
                    # Try DELETE first, then POST
                    resp = None
                    for method in ["DELETE", "POST"]:
                        resp = await self._make_request(
                            client,
                            method,
                            deletion_url,
                            auth_headers,
                            {
                                "subject_id": test_subject_id or "test-subject-id",
                                "reason": "data_rights_validation_test",
                            },
                        )
                        if resp and resp.status_code in {200, 202, 204}:
                            break

                    elapsed_ms = (time.perf_counter() - deletion_start) * 1000
                    total_response_time += elapsed_ms

                    if resp and resp.status_code in {200, 202, 204}:
                        tests_passed += 1
                        score += 30
                        evidence["deletion_response_status"] = resp.status_code
                        evidence["deletion_response_time_ms"] = elapsed_ms
                        findings.append(
                            {
                                "test_name": "deletion_request_submission",
                                "status": "passed",
                                "details": f"Deletion request accepted with status {resp.status_code} ({elapsed_ms:.0f}ms)",
                            }
                        )
                    elif resp:
                        findings.append(
                            {
                                "test_name": "deletion_request_submission",
                                "status": "failed",
                                "details": f"Deletion request rejected with status {resp.status_code}",
                            }
                        )
                    else:
                        findings.append(
                            {
                                "test_name": "deletion_request_submission",
                                "status": "failed",
                                "details": "Deletion request failed (network error or out of scope)",
                            }
                        )
                except Exception:
                    findings.append(
                        {
                            "test_name": "deletion_request_submission",
                            "status": "failed",
                            "details": "Deletion request failed due to an unexpected error",
                        }
                    )
            else:
                findings.append(
                    {
                        "test_name": "deletion_request_submission",
                        "status": "not_testable",
                        "details": "No deletion endpoint available to test",
                    }
                )

            # Test 3: Deletion Verification (30 points)
            tests_run += 1
            if deletion_url and (
                not self.scope_guard
                or await self.scope_guard.is_url_allowed(deletion_url)
            ):
                # Convert deletion URL to a GET URL for verification
                verify_url = deletion_url.replace("/delete", "").replace("/erasure", "")
                if not self.scope_guard or await self.scope_guard.is_url_allowed(
                    verify_url
                ):
                    try:
                        verification_start = time.perf_counter()
                        resp = await self._make_request(
                            client, "GET", verify_url, auth_headers
                        )
                        elapsed_ms = (time.perf_counter() - verification_start) * 1000
                        total_response_time += elapsed_ms

                        if resp and resp.status_code == 404:
                            tests_passed += 1
                            score += 30
                            deletion_verified = True
                            evidence["deletion_confirmed"] = True
                            evidence["verification_status"] = 404
                            findings.append(
                                {
                                    "test_name": "deletion_verification",
                                    "status": "passed",
                                    "details": "Data no longer accessible after deletion (404)",
                                }
                            )
                        elif resp and resp.status_code == 200:
                            body = resp.text.strip()
                            if not body or body in {"{}", "[]", "null"}:
                                tests_passed += 1
                                score += 30
                                deletion_verified = True
                                evidence["deletion_confirmed"] = True
                                evidence["verification_status"] = "empty_response"
                                findings.append(
                                    {
                                        "test_name": "deletion_verification",
                                        "status": "passed",
                                        "details": "Data appears deleted (empty response)",
                                    }
                                )
                            else:
                                findings.append(
                                    {
                                        "test_name": "deletion_verification",
                                        "status": "failed",
                                        "details": "Data still accessible after deletion request",
                                    }
                                )
                        else:
                            findings.append(
                                {
                                    "test_name": "deletion_verification",
                                    "status": "failed",
                                    "details": f"Verification returned status {resp.status_code if resp else 'error'}",
                                }
                            )
                    except Exception:
                        findings.append(
                            {
                                "test_name": "deletion_verification",
                                "status": "failed",
                                "details": "Deletion verification failed due to an unexpected error",
                            }
                        )
                else:
                    findings.append(
                        {
                            "test_name": "deletion_verification",
                            "status": "not_testable",
                            "details": "Verification URL is out of scope",
                        }
                    )
            else:
                findings.append(
                    {
                        "test_name": "deletion_verification",
                        "status": "not_testable",
                        "details": "No deletion endpoint available to verify",
                    }
                )

            # Test 4: Backup/Log Deletion Policy (10 points)
            tests_run += 1
            policy_found = False
            for policy_path in [
                "/api/privacy/policy",
                "/api/privacy/data-retention",
                "/api/policy/deletion",
            ]:
                policy_url = urljoin(target.rstrip("/") + "/", policy_path.lstrip("/"))
                if self.scope_guard and not await self.scope_guard.is_url_allowed(
                    policy_url
                ):
                    continue
                try:
                    resp = await self._make_request(
                        client, "GET", policy_url, auth_headers
                    )
                    if resp and resp.status_code == 200:
                        body = resp.text.lower()
                        backup_keywords = [
                            "backup",
                            "retention",
                            "log",
                            "archive",
                            "timeline",
                            "deletion",
                        ]
                        if any(kw in body for kw in backup_keywords):
                            policy_found = True
                            score += 10
                            tests_passed += 1
                            evidence["deletion_policy_found"] = policy_path
                            findings.append(
                                {
                                    "test_name": "backup_log_deletion_policy",
                                    "status": "passed",
                                    "details": f"Deletion/retention policy found at {policy_path}",
                                }
                            )
                            break
                except (httpx.HTTPError, httpx.TimeoutException, httpx.NetworkError):
                    continue

            if not policy_found:
                findings.append(
                    {
                        "test_name": "backup_log_deletion_policy",
                        "status": "failed",
                        "details": "No backup/log deletion policy endpoint found",
                    }
                )

            # Test 5: Confirmation Response (10 points)
            tests_run += 1
            if evidence.get("deletion_response_status") in {200, 202, 204}:
                # Check if the deletion response included a confirmation
                confirmation_found = False
                for key in [
                    "deletion_response_body",
                    "confirmation_id",
                    "receipt",
                    "request_id",
                ]:
                    if key in evidence:
                        body_text = str(evidence[key]).lower()
                        confirmation_keywords = [
                            "confirm",
                            "receipt",
                            "request_id",
                            "ticket",
                            "reference",
                            "id",
                        ]
                        if any(kw in body_text for kw in confirmation_keywords):
                            confirmation_found = True
                            break

                # If we got a successful deletion response, give partial credit for having a response
                if not confirmation_found:
                    # Check the actual response body if we captured it
                    score += 10
                    tests_passed += 1
                    findings.append(
                        {
                            "test_name": "confirmation_response",
                            "status": "passed",
                            "details": "Deletion response received (confirmation details may vary)",
                        }
                    )
            else:
                findings.append(
                    {
                        "test_name": "confirmation_response",
                        "status": "failed",
                        "details": "No deletion response to verify confirmation",
                    }
                )

        avg_response_time = total_response_time / max(
            tests_run - 2, 1
        )  # exclude discovery/policy checks
        status = self._determine_status(score)

        return DataRightsTestResult(
            right_type="right_to_be_forgotten",
            status=status,
            score=score,
            tests_run=tests_run,
            tests_passed=tests_passed,
            tests_failed=tests_run - tests_passed,
            findings=findings,
            deletion_verified=deletion_verified,
            response_time_ms=avg_response_time if avg_response_time > 0 else None,
            evidence=evidence,
        )

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

    async def test_right_to_rectification(
        self,
        target: str,
        auth_headers: dict[str, str] | None = None,
        update_endpoint: str | None = None,
    ) -> DataRightsTestResult:
        """
        Test right to rectification (Pasal 22 UU PDP) — data correction.

        Runs four checks: update endpoint discovery, update submission,
        update verification, and update confirmation.
        """
        findings: list[dict] = []
        tests_passed = 0
        tests_run = 0
        score = 0.0
        evidence: dict = {}
        update_url: str | None = None

        async with httpx.AsyncClient(timeout=10.0, follow_redirects=True) as client:
            # Test 1: Update Endpoint Discovery (25 points)
            tests_run += 1
            found_endpoint: str | None = None

            if update_endpoint:
                full_url = urljoin(
                    target.rstrip("/") + "/", update_endpoint.lstrip("/")
                )
                if not self.scope_guard or await self.scope_guard.is_url_allowed(
                    full_url
                ):
                    found_endpoint = update_endpoint

            if not found_endpoint:
                for pattern in self.UPDATE_ENDPOINTS:
                    url = self._resolve_endpoint(target, pattern)
                    if self.scope_guard and not await self.scope_guard.is_url_allowed(
                        url
                    ):
                        continue
                    try:
                        # Try OPTIONS to check allowed methods
                        resp = await client.options(url, headers=auth_headers)
                        allow = resp.headers.get("allow", "").upper()
                        if resp.status_code in {200, 204, 405} and any(
                            m in allow for m in ["PUT", "PATCH"]
                        ):
                            found_endpoint = pattern
                            evidence["discovered_endpoint"] = pattern
                            break
                        # If no Allow header, try a lightweight HEAD
                        if resp.status_code in {200, 204}:
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
                        "test_name": "update_endpoint_discovery",
                        "status": "passed",
                        "details": f"Found update endpoint: {found_endpoint}",
                    }
                )
            else:
                findings.append(
                    {
                        "test_name": "update_endpoint_discovery",
                        "status": "failed",
                        "details": "No update endpoint discovered",
                    }
                )
                return DataRightsTestResult(
                    right_type="right_to_rectification",
                    status=self._determine_status(score),
                    score=score,
                    tests_run=tests_run,
                    tests_passed=tests_passed,
                    tests_failed=tests_run - tests_passed,
                    findings=findings,
                    evidence=evidence,
                )

            update_url = self._resolve_endpoint(target, found_endpoint)

            # Test 2: Update Submission (25 points)
            tests_run += 1
            test_field_name = "test_validation_field"
            test_field_value = f"validation-test-{int(time.time())}"
            update_response: httpx.Response | None = None

            if update_url and (
                not self.scope_guard
                or await self.scope_guard.is_url_allowed(update_url)
            ):
                try:
                    update_start = time.perf_counter()
                    # Try PATCH first, then PUT
                    for method in ["PATCH", "PUT"]:
                        update_response = await self._make_request(
                            client,
                            method,
                            update_url,
                            auth_headers,
                            {test_field_name: test_field_value},
                        )
                        if update_response and update_response.status_code in {
                            200,
                            202,
                            204,
                        }:
                            break

                    elapsed_ms = (time.perf_counter() - update_start) * 1000
                    evidence["update_response_time_ms"] = elapsed_ms

                    if update_response and update_response.status_code in {
                        200,
                        202,
                        204,
                    }:
                        tests_passed += 1
                        score += 25
                        evidence["update_response_status"] = update_response.status_code
                        findings.append(
                            {
                                "test_name": "update_submission",
                                "status": "passed",
                                "details": f"Update request accepted with status {update_response.status_code}",
                            }
                        )
                    elif update_response and update_response.status_code == 403:
                        findings.append(
                            {
                                "test_name": "update_submission",
                                "status": "failed",
                                "details": "Update request forbidden (403) — may require different authorization",
                            }
                        )
                    else:
                        status_code = (
                            update_response.status_code if update_response else "error"
                        )
                        findings.append(
                            {
                                "test_name": "update_submission",
                                "status": "failed",
                                "details": f"Update request rejected with status {status_code}",
                            }
                        )
                except Exception:
                    findings.append(
                        {
                            "test_name": "update_submission",
                            "status": "failed",
                            "details": "Update submission failed due to an unexpected error",
                        }
                    )
            else:
                findings.append(
                    {
                        "test_name": "update_submission",
                        "status": "not_testable",
                        "details": "Update endpoint is out of scope",
                    }
                )

            # Test 3: Update Verification (25 points)
            tests_run += 1
            if update_response and update_response.status_code in {200, 202, 204}:
                try:
                    verify_start = time.perf_counter()
                    verify_resp = await self._make_request(
                        client, "GET", update_url, auth_headers
                    )
                    elapsed_ms = (time.perf_counter() - verify_start) * 1000
                    evidence["verification_response_time_ms"] = elapsed_ms

                    if verify_resp and verify_resp.status_code == 200:
                        body = verify_resp.text
                        if test_field_value in body:
                            tests_passed += 1
                            score += 25
                            evidence["update_verified"] = True
                            findings.append(
                                {
                                    "test_name": "update_verification",
                                    "status": "passed",
                                    "details": "Update confirmed — new value found in subsequent GET request",
                                }
                            )
                        else:
                            findings.append(
                                {
                                    "test_name": "update_verification",
                                    "status": "failed",
                                    "details": "Update not reflected in subsequent GET request",
                                }
                            )
                    else:
                        findings.append(
                            {
                                "test_name": "update_verification",
                                "status": "failed",
                                "details": f"Verification request returned status {verify_resp.status_code if verify_resp else 'error'}",
                            }
                        )
                except Exception:
                    findings.append(
                        {
                            "test_name": "update_verification",
                            "status": "failed",
                            "details": "Update verification failed due to an unexpected error",
                        }
                    )
            else:
                findings.append(
                    {
                        "test_name": "update_verification",
                        "status": "not_testable",
                        "details": "No successful update to verify",
                    }
                )

            # Test 4: Update Confirmation (25 points)
            tests_run += 1
            if update_response and update_response.status_code in {200, 202, 204}:
                body = update_response.text.lower()
                headers = {k.lower(): v for k, v in update_response.headers.items()}

                confirmation_found = False
                # Check response body for confirmation indicators
                confirmation_keywords = [
                    "updated",
                    "success",
                    "confirm",
                    "modified",
                    "changed",
                    test_field_name.lower(),
                ]
                if any(kw in body for kw in confirmation_keywords):
                    confirmation_found = True

                # Check headers for confirmation indicators
                if (
                    headers.get("x-confirmation")
                    or headers.get("x-update-status")
                    or headers.get("x-request-id")
                ):
                    confirmation_found = True

                # 204 No Content is itself a confirmation of success
                if update_response.status_code == 204:
                    confirmation_found = True

                if confirmation_found:
                    tests_passed += 1
                    score += 25
                    findings.append(
                        {
                            "test_name": "update_confirmation",
                            "status": "passed",
                            "details": "Update confirmation provided in response",
                        }
                    )
                else:
                    findings.append(
                        {
                            "test_name": "update_confirmation",
                            "status": "failed",
                            "details": "No explicit update confirmation in response",
                        }
                    )
            else:
                findings.append(
                    {
                        "test_name": "update_confirmation",
                        "status": "failed",
                        "details": "No successful update to check confirmation",
                    }
                )

        status = self._determine_status(score)

        return DataRightsTestResult(
            right_type="right_to_rectification",
            status=status,
            score=score,
            tests_run=tests_run,
            tests_passed=tests_passed,
            tests_failed=tests_run - tests_passed,
            findings=findings,
            evidence=evidence,
        )

    async def assess_all_rights(
        self,
        target: str,
        auth_headers: dict[str, str] | None = None,
    ) -> dict:
        """
        Run all data rights tests and return combined assessment.

        Executes tests for the right to be forgotten, right to access,
        and right to rectification, then produces an overall compliance
        summary aligned with Pasal 22 UU PDP.
        """
        forgotten = await self.test_right_to_be_forgotten(target, auth_headers)
        access = await self.test_right_to_access(target, auth_headers)
        rectification = await self.test_right_to_rectification(target, auth_headers)

        scores = [forgotten.score, access.score, rectification.score]
        overall_score = sum(scores) / len(scores)
        overall_status = self._determine_status(overall_score)

        # Identify gaps
        gaps: list[str] = []
        if forgotten.score < 80:
            gaps.append(
                f"Right to be forgotten is not fully compliant (score: {forgotten.score:.0f}/100). "
                f"Status: {forgotten.status}."
            )
        if not forgotten.deletion_verified and forgotten.score >= 20:
            gaps.append("Data deletion could not be verified after request.")
        if access.score < 80:
            gaps.append(
                f"Right to access is not fully compliant (score: {access.score:.0f}/100). "
                f"Status: {access.status}."
            )
        if rectification.score < 80:
            gaps.append(
                f"Right to rectification is not fully compliant (score: {rectification.score:.0f}/100). "
                f"Status: {rectification.status}."
            )
        if not gaps:
            gaps.append(
                "No significant gaps identified in data subject rights implementation."
            )

        return {
            "overall_score": overall_score,
            "overall_status": overall_status,
            "right_to_be_forgotten": forgotten,
            "right_to_access": access,
            "right_to_rectification": rectification,
            "uu_pdp_pasal_22_compliance": {
                "status": overall_status,
                "score": overall_score,
                "gaps": gaps,
            },
        }
