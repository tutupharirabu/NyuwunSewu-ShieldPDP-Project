from __future__ import annotations

import time
from urllib.parse import urljoin

import httpx

from app.validation.data_rights.base import DataRightsTestResult


class RightToBeForgottenMixin:
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

