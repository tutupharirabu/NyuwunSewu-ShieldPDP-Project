from __future__ import annotations

import time
from urllib.parse import urljoin

import httpx

from app.validation.data_rights.base import DataRightsTestResult


class RightToRectificationMixin:
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

