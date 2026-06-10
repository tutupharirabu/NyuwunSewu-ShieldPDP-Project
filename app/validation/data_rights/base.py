"""Shared primitives for the data-subject-rights validators.

Holds the endpoint catalogs, the dataclass result type, and the HTTP/scoring
helpers reused by each per-right mixin. Sits at the bottom of the package
import graph (depends only on ScopeGuard).
"""

from __future__ import annotations

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



class _DataRightsBase:
    """Endpoint catalogs + request/scoring helpers shared by the right mixins."""

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

