from __future__ import annotations

import json
import re
from urllib.parse import urlparse

from app.recon import CrawledEndpoint
from app.validation.types import ValidationResult


class SafeAPIExposureValidator:
    """Passive checks for sensitive API surfaces discovered during ordinary crawling."""

    SENSITIVE_ROUTE_RE = re.compile(
        r"(?i)/(?:api/)?(?:transactions?|payments?|bill-payments|cards?|virtual-cards?|"
        r"accounts?|profile|check[_-]?balance|debug/users)(?:/|$)"
    )
    GRAPHQL_PATH_RE = re.compile(r"(?i)/graphql/?$")
    TOKEN_STORAGE_RE = re.compile(
        r"""(?ix)
        localStorage\s*(?:
            \.\s*(?:setItem|getItem)\s*\(\s*["']
            (?:token|access[_-]?token|jwt|jwt[_-]?token|auth[_-]?token|session[_-]?token)["']
            |
            \[\s*["'](?:token|access[_-]?token|jwt|jwt[_-]?token|auth[_-]?token|session[_-]?token)["']\s*\]
        )
        """
    )
    AUTH_COOKIE_RE = re.compile(r"(?i)(?:^|,\s*)(token|jwt|session|auth(?:_?token)?)=([^;]+)([^,]*)")
    FINANCIAL_FIELDS = {
        "account_number",
        "accountnumber",
        "balance",
        "amount",
        "card_number",
        "cardnumber",
        "cvv",
        "transactions",
        "payments",
    }
    IDENTITY_FIELDS = {
        "user_id",
        "userid",
        "username",
        "email",
        "phone",
        "nik",
        "npwp",
        "is_admin",
    }
    GRAPHQL_SENSITIVE_MUTATION_RE = re.compile(
        r"(?i)(mutation|createUser|updateUser|deleteUser|transfer|payment|admin|role|permission)"
    )
    GRAPHQL_ADMIN_OBJECT_RE = re.compile(r"(?i)(Admin|Role|Permission|UserAdmin|AuditLog|Internal)")

    def findings(self, endpoint: CrawledEndpoint) -> list[ValidationResult]:
        results: list[ValidationResult] = []
        for finding in (
            self.public_sensitive_api_response(endpoint),
            self.client_side_token_storage(endpoint),
            self.public_graphql_introspection(endpoint),
        ):
            if finding:
                results.append(finding)
        return results

    def public_sensitive_api_response(self, endpoint: CrawledEndpoint) -> ValidationResult | None:
        if not self._is_guest_success(endpoint):
            return None
        if not self.SENSITIVE_ROUTE_RE.search(urlparse(endpoint.url).path):
            return None
        keys = self._response_keys(endpoint)
        financial = sorted(keys.intersection(self.FINANCIAL_FIELDS))
        identity = sorted(keys.intersection(self.IDENTITY_FIELDS))
        if not financial or not identity:
            return None

        return ValidationResult(
            finding_type="unauthenticated_sensitive_api_exposure",
            title="Unauthenticated Sensitive API Data Exposure",
            severity="high",
            confidence=92.0,
            endpoint=endpoint.url,
            description=(
                "A guest-accessible API response returned structured identity and financial data "
                "fields without an authenticated session."
            ),
            reasoning=[
                "The endpoint was observed during the guest crawl context",
                f"Financial response fields exposed: {', '.join(financial)}",
                f"Identity response fields exposed: {', '.join(identity)}",
            ],
            evidence={
                "validation_mode": "passive_guest_response_analysis",
                "authentication_context": "guest",
                "financial_fields": financial,
                "identity_fields": identity,
                "payload": None,
            },
            remediation=(
                "Require authentication and object-level authorization before returning financial "
                "records, and minimize identity fields in API responses."
            ),
            pii_types=identity,
            request_method="GET",
            request_url=endpoint.url,
            request_headers=endpoint.guest_request_headers,
            response_status=endpoint.guest_status_code,
            response_headers=endpoint.guest_response_headers,
            response_body=endpoint.guest_response_body_sample,
            http_version=endpoint.guest_http_version,
            response_reason=endpoint.guest_response_reason,
        )

    def client_side_token_storage(self, endpoint: CrawledEndpoint) -> ValidationResult | None:
        if endpoint.status_code != 200 or not self._has_client_script_content(endpoint):
            return None
        if not self.TOKEN_STORAGE_RE.search(endpoint.response_body_sample):
            return None

        return ValidationResult(
            finding_type="client_side_auth_token_storage",
            title="Client-Side Authentication Token Storage Pattern",
            severity="medium",
            confidence=86.0,
            endpoint=endpoint.url,
            description=(
                "Client JavaScript references authentication tokens in localStorage, which may "
                "increase token theft impact if client-side injection occurs."
            ),
            reasoning=[
                "Static JavaScript analysis detected localStorage access for an authentication token key",
                "The check reports storage exposure only and does not attempt script execution or token theft",
            ],
            evidence={
                "validation_mode": "static_javascript_analysis",
                "storage_api": "localStorage",
                "payload": None,
            },
            remediation=(
                "Prefer Secure, HttpOnly, SameSite session cookies where appropriate and enforce "
                "strong content security controls against client-side injection."
            ),
        )

    def authentication_cookie_protection(self, endpoint: CrawledEndpoint | None) -> ValidationResult | None:
        if endpoint is None or endpoint.status_code != 200:
            return None
        set_cookie = endpoint.response_headers.get("set-cookie", "")
        match = self.AUTH_COOKIE_RE.search(set_cookie)
        if not match:
            return None
        attributes = match.group(3).lower()
        missing = [
            flag
            for flag, present in (
                ("Secure", "secure" in attributes),
                ("SameSite", "samesite" in attributes),
                ("HttpOnly", "httponly" in attributes),
            )
            if not present
        ]
        if not missing:
            return None
        cookie_name = match.group(1)
        severity = "high" if "HttpOnly" in missing else "medium"
        return ValidationResult(
            finding_type="authentication_cookie_protection",
            title="Authentication Cookie Missing Browser Protection Attributes",
            severity=severity,
            confidence=94.0,
            endpoint=endpoint.url,
            description=(
                "The normal authenticated login response set an authentication cookie without "
                "all expected browser protection attributes."
            ),
            reasoning=[
                f"Authentication cookie name observed: {cookie_name}",
                f"Missing cookie attributes: {', '.join(missing)}",
                "The cookie value is redacted and no token extraction payload was executed",
            ],
            evidence={
                "validation_mode": "authenticated_login_cookie_attribute_analysis",
                "cookie_name": cookie_name,
                "missing_attributes": missing,
                "payload": None,
            },
            remediation=(
                "Set authentication cookies with HttpOnly, Secure, and an appropriate SameSite "
                "policy, and avoid duplicating bearer tokens in JavaScript-accessible storage."
            ),
            request_method="POST",
            request_url=endpoint.url,
            request_headers=endpoint.request_headers,
            response_status=endpoint.status_code,
            response_headers=endpoint.response_headers,
            response_body="Authentication response body omitted; token material is not retained in this finding.",
            http_version=endpoint.http_version,
            response_reason=endpoint.response_reason,
        )

    def public_graphql_introspection(self, endpoint: CrawledEndpoint) -> ValidationResult | None:
        if not self._is_guest_success(endpoint):
            return None
        if not self.GRAPHQL_PATH_RE.search(urlparse(endpoint.url).path):
            return None
        normalized_body = endpoint.guest_response_body_sample.lower()
        has_schema_exposure = "__schema" in normalized_body or "querytype" in normalized_body
        advertises_introspection = "introspection" in normalized_body and "enabled" in normalized_body
        if not has_schema_exposure and not advertises_introspection:
            return None
        sensitive_mutation = bool(self.GRAPHQL_SENSITIVE_MUTATION_RE.search(endpoint.guest_response_body_sample))
        admin_object = bool(self.GRAPHQL_ADMIN_OBJECT_RE.search(endpoint.guest_response_body_sample))
        sensitive_schema = sensitive_mutation or admin_object

        return ValidationResult(
            finding_type="graphql_schema_exposure",
            title=(
                "Public GraphQL Introspection Exposes Sensitive Schema"
                if sensitive_schema
                else "Public GraphQL Introspection Capability Advertised"
            ),
            severity="medium" if sensitive_schema else "low",
            confidence=88.0 if sensitive_schema else 72.0,
            endpoint=endpoint.url,
            description=(
                "The public GraphQL route exposes or advertises introspection. Introspection alone "
                "is tracked as low severity unless sensitive schema or authorization weaknesses are present."
            ),
            reasoning=[
                "A guest request reached the GraphQL endpoint successfully",
                (
                    "__schema markers were present in the response"
                    if has_schema_exposure
                    else "The response advertises an enabled introspection capability"
                ),
                f"Sensitive mutation exposure: {sensitive_mutation}",
                f"Admin object exposure: {admin_object}",
                "No mutation or schema extraction query was executed by this validation",
            ],
            evidence={
                "validation_mode": "passive_guest_response_analysis",
                "authentication_context": "guest",
                "payload": None,
                "mutation_executed": False,
                "__schema_exposure": has_schema_exposure,
                "sensitive_mutation": sensitive_mutation,
                "admin_object_exposure": admin_object,
                "auth_weakness_evidence": False,
            },
            remediation=(
                "Restrict production schema introspection to authorized roles where it is not "
                "required publicly, and enforce resolver-level authorization."
            ),
            request_method="GET",
            request_url=endpoint.url,
            request_headers=endpoint.guest_request_headers,
            response_status=endpoint.guest_status_code,
            response_headers=endpoint.guest_response_headers,
            response_body=endpoint.guest_response_body_sample,
            http_version=endpoint.guest_http_version,
            response_reason=endpoint.guest_response_reason,
            exploitability_assessment="ATTACK_SURFACE_IDENTIFIED",
            evidence_quality="MEDIUM" if sensitive_schema else "LOW",
            false_positive_likelihood="MEDIUM",
        )

    @staticmethod
    def _is_guest_success(endpoint: CrawledEndpoint) -> bool:
        return endpoint.guest_status_code == 200 and "access:guest" in endpoint.tech_stack

    @staticmethod
    def _has_client_script_content(endpoint: CrawledEndpoint) -> bool:
        content_type = (endpoint.content_type or "").lower()
        path = urlparse(endpoint.url).path.lower()
        return (
            "javascript" in content_type
            or path.endswith(".js")
            or ("html" in content_type and "<script" in endpoint.response_body_sample.lower())
        )

    @staticmethod
    def _response_keys(endpoint: CrawledEndpoint) -> set[str]:
        content_type = (endpoint.guest_content_type or "").lower()
        body = endpoint.guest_response_body_sample.strip()
        if "json" not in content_type and not body.startswith(("{", "[")):
            return set()
        try:
            payload = json.loads(body)
        except json.JSONDecodeError:
            return set()

        keys: set[str] = set()

        def collect(value: object) -> None:
            if isinstance(value, dict):
                for key, nested in value.items():
                    keys.add(str(key).lower().replace("-", "_"))
                    collect(nested)
            elif isinstance(value, list):
                for nested in value[:25]:
                    collect(nested)

        collect(payload)
        return keys
