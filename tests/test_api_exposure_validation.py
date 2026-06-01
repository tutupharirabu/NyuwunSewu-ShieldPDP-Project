from app.recon import CrawledEndpoint
from app.validation.api_exposure import SafeAPIExposureValidator


def guest_endpoint(url: str, body: str, content_type: str = "application/json") -> CrawledEndpoint:
    return CrawledEndpoint(
        url=url,
        status_code=200,
        content_type=content_type,
        response_body_sample=body,
        tech_stack=["access:guest"],
        guest_status_code=200,
        guest_content_type=content_type,
        guest_response_body_sample=body,
        guest_response_headers={"content-type": content_type},
        guest_request_headers={"user-agent": "ShieldPDP-Test"},
    )


def test_guest_sensitive_api_response_requires_financial_and_identity_fields():
    endpoint = guest_endpoint(
        "https://example.com/api/transactions/1001",
        '{"transactions":[{"account_number":"1001","balance":400,"username":"customer"}]}',
    )

    result = SafeAPIExposureValidator().public_sensitive_api_response(endpoint)

    assert result is not None
    assert result.finding_type == "unauthenticated_sensitive_api_exposure"
    assert result.severity == "high"
    assert result.response_body == endpoint.guest_response_body_sample


def test_authenticated_replacement_does_not_turn_into_guest_exposure():
    endpoint = CrawledEndpoint(
        url="https://example.com/api/transactions/1001",
        status_code=200,
        content_type="application/json",
        response_body_sample='{"account_number":"1001","balance":400,"username":"customer"}',
        tech_stack=["access:authenticated", "access:guest"],
        guest_status_code=401,
        guest_content_type="application/json",
        guest_response_body_sample='{"error":"authentication required"}',
    )

    result = SafeAPIExposureValidator().public_sensitive_api_response(endpoint)

    assert result is None


def test_javascript_token_storage_pattern_is_reported_without_executing_code():
    endpoint = CrawledEndpoint(
        url="https://example.com/static/app.js",
        status_code=200,
        content_type="application/javascript",
        response_body_sample='localStorage.setItem("access_token", response.token);',
    )

    result = SafeAPIExposureValidator().client_side_token_storage(endpoint)

    assert result is not None
    assert result.finding_type == "client_side_auth_token_storage"
    assert result.evidence["validation_mode"] == "static_javascript_analysis"


def test_inline_login_script_jwt_token_storage_is_detected():
    endpoint = CrawledEndpoint(
        url="https://example.com/login",
        status_code=200,
        content_type="text/html; charset=utf-8",
        response_body_sample='<script>localStorage.setItem("jwt_token", data.token);</script>',
    )

    result = SafeAPIExposureValidator().client_side_token_storage(endpoint)

    assert result is not None
    assert result.finding_type == "client_side_auth_token_storage"


def test_authentication_cookie_reports_missing_browser_protections_without_value():
    endpoint = CrawledEndpoint(
        url="https://example.com/login",
        method="POST",
        status_code=200,
        response_headers={"set-cookie": "token=secret-value; HttpOnly; Path=/"},
    )

    result = SafeAPIExposureValidator().authentication_cookie_protection(endpoint)

    assert result is not None
    assert result.finding_type == "authentication_cookie_protection"
    assert result.evidence["missing_attributes"] == ["Secure", "SameSite"]
    assert "secret-value" not in result.response_body


def test_public_graphql_advertisement_is_reported_without_schema_query():
    endpoint = guest_endpoint(
        "https://example.com/graphql",
        '{"message":"GraphQL API","introspection":"enabled"}',
    )

    result = SafeAPIExposureValidator().public_graphql_introspection(endpoint)

    assert result is not None
    assert result.finding_type == "graphql_schema_exposure"
    assert result.severity == "low"
    assert result.evidence["mutation_executed"] is False
    assert result.evidence["__schema_exposure"] is False
