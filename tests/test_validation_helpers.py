import asyncio

from app.validation.bola import BOLAValidator
from app.validation.access_matrix import AccessControlMatrixValidator
from app.validation.auth import AuthValidator
from app.validation.attack_knowledge import AttackKnowledgeEngine
from app.validation.exploit_chains import ActiveExploitChainValidator
from app.validation.impact_validators import (
    BusinessLogicImpactEvaluator,
    RateLimitRoleValidator,
    SSRFInBandValidator,
)
from app.validation.path_traversal import PathTraversalValidator
from app.validation.reflected_html import ReflectedHTMLInjectionValidator
from app.validation.sqli import LightweightSQLiValidator
from app.validation.types import HttpObservation
from app.recon import CrawledEndpoint


def observation(
    body: str,
    *,
    url: str = "https://example.com/api/proof",
    method: str = "GET",
    status: int = 200,
) -> HttpObservation:
    return HttpObservation(
        url=url,
        method=method,
        status_code=status,
        elapsed_ms=3,
        headers={"content-type": "application/json"},
        body_sample=body,
        content_length=len(body),
        request_headers={"user-agent": "NyuwunSewu-MVP/1.0"},
        response_reason="OK",
    )


def test_sqli_dbms_detection_is_specific():
    validator = LightweightSQLiValidator.__new__(LightweightSQLiValidator)
    assert validator._detect_dbms("PostgreSQL ERROR: syntax error at or near \"'\"") == "PostgreSQL"
    assert validator._detect_dbms("ORA-01756 quoted string not properly terminated") == "Oracle"


def test_sqli_recognizes_json_login_flow_and_token_transition_only_on_login_path():
    validator = LightweightSQLiValidator.__new__(LightweightSQLiValidator)
    script = """
        fetch("/login", {
            method: "POST",
            headers: {"Content-Type": "application/json"},
            body: JSON.stringify(formData)
        });
    """
    login = CrawledEndpoint(url="https://example.com/login", response_body_sample=script)
    settings = CrawledEndpoint(url="https://example.com/settings", response_body_sample=script)
    token_response = HttpObservation(
        url="https://example.com/login",
        method="POST",
        status_code=200,
        elapsed_ms=2,
        headers={"content-type": "application/json"},
        body_sample='{"token":"redacted-token","status":"success"}',
        content_length=45,
    )

    assert validator._javascript_json_login_action(login) == "https://example.com/login"
    assert validator._javascript_json_login_action(settings) is None
    assert validator._looks_authenticated(token_response)


def test_attack_knowledge_marks_login_as_sqli_auth_bypass_candidate():
    engine = AttackKnowledgeEngine()
    endpoint = CrawledEndpoint(
        url="https://example.com/login",
        method="GET",
        response_body_sample='fetch("/login", {method:"POST", body: JSON.stringify({username, password})})',
        forms=[
            {
                "action": "https://example.com/login",
                "method": "POST",
                "fields": [
                    {"name": "username", "type": "text"},
                    {"name": "password", "type": "password"},
                ],
            }
        ],
    )

    [candidate] = [
        item for item in engine.candidates(endpoint) if item.technique == "sqli_auth_bypass"
    ]

    assert candidate.risk in {"medium", "high"}
    assert "authenticated-state proof" in " ".join(candidate.prerequisites)
    assert any("Login/session" in reason for reason in candidate.reasoning)


def test_attack_knowledge_marks_url_import_as_ssrf_candidate():
    engine = AttackKnowledgeEngine()
    endpoint = CrawledEndpoint(
        url="https://example.com/upload_profile_picture_url",
        method="POST",
        forms=[
            {
                "action": "https://example.com/upload_profile_picture_url",
                "method": "POST",
                "fields": [{"name": "image_url", "type": "url"}],
            }
        ],
    )

    candidates = engine.classification_dicts(endpoint)

    assert any(item["classification"] == "attack_candidate:ssrf_url_fetch" for item in candidates)
    ssrf = next(item for item in candidates if item["classification"] == "attack_candidate:ssrf_url_fetch")
    assert "loopback" in " ".join(ssrf["prerequisites"]).lower()
    assert "No external callback" in " ".join(ssrf["safe_validation"])


def test_attack_knowledge_marks_negative_amount_business_logic_candidate():
    engine = AttackKnowledgeEngine()
    endpoint = CrawledEndpoint(
        url="https://example.com/api/transfers",
        method="POST",
        forms=[
            {
                "action": "https://example.com/api/transfers",
                "method": "POST",
                "fields": [
                    {"name": "from_account", "type": "text"},
                    {"name": "to_account", "type": "text"},
                    {"name": "amount", "type": "number"},
                ],
            }
        ],
    )

    [candidate] = [
        item
        for item in engine.candidates(endpoint)
        if item.technique == "negative_amount_business_logic"
    ]

    assert candidate.risk == "high"
    assert "test accounts" in " ".join(candidate.prerequisites)
    assert "before/after state" in " ".join(candidate.evidence_needed).lower()


def test_attack_knowledge_marks_rate_limit_role_candidate_without_flooding():
    engine = AttackKnowledgeEngine()
    endpoint = CrawledEndpoint(
        url="https://example.com/api/ai/rate-limit-status",
        method="GET",
        response_body_sample='{"role":"unauthenticated","remaining":10,"limit":20}',
    )

    [candidate] = [
        item
        for item in engine.candidates(endpoint)
        if item.technique == "rate_limit_role_misclassification"
    ]

    assert candidate.risk in {"medium", "high"}
    assert "Do not flood" in " ".join(candidate.safe_validation)


def test_ssrf_inband_validator_requires_operator_canary_marker():
    validator = SSRFInBandValidator.__new__(SSRFInBandValidator)
    endpoint = CrawledEndpoint(url="https://example.com/upload_profile_picture_url")

    missing = validator._confirmed_result(
        endpoint=endpoint,
        field_name="image_url",
        canary_url="http://127.0.0.1:5000/internal/secret",
        markers=["NYUWUNSEWU_CANARY"],
        observation=observation('{"note":"ordinary response"}', method="POST"),
        request_url="https://example.com/upload_profile_picture_url",
        request_body='{"image_url":"http://127.0.0.1:5000/internal/secret"}',
    )
    confirmed = validator._confirmed_result(
        endpoint=endpoint,
        field_name="image_url",
        canary_url="http://127.0.0.1:5000/internal/secret",
        markers=["NYUWUNSEWU_CANARY"],
        observation=observation('{"note":"NYUWUNSEWU_CANARY internal proof"}', method="POST"),
        request_url="https://example.com/upload_profile_picture_url",
        request_body='{"image_url":"http://127.0.0.1:5000/internal/secret"}',
    )

    assert missing is None
    assert confirmed is not None
    assert confirmed.finding_type == "ssrf_inband_url_fetch"
    assert confirmed.exploitability_assessment == "CONFIRMED_EXPLOIT"


def test_ssrf_canary_blocks_metadata_and_allows_loopback_or_allowlist():
    validator = SSRFInBandValidator.__new__(SSRFInBandValidator)

    assert validator._canary_allowed("http://127.0.0.1:5000/proof", {})
    assert validator._canary_allowed(
        "https://canary.internal/proof",
        {"ssrf_allowed_hosts": ["canary.internal"]},
    )
    assert not validator._canary_allowed("http://169.254.169.254/latest/meta-data", {})
    assert not validator._canary_allowed("https://attacker.example/proof", {})


def test_rate_limit_role_validator_confirms_auth_role_misclassification():
    validator = RateLimitRoleValidator.__new__(RateLimitRoleValidator)
    endpoint = CrawledEndpoint(url="https://example.com/api/ai/rate-limit-status")

    result = validator._mismatch_result(
        endpoint,
        observation('{"role":"unauthenticated","remaining":10,"limit":20}'),
        observation('{"role":"unauthenticated","remaining":10,"limit":20}'),
    )

    assert result is not None
    assert result.finding_type == "rate_limit_role_misclassification"
    assert result.exploitability_assessment == "VALIDATED_EXPOSURE"
    assert "No quota exhaustion" in " ".join(result.reasoning)


def test_business_logic_evaluator_confirms_negative_amount_reverse_movement_only():
    evaluator = BusinessLogicImpactEvaluator()
    proof = observation(
        '{"status":"success","source_balance":110,"destination_balance":90}',
        url="https://example.com/api/transfers",
        method="POST",
    )

    confirmed = evaluator.negative_amount_transfer_result(
        endpoint_url="https://example.com/api/transfers",
        amount=-10,
        source_before=100,
        source_after=110,
        destination_before=100,
        destination_after=90,
        observation=proof,
        request_body='{"from":"A","to":"B","amount":-10}',
    )
    not_impact = evaluator.negative_amount_transfer_result(
        endpoint_url="https://example.com/api/transfers",
        amount=-10,
        source_before=100,
        source_after=90,
        destination_before=100,
        destination_after=110,
        observation=proof,
        request_body='{"from":"A","to":"B","amount":-10}',
    )

    assert confirmed is not None
    assert confirmed.finding_type == "negative_amount_business_logic"
    assert confirmed.exploitability_assessment == "CONFIRMED_EXPLOIT"
    assert not_impact is None


def test_jwt_tamper_negative_control_changes_claim_without_new_signature():
    validator = AuthValidator.__new__(AuthValidator)
    header = "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9"
    payload = "eyJ1c2VyX2lkIjo3LCJpc19hZG1pbiI6ZmFsc2V9"
    signature = "original-signature"
    token = f"{header}.{payload}.{signature}"

    modified = validator._tamper_boolean_claim_without_resigning(token, "is_admin", True)
    _, claims = validator._decode_unverified(modified or "")

    assert modified is not None
    assert modified.split(".")[2] == signature
    assert claims["is_admin"] is True


def test_jwt_observation_is_info_without_concrete_weakness():
    validator = AuthValidator.__new__(AuthValidator)
    token = (
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiJ1c2VyLTEiLCJleHAiOjQxMDI0NDQ4MDB9."
        "signature"
    )

    [result] = validator.inspect_jwt({"authorization": f"Bearer {token}"})

    assert result.finding_type == "jwt_observed"
    assert result.severity == "info"
    assert result.evidence["decoded_header"]["alg"] == "HS256"
    assert result.evidence["weakness_reason"] == []


def test_jwt_missing_exp_reports_explicit_weakness_evidence():
    validator = AuthValidator.__new__(AuthValidator)
    token = (
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9."
        "eyJzdWIiOiJ1c2VyLTEifQ."
        "signature"
    )

    [result] = validator.inspect_jwt({"authorization": f"Bearer {token}"})

    assert result.finding_type == "jwt_weakness"
    assert result.severity == "medium"
    assert result.evidence["missing_exp"] is True
    assert any("exp" in reason for reason in result.evidence["weakness_reason"])


def test_authorization_classifier_excludes_public_docs_and_static_assets():
    validator = AuthValidator.__new__(AuthValidator)
    public_urls = [
        "https://example.com/login",
        "https://example.com/register",
        "https://example.com/forgot-password",
        "https://example.com/privacy",
        "https://example.com/terms",
        "https://example.com/blog/post-1",
        "https://example.com/careers/engineer",
        "https://example.com/docs",
        "https://example.com/swagger-ui/swagger-ui.css",
        "https://example.com/api/openapi.json",
        "https://example.com/assets/app.js",
        "https://example.com/images/logo.png",
    ]

    for url in public_urls:
        endpoint = CrawledEndpoint(url=url)
        assert validator.classify_endpoint_authorization(endpoint) == validator.PUBLIC_ENDPOINT


def test_authorization_classifier_marks_sensitive_business_routes_required():
    validator = AuthValidator.__new__(AuthValidator)

    assert (
        validator.classify_endpoint_authorization(CrawledEndpoint(url="https://example.com/api/accounts"))
        == validator.AUTH_REQUIRED
    )
    assert (
        validator.classify_endpoint_authorization(CrawledEndpoint(url="https://example.com/admin/users"))
        == validator.AUTH_REQUIRED
    )
    assert (
        validator.classify_endpoint_authorization(CrawledEndpoint(url="https://example.com/api/products"))
        == validator.AUTH_OPTIONAL
    )


def test_authorization_proof_requires_material_sensitive_data_or_functionality():
    validator = AuthValidator.__new__(AuthValidator)
    marketing = HttpObservation(
        url="https://example.com/dashboard",
        method="GET",
        status_code=200,
        elapsed_ms=2,
        headers={"content-type": "text/html"},
        body_sample="<h1>Manage your account securely</h1>",
        content_length=40,
    )
    exposure = HttpObservation(
        url="https://example.com/api/accounts",
        method="GET",
        status_code=200,
        elapsed_ms=2,
        headers={"content-type": "application/json"},
        body_sample='{"account_number":"88771","balance":400}',
        content_length=40,
    )

    assert not any(
        validator._authorization_bypass_proof(
            CrawledEndpoint(url="https://example.com/dashboard"),
            marketing,
        ).values()
    )
    assert validator._authorization_bypass_proof(
        CrawledEndpoint(url="https://example.com/api/accounts"),
        exposure,
    )["sensitive_data"]


def test_missing_authorization_skips_public_endpoint_before_network():
    class AllowPolicy:
        def is_validation_allowed(self, _name):
            return True

    validator = AuthValidator.__new__(AuthValidator)
    validator.policy = AllowPolicy()

    result = asyncio.run(
        validator.validate_missing_authorization(
            CrawledEndpoint(url="https://example.com/login"),
            None,
            {"authorization": "Bearer token"},
        )
    )

    assert result is None


def test_active_exploit_chain_builds_signed_admin_jwt_variants():
    validator = ActiveExploitChainValidator.__new__(ActiveExploitChainValidator)
    header = {"typ": "JWT", "alg": "HS256"}
    payload = {"user_id": 7, "username": "jeruk", "is_admin": False}
    elevated = validator._elevate_claims(payload)

    variants = validator._local_jwt_variants(
        "eyJ0eXAiOiJKV1QiLCJhbGciOiJIUzI1NiJ9.eyJpc19hZG1pbiI6ZmFsc2V9.sig",
        header,
        elevated,
        {"weak_jwt_secrets": ["secret"]},
    )
    names = [name for name, _ in variants]

    assert elevated["is_admin"] is True
    assert "admin" in elevated["roles"]
    assert "none_algorithm" in names
    assert "hs256_weak_secret:secret" in names


def test_active_exploit_chain_extracts_cookie_jwt_name():
    validator = ActiveExploitChainValidator.__new__(ActiveExploitChainValidator)

    assert validator._token_cookie_name({"cookie": "csrftoken=abc; token=jwt.value.sig"}) == "token"
    assert validator._token_cookie_name({"Cookie": "auth_jwt=jwt.value.sig"}) == "auth_jwt"


def test_token_storage_xss_chain_records_no_exfiltration_payload():
    validator = ActiveExploitChainValidator.__new__(ActiveExploitChainValidator)
    endpoint = CrawledEndpoint(url="https://example.com/dashboard")
    auth = CrawledEndpoint(
        url="https://example.com/login",
        status_code=200,
        response_headers={"set-cookie": "token=eyJaaaa.eyJbbbb.cccc; Path=/; SameSite=Lax"},
    )
    headers = {"cookie": "token=eyJaaaa.eyJbbbb.cccc"}

    result = validator.token_storage_xss_impact(endpoint, headers, auth, [endpoint])

    assert result is not None
    assert result.finding_type == "token_storage_xss_account_takeover_chain"
    payload = result.evidence["safe_no_exfiltration_payload"]
    assert "document.cookie" in payload
    assert "fetch(" not in payload
    assert "http://" not in payload and "https://" not in payload


def test_bola_identifier_mutation_handles_path_and_query_ids():
    validator = BOLAValidator.__new__(BOLAValidator)
    mutations = validator._mutate_identifiers("https://example.com/api/users/41/orders?invoice_id=100")
    urls = [url for url, _ in mutations]

    assert "https://example.com/api/users/42/orders?invoice_id=100" in urls
    assert any("invoice_id=101" in url for url in urls)


def test_path_traversal_only_targets_file_like_parameters():
    validator = PathTraversalValidator.__new__(PathTraversalValidator)
    endpoint = CrawledEndpoint(
        url="https://example.com/download?file=invoice.pdf&customer_id=10",
        forms=[
            {
                "action": "https://example.com/export",
                "method": "POST",
                "fields": [{"name": "path", "value": "report.pdf"}, {"name": "email", "value": ""}],
            }
        ],
    )

    candidates = validator._candidates(endpoint)

    assert ("GET", endpoint.url, "file", None) in candidates
    assert any(candidate[2] == "path" for candidate in candidates)
    assert not any(candidate[2] == "customer_id" for candidate in candidates)


def test_path_traversal_recognizes_file_shaped_values_with_application_parameter_names():
    validator = PathTraversalValidator.__new__(PathTraversalValidator)
    endpoint = CrawledEndpoint(
        url="https://example.com/news?NewsAd=ads/def.html&id=10",
    )

    candidates = validator._candidates(endpoint)

    assert any(candidate[2] == "NewsAd" for candidate in candidates)
    assert not any(candidate[2] == "id" for candidate in candidates)


def test_reflected_html_requires_rendered_inert_canary_not_encoded_text():
    validator = ReflectedHTMLInjectionValidator.__new__(ReflectedHTMLInjectionValidator)
    marker = "shieldpdp-check"

    assert validator._contains_probe(
        f'<div><span data-shieldpdp-probe="{marker}">{marker}</span></div>',
        marker,
    )
    assert not validator._contains_probe(
        f'&lt;span data-shieldpdp-probe="{marker}"&gt;{marker}&lt;/span&gt;',
        marker,
    )


def test_access_matrix_sensitive_data_requires_structured_material_value():
    validator = AccessControlMatrixValidator.__new__(AccessControlMatrixValidator)
    marketing = HttpObservation(
        url="https://example.com/",
        method="GET",
        status_code=200,
        elapsed_ms=2,
        headers={"content-type": "text/html"},
        body_sample="<h1>Manage your account and payments securely</h1>",
        content_length=50,
    )
    placeholder = HttpObservation(
        url="https://example.com/transactions/{account_number}",
        method="GET",
        status_code=200,
        elapsed_ms=2,
        headers={"content-type": "application/json"},
        body_sample='{"account_number":"{account_number}","transactions":[]}',
        content_length=60,
    )
    exposure = HttpObservation(
        url="https://example.com/api/account",
        method="GET",
        status_code=200,
        elapsed_ms=2,
        headers={"content-type": "application/json"},
        body_sample='{"account_number":"88771","balance":400}',
        content_length=45,
    )

    assert not validator._contains_material_sensitive_data(marketing)
    assert not validator._contains_material_sensitive_data(placeholder)
    assert validator._contains_material_sensitive_data(exposure)
