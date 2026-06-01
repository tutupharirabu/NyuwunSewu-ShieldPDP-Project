from app.recon import CrawledEndpoint
from app.validation.cors import CorsValidationEngine
from app.validation.types import HttpObservation
from app.validation.username_enumeration import UsernameEnumerationValidator


def observation(status: int, body: str) -> HttpObservation:
    return HttpObservation(
        url="https://example.com/login",
        method="POST",
        status_code=status,
        elapsed_ms=5,
        headers={"content-type": "application/json"},
        body_sample=body,
        content_length=len(body),
    )


def test_username_enumeration_fingerprint_ignores_debug_username_reflection():
    known = observation(
        401,
        '{"status":"error","message":"Invalid credentials","debug_info":{"attempted_username":"admin"}}',
    )
    control = observation(
        401,
        '{"status":"error","message":"Invalid credentials","debug_info":{"attempted_username":"random"}}',
    )

    assert UsernameEnumerationValidator._fingerprint(known) == UsernameEnumerationValidator._fingerprint(control)


def test_username_enumeration_recognizes_material_response_difference():
    known = observation(401, '{"status":"error","message":"Password incorrect"}')
    control = observation(404, '{"status":"error","message":"User not found"}')

    assert UsernameEnumerationValidator._fingerprint(known) != UsernameEnumerationValidator._fingerprint(control)


def test_cors_engine_only_targets_discovered_cors_routes():
    validator = CorsValidationEngine.__new__(CorsValidationEngine)
    endpoint = CrawledEndpoint(url="https://example.com/api/cors-test")
    ordinary = CrawledEndpoint(url="https://example.com/api/account")

    assert validator.CORS_ROUTE_RE.search(endpoint.normalized_path)
    assert not validator.CORS_ROUTE_RE.search(ordinary.normalized_path)
