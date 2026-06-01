from app.recon import CrawledEndpoint
from app.services.discovery_validation import DiscoveryValidationService


def test_internal_api_discovery_flags_debug_routes():
    endpoint = CrawledEndpoint(
        url="https://example.com/internal/debug/metrics",
        status_code=200,
        content_type="application/json",
        response_body_sample='{"status":"ok"}',
    )

    result = DiscoveryValidationService().internal_api_finding(endpoint)

    assert result is not None
    assert result.finding_type == "internal_api_discovery"
    assert result.severity == "low"
    assert result.confidence >= 70


def test_protected_internal_endpoint_is_not_reported_as_vulnerability():
    endpoint = CrawledEndpoint(
        url="https://example.com/admin",
        status_code=403,
        content_type="application/json",
        response_body_sample='{"error":"forbidden"}',
    )

    result = DiscoveryValidationService().internal_api_finding(endpoint)

    assert result is not None
    assert result.finding_type == "protected_internal_surface"
    assert result.severity == "info"
    assert result.evidence["protected"] is True


def test_segmentation_detection_flags_private_metadata_leakage():
    endpoint = CrawledEndpoint(
        url="https://example.com/api/profile",
        status_code=200,
        content_type="application/json",
        response_body_sample='{"upstream":"dev.internal.local","db":"10.1.2.3"}',
    )

    result = DiscoveryValidationService().segmentation_finding(endpoint)

    assert result is not None
    assert result.finding_type == "segmentation_exposure"
    assert "10.1.2.3" in result.evidence["leaked_indicators"]
