"""Guard for the data_rights package split (engine composed from per-right mixins).

The three large ``test_right_*`` methods were moved verbatim into separate mixin
modules; this locks the composition so a broken MRO, a dropped method, or an
unreachable shared class-attribute fails fast.
"""

from app.validation.data_rights import DataRightsTestResult, DataRightsValidationEngine


def test_engine_composition_and_helpers():
    engine = DataRightsValidationEngine()  # no scope_guard

    # every public + helper method resolves through the mixin MRO
    for name in (
        "test_right_to_be_forgotten",
        "test_right_to_access",
        "test_right_to_rectification",
        "assess_all_rights",
        "_make_request",
        "_resolve_endpoint",
        "_determine_status",
    ):
        assert callable(getattr(engine, name)), f"missing {name}"

    # shared endpoint catalogs are reachable via the base class
    assert engine.DELETION_ENDPOINTS and engine.ACCESS_ENDPOINTS
    assert engine.UPDATE_ENDPOINTS and engine.PII_FIELDS

    # pure helpers preserve their original behavior
    assert engine._determine_status(90) == "compliant"
    assert engine._determine_status(60) == "partial"
    assert engine._determine_status(30) == "non_compliant"
    assert engine._determine_status(5) == "not_testable"
    assert engine._resolve_endpoint(
        "https://x.test", "/api/users/{id}/delete", "42"
    ).endswith("/api/users/42/delete")

    assert DataRightsTestResult.__dataclass_fields__["right_type"]
