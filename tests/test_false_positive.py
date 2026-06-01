from app.validation.false_positive import FalsePositiveReducer, SignalSet
from app.validation.types import HttpObservation


def observation(body: str, status: int = 200, elapsed: float = 100.0) -> HttpObservation:
    return HttpObservation(
        url="https://example.com/api/user?id=1",
        method="GET",
        status_code=status,
        elapsed_ms=elapsed,
        headers={},
        body_sample=body,
        content_length=len(body),
    )


def test_false_positive_reducer_accepts_multi_signal_sqli_evidence():
    baseline = observation("normal account response")
    candidate = observation("PostgreSQL ERROR: syntax error at or near quote")
    decision = FalsePositiveReducer().reduce(
        baseline,
        [candidate],
        SignalSet(sql_error=True, boolean_delta=True),
    )

    assert decision.accepted
    assert decision.confidence >= 70
    assert any("Database error" in reason for reason in decision.reasoning)


def test_false_positive_reducer_discards_soft_404_baseline():
    baseline = observation("route not found")
    candidate = observation("route not found")
    decision = FalsePositiveReducer().reduce(
        baseline,
        [candidate],
        SignalSet(status_changed=True),
    )

    assert not decision.accepted
    assert "soft 404" in " ".join(decision.reasoning).lower()


def test_false_positive_reducer_accepts_confirmed_sqli_auth_transition_with_error_status():
    baseline = observation("invalid credentials", status=401)
    sql_error = observation("PostgreSQL ERROR: syntax error", status=500)
    authenticated = observation('{"token":"issued"}', status=200)
    denial = observation("invalid credentials", status=401)

    decision = FalsePositiveReducer().reduce(
        baseline,
        [sql_error, authenticated, denial],
        SignalSet(
            sql_error=True,
            boolean_delta=True,
            status_changed=True,
            auth_context_changed=True,
            authentication_bypass=True,
        ),
    )

    assert decision.accepted
    assert decision.confidence >= 88
    assert any("corroborated" in reason for reason in decision.reasoning)


def test_false_positive_reducer_still_discards_unexplained_status_instability():
    decision = FalsePositiveReducer().reduce(
        observation("baseline", status=200),
        [observation("one", status=200), observation("two", status=401), observation("three", status=500)],
        SignalSet(status_changed=True),
    )

    assert not decision.accepted
    assert "unstable" in " ".join(decision.reasoning).lower()
