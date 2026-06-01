from app.classifier import EndpointClassifier


def test_classifier_scores_financial_api_endpoint():
    results = EndpointClassifier().classify(
        "https://example.com/api/transfer?customer_id=123",
        method="POST",
    )

    top = results[0]
    assert top.classification == "financial"
    assert top.confidence >= 70
    assert top.risk in {"medium", "high"}
    assert any("Financial" in reason for reason in top.reasoning)

