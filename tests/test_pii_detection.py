from app.pii_detection import PIIDetectionEngine


def test_pii_detection_identifies_indonesian_privacy_signals():
    content = """
    user email: rani@example.co.id
    nik: 3175014401010001
    rekening bank mandiri 1234567890123
    access_token: abcdefghijklmnopqrstuvwxyz123456
    """

    detections = PIIDetectionEngine().detect(content)
    types = {item.pii_type for item in detections}

    assert "email" in types
    assert "nik" in types
    assert "bank_account_number" in types
    assert "access_token" in types
    assert max(item.confidence for item in detections) >= 80


def test_pii_detection_rejects_test_cards_dummy_numbers_and_contextless_accounts():
    content = """
    visa test card 4111111111111111
    dummy id 1111111111111111
    random number 9876543210123
    virtual account transfer 8877665544332211
    """

    detections = PIIDetectionEngine().detect(content)
    by_type = {item.pii_type for item in detections}

    assert "nik" not in by_type
    assert sum(1 for item in detections if item.pii_type == "bank_account_number") == 1
