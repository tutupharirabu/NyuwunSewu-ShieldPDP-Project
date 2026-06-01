from app.services.policy_engine import PolicyEngine, ScanPolicyConfig


def test_policy_engine_enforces_excluded_paths_and_validation_flags():
    policy = PolicyEngine(
        ScanPolicyConfig(
            allow_sqli_validation=False,
            excluded_paths=["/payment/live", "/admin/*"],
            forbidden_paths=["/admin/delete"],
        )
    )

    assert policy.is_path_excluded("https://example.com/payment/live")
    assert policy.is_path_excluded("https://example.com/admin/users")
    assert not policy.is_validation_allowed("sqli")
    assert not policy.is_validation_allowed("reflected_html")
    assert policy.is_validation_allowed("auth")
