import phantom_webhook_receiver as pwr


def test_internal_prompt_has_owned_lab_framing():
    prompt = pwr._build_internal_prompt(
        scan_id="s1", target_url="http://t", context_path="/tmp/ctx.json",
        session_block="",
    )
    assert "OWNED lab" in prompt
    assert "non-public" in prompt.lower() or "tailnet" in prompt.lower()
    assert "NOT INSTALLED" in prompt


def test_external_prompt_embeds_supplied_roe():
    prompt = pwr._build_external_prompt(
        scan_id="s1", target_url="http://t", context_path="/tmp/ctx.json",
        session_block="", roe_text="IN SCOPE: api.example.com ONLY",
        roe_basis="document", extraction_warning=False,
    )
    assert "IN SCOPE: api.example.com ONLY" in prompt
    assert "public-facing" in prompt.lower()
    assert "OWNED lab" not in prompt


def test_external_prompt_uses_default_roe_when_absent():
    prompt = pwr._build_external_prompt(
        scan_id="s1", target_url="http://t", context_path="/tmp/ctx.json",
        session_block="", roe_text=None, roe_basis="default_roe_v1",
        extraction_warning=False,
    )
    assert pwr.DEFAULT_ROE_V1.strip()[:30] in prompt
    assert "default_roe_v1" in prompt


def test_external_prompt_flags_extraction_warning():
    prompt = pwr._build_external_prompt(
        scan_id="s1", target_url="http://t", context_path="/tmp/ctx.json",
        session_block="", roe_text="", roe_basis="document",
        extraction_warning=True,
    )
    assert "extraction incomplete" in prompt.lower()


def test_goal_objective_is_single_line_with_ids():
    obj = pwr._goal_objective("scan-123", "http://target.local")
    assert "\n" not in obj  # MUST be single-line: used as the /goal arg in approach B
    assert "scan-123" in obj
    assert "http://target.local" in obj


def test_goal_block_has_objective_and_done_criteria():
    block = pwr._goal_block("scan-123", "http://target.local")
    assert "STANDING GOAL" in block
    assert pwr._goal_objective("scan-123", "http://target.local") in block
    assert "DONE CRITERIA" in block
    assert "/findings/ingest" in block
    assert "completed" in block.lower()


def test_durability_block_warns_about_compaction_and_flush():
    block = pwr._durability_block()
    low = block.lower()
    assert "compact" in low
    assert "volatile" in low
    assert "durable" in low or "persistent memory" in low
    assert "/findings/ingest" in block
    assert "before" in low  # flush BEFORE spending more turns
