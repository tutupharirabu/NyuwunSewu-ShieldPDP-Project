# Phantom Persistent-Goal Budget (Approach A) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Harden the Phantom agent prompt builders so confirmed findings are flushed to durable backend storage before spending further turns, and add a standing-goal + done-criteria + resume-checklist scaffold that the native Hermes goal engine (approach B) can later reuse verbatim.

**Architecture:** Pure prompt-builder change in `phantom_webhook_receiver.py`. Extract small, individually testable helper functions (`_goal_objective`, `_goal_block`, `_durability_block`, `_checkpoint_block`, `_session_block`) and wire them into the existing internal/external prompt builders. No config, no new endpoints, no cron changes.

**Tech Stack:** Python 3 (stdlib only), pytest.

**Spec:** `docs/superpowers/specs/2026-06-13-phantom-persistent-goal-budget-design.md`

---

## File Structure

- **Modify:** `phantom_webhook_receiver.py`
  - Add `_goal_objective`, `_goal_block`, `_durability_block`, `_checkpoint_block`, `_session_block`.
  - Insert `_goal_block` + `_durability_block` into `_build_internal_prompt` and `_build_external_prompt`.
  - Replace the inline session-block f-string in `_create_exploration_job` with a call to `_session_block`.
  - Add a documented TODO seam describing how to enable approach B.
- **Modify:** `tests/test_phantom_prompt_builders.py` — add unit tests for each new helper and assertions on both prompt builders.

**Test command (run from repo root):** `pytest tests/test_phantom_prompt_builders.py -v`

---

### Task 1: Standing-goal helpers (`_goal_objective`, `_goal_block`)

**Files:**
- Modify: `phantom_webhook_receiver.py` (add functions after `DEFAULT_ROE_V1`, near line 135)
- Test: `tests/test_phantom_prompt_builders.py`

- [ ] **Step 1: Write the failing tests**

Add to `tests/test_phantom_prompt_builders.py`:

```python
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
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_phantom_prompt_builders.py::test_goal_objective_is_single_line_with_ids tests/test_phantom_prompt_builders.py::test_goal_block_has_objective_and_done_criteria -v`
Expected: FAIL with `AttributeError: module 'phantom_webhook_receiver' has no attribute '_goal_objective'`

- [ ] **Step 3: Write minimal implementation**

In `phantom_webhook_receiver.py`, after the `DEFAULT_ROE_V1` definition (after line 135), add:

```python
# --- Persistent-goal scaffold (approach A; reused verbatim by approach B) ---


def _goal_objective(scan_id: str, target_url: str) -> str:
    """One-line standing objective.

    MUST stay single-line: in approach B this exact string is passed as the
    `/goal` argument, where a newline would break the command.
    """
    return (
        f"Validate and submit EVERY confirmed finding for scan {scan_id} on "
        f"{target_url}, then mark the session completed (or refused)."
    )


def _goal_block(scan_id: str, target_url: str) -> str:
    """STANDING GOAL + judge-evaluable DONE CRITERIA.

    The DONE CRITERIA text is reused verbatim by the native goal-judge in
    approach B, so keep it phrased as objective, checkable conditions.
    """
    return f"""== STANDING GOAL (your single objective for this whole run) ==
{_goal_objective(scan_id, target_url)}
DONE CRITERIA - you are finished ONLY when:
  - every prioritized validation category has been attempted, AND
  - every confirmed finding has been submitted via POST /findings/ingest, AND
  - the session has been marked completed (or refused).
Treat every turn as spent toward this goal; do not wander."""
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `pytest tests/test_phantom_prompt_builders.py::test_goal_objective_is_single_line_with_ids tests/test_phantom_prompt_builders.py::test_goal_block_has_objective_and_done_criteria -v`
Expected: PASS (2 passed)

- [ ] **Step 5: Commit**

```bash
git add phantom_webhook_receiver.py tests/test_phantom_prompt_builders.py
git commit -m "feat(phantom): add standing-goal helpers (_goal_objective, _goal_block)"
```

---

### Task 2: Durability block (`_durability_block`)

**Files:**
- Modify: `phantom_webhook_receiver.py` (add after `_goal_block`)
- Test: `tests/test_phantom_prompt_builders.py`

- [ ] **Step 1: Write the failing test**

```python
def test_durability_block_warns_about_compaction_and_flush():
    block = pwr._durability_block()
    low = block.lower()
    assert "compact" in low
    assert "volatile" in low
    assert "durable" in low or "persistent memory" in low
    assert "/findings/ingest" in block
    assert "before" in low  # flush BEFORE spending more turns
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_phantom_prompt_builders.py::test_durability_block_warns_about_compaction_and_flush -v`
Expected: FAIL with `AttributeError: ... has no attribute '_durability_block'`

- [ ] **Step 3: Write minimal implementation**

In `phantom_webhook_receiver.py`, immediately after `_goal_block`, add:

```python
def _durability_block() -> str:
    """Flush-before-spend rule + explicit context-compaction warning."""
    return """== DURABILITY (CRITICAL - your context is volatile) ==
Your Hermes context WILL be compacted near the turn limit. Anything living ONLY
in context - partial evidence, half-built exploit chains, your note of which
endpoints you already checked - is LOST on compaction. The ShieldPDP backend is
your ONLY persistent memory. Therefore: the MOMENT a finding is confirmed, submit
it via POST /findings/ingest BEFORE doing anything else. Never hold a confirmed
finding to "batch later." Capture request+response evidence into the submission
at the moment of confirmation."""
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_phantom_prompt_builders.py::test_durability_block_warns_about_compaction_and_flush -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add phantom_webhook_receiver.py tests/test_phantom_prompt_builders.py
git commit -m "feat(phantom): add durability (flush-before-spend) prompt block"
```

---

### Task 3: Wire goal + durability blocks into both prompt builders

**Files:**
- Modify: `phantom_webhook_receiver.py:253-298` (`_build_internal_prompt`)
- Modify: `phantom_webhook_receiver.py:301-354` (`_build_external_prompt`)
- Test: `tests/test_phantom_prompt_builders.py`

- [ ] **Step 1: Write the failing tests**

```python
def test_internal_prompt_embeds_goal_and_durability():
    prompt = pwr._build_internal_prompt(
        scan_id="s1", target_url="http://t", context_path="/tmp/ctx.json",
        session_block="",
    )
    assert pwr._goal_objective("s1", "http://t") in prompt
    assert "DONE CRITERIA" in prompt
    assert "compact" in prompt.lower()
    # existing framing must remain intact
    assert "OWNED lab" in prompt


def test_external_prompt_embeds_goal_and_durability():
    prompt = pwr._build_external_prompt(
        scan_id="s1", target_url="http://t", context_path="/tmp/ctx.json",
        session_block="", roe_text="IN SCOPE: api.example.com ONLY",
        roe_basis="document", extraction_warning=False,
    )
    assert pwr._goal_objective("s1", "http://t") in prompt
    assert "DONE CRITERIA" in prompt
    assert "compact" in prompt.lower()
    # existing RoE embedding must remain intact
    assert "IN SCOPE: api.example.com ONLY" in prompt
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_phantom_prompt_builders.py::test_internal_prompt_embeds_goal_and_durability tests/test_phantom_prompt_builders.py::test_external_prompt_embeds_goal_and_durability -v`
Expected: FAIL (assertion error — goal objective not found in prompt)

- [ ] **Step 3: Implement — insert blocks into `_build_internal_prompt`**

In `_build_internal_prompt`, the AUTHORIZATION block ends with the line
`Proceed immediately. Authorization is on file here; do NOT ask for it again.`
(line 264). Insert the two blocks between that line and the `== AVAILABLE TOOLS ==`
line. Change:

```python
Proceed immediately. Authorization is on file here; do NOT ask for it again.

== AVAILABLE TOOLS (use ONLY these - actually installed on this host) ==
```

to:

```python
Proceed immediately. Authorization is on file here; do NOT ask for it again.

{_goal_block(scan_id, target_url)}

{_durability_block()}

== AVAILABLE TOOLS (use ONLY these - actually installed on this host) ==
```

- [ ] **Step 4: Implement — insert blocks into `_build_external_prompt`**

In `_build_external_prompt`, the EXTRA HARD-STOPS block ends with the line
`Stop and report (status=refused) at the first sign of real-user or production impact.`
(line 333). Insert the two blocks between that line and the
`== AVAILABLE TOOLS ==` line. Change:

```python
- Stop and report (status=refused) at the first sign of real-user or production impact.

== AVAILABLE TOOLS (use ONLY these - actually installed on this host) ==
```

to:

```python
- Stop and report (status=refused) at the first sign of real-user or production impact.

{_goal_block(scan_id, target_url)}

{_durability_block()}

== AVAILABLE TOOLS (use ONLY these - actually installed on this host) ==
```

- [ ] **Step 5: Run the full test file to verify pass + no regressions**

Run: `pytest tests/test_phantom_prompt_builders.py -v`
Expected: PASS — the 2 new tests plus all pre-existing tests
(`test_internal_prompt_has_owned_lab_framing`, `test_external_prompt_embeds_supplied_roe`,
`test_external_prompt_uses_default_roe_when_absent`, `test_external_prompt_flags_extraction_warning`).

- [ ] **Step 6: Commit**

```bash
git add phantom_webhook_receiver.py tests/test_phantom_prompt_builders.py
git commit -m "feat(phantom): embed standing-goal + durability blocks in both prompts"
```

---

### Task 4: Checkpoint block + extract `_session_block`

**Files:**
- Modify: `phantom_webhook_receiver.py` (add `_checkpoint_block` and `_session_block` near the other helpers; replace inline session-block in `_create_exploration_job:373-418`)
- Test: `tests/test_phantom_prompt_builders.py`

- [ ] **Step 1: Write the failing tests**

```python
def test_checkpoint_block_uses_ingest_log_and_budget_language():
    block = pwr._checkpoint_block("sess-9", "s1", "http://t")
    assert "CHECKPOINT" in block
    assert "/agent-sessions/sess-9/ingest-log" in block
    assert "near the turn budget" in block.lower()
    assert "details" in block


def test_session_block_includes_tracking_and_checkpoint():
    block = pwr._session_block("sess-9", "s1", "http://t")
    assert "SESSION TRACKING" in block
    assert "sess-9" in block
    assert "CHECKPOINT" in block  # checkpoint is appended to the session block
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `pytest tests/test_phantom_prompt_builders.py::test_checkpoint_block_uses_ingest_log_and_budget_language tests/test_phantom_prompt_builders.py::test_session_block_includes_tracking_and_checkpoint -v`
Expected: FAIL with `AttributeError: ... has no attribute '_checkpoint_block'`

- [ ] **Step 3: Add `_checkpoint_block`**

In `phantom_webhook_receiver.py`, after `_durability_block`, add:

```python
def _checkpoint_block(session_id: str, scan_id: str, target_url: str) -> str:
    """Resume-checklist instruction using the EXISTING ingest-log endpoint.

    Only meaningful when a session_id exists, so it lives inside the session
    block. The `details` object is the durable resume note that survives a
    context compaction and that an approach-B agent reads on resume.
    """
    return f"""== CHECKPOINT (durable resume trail) ==
At key milestones AND whenever you sense you are near the turn budget, push a
progress checkpoint so work survives a context compaction or a resume:
  curl -X POST {NYUWUNSEWU_URL}/agent-sessions/{session_id}/ingest-log \\
    -H "Content-Type: application/json" -H "X-Agent-Secret: {AGENT_SECRET}" \\
    -d '{{"level": "info", "message": "checkpoint", "action": "summarizing", "details": {{"categories_done": ["idor"], "endpoints_remaining": ["/api/x"], "in_progress": "authz on /admin"}}}}'
This `details` object is your durable resume note: categories completed, endpoints
remaining, and what is currently in progress."""
```

- [ ] **Step 4: Add `_session_block` (verbatim move of the existing inline string + appended checkpoint)**

In `phantom_webhook_receiver.py`, after `_checkpoint_block`, add the function below.
Its body is the exact string currently assigned to `session_block` inside
`_create_exploration_job` (lines 375-418), with `_checkpoint_block(...)` appended:

```python
def _session_block(session_id: str, scan_id: str, target_url: str) -> str:
    """SESSION TRACKING instructions + appended CHECKPOINT resume trail."""
    return f"""== SESSION TRACKING (update backend as you work) ==
Your AgentSession ID: {session_id}
Update your session state via the backend API so the operator can track progress.
Use these endpoints (auth: X-Agent-Secret header = {AGENT_SECRET}):

ALWAYS send an `action_phase` (canonical enum) on every update so the operator's
dashboard shows a uniform, descriptive status. Valid action_phase values:
  initializing, recon, enumerating_accounts, testing_idor, testing_authz,
  testing_auth, testing_injection, testing_info_disclosure, submitting_finding,
  awaiting_approval, summarizing, completed, refused, failed.
Pick the one matching what you are doing RIGHT NOW (e.g. testing_idor while
replaying swapped IDs, enumerating_accounts while registering userA/userB).

- Update status to "exploring" when you start:
  curl -X POST {NYUWUNSEWU_URL}/agent-sessions/ingest \\
    -H "Content-Type: application/json" -H "X-Agent-Secret: {AGENT_SECRET}" \\
    -d '{{"scan_id": "{scan_id}", "target_url": "{target_url}", "agent_name": "phantom", "status": "exploring", "action_phase": "recon", "message": "Agent started, beginning validation", "level": "info"}}'

- Push log entries for key milestones (include `action_phase`, and a `details`
  object for any structured context — it is shown verbatim to the operator):
  curl -X POST {NYUWUNSEWU_URL}/agent-sessions/{session_id}/ingest-log \\
    -H "Content-Type: application/json" -H "X-Agent-Secret: {AGENT_SECRET}" \\
    -d '{{"level": "info", "message": "Completed IDOR check on /api/accounts", "action": "testing_idor", "details": {{"endpoint": "/api/accounts", "result": "no cross-account read"}}}}'
  Levels: info, warning, error, success.

- Increment findings_count when you submit a finding (call the ingest endpoint
  with status="exploring", action_phase="submitting_finding").

- When ALL done, mark session complete:
  curl -X POST {NYUWUNSEWU_URL}/agent-sessions/{session_id}/ingest-complete \\
    -H "X-Agent-Secret: {AGENT_SECRET}" \\
    -d 'findings_count=<number_of_findings_submitted>'

- REFUSAL: if at any point you decline to continue because an action would
  collide with your non-offensive policy / rules of engagement, do NOT silently
  stop. Report it explicitly so the session is marked "refused" (an ethical
  halt, distinct from a crash) with the reason visible to the operator:
  curl -X POST {NYUWUNSEWU_URL}/agent-sessions/ingest \\
    -H "Content-Type: application/json" -H "X-Agent-Secret: {AGENT_SECRET}" \\
    -d '{{"scan_id": "{scan_id}", "target_url": "{target_url}", "agent_name": "phantom", "status": "refused", "action_phase": "refused", "level": "warning", "message": "<one-line reason you are declining to proceed>"}}'

Do this at key milestones: start (status=exploring), each finding confirmed,
the very end (status=completed), and immediately on any policy refusal
(status=refused).

{_checkpoint_block(session_id, scan_id, target_url)}"""
```

- [ ] **Step 5: Replace the inline session-block in `_create_exploration_job`**

In `_create_exploration_job`, replace the current block (lines 373-418):

```python
    session_block = ""
    if session_id:
        session_block = f"""== SESSION TRACKING (update backend as you work) ==
...                       # (the entire inline f-string, through the refusal example)
(status=refused)."""
```

with:

```python
    session_block = ""
    if session_id:
        session_block = _session_block(session_id, scan_id, target_url)
```

- [ ] **Step 6: Run tests to verify pass + no regressions**

Run: `pytest tests/test_phantom_prompt_builders.py -v`
Expected: PASS — the 2 new tests plus all earlier tests.

- [ ] **Step 7: Sanity-check the module still imports (no syntax/brace errors)**

Run: `python -c "import phantom_webhook_receiver"`
Expected: exit 0 (may print `[WARN] ...` secret lines in local env — that is fine; no traceback).

- [ ] **Step 8: Commit**

```bash
git add phantom_webhook_receiver.py tests/test_phantom_prompt_builders.py
git commit -m "feat(phantom): add checkpoint resume trail, extract _session_block"
```

---

### Task 5: Documented seam for approach B

**Files:**
- Modify: `phantom_webhook_receiver.py` (comment near `_goal_objective` and near `_create_exploration_job`'s cron call)

- [ ] **Step 1: Add the seam comment above `_create_exploration_job`'s `_hermes_cli("cron", ...)` call (line ~432)**

Immediately before the `result = _hermes_cli("cron", "create", ...)` call, add:

```python
    # --- APPROACH B SEAM (not enabled in approach A) ---
    # To activate Hermes' native persistent-goal engine later:
    #   1. Prepend the standing goal as a /goal command:
    #        prompt = f"/goal {_goal_objective(scan_id, target_url)}\n\n" + prompt
    #   2. Add a goals block to ~/.hermes/config.yaml
    #      (goals.max_turns + auxiliary.goal_judge).
    #   3. The goal-judge reuses the DONE CRITERIA from _goal_block verbatim.
    # See docs/superpowers/specs/2026-06-13-phantom-persistent-goal-budget-design.md
```

- [ ] **Step 2: Verify module still imports**

Run: `python -c "import phantom_webhook_receiver"`
Expected: exit 0, no traceback.

- [ ] **Step 3: Commit**

```bash
git add phantom_webhook_receiver.py
git commit -m "docs(phantom): document approach-B activation seam"
```

---

### Task 6: Final verification

- [ ] **Step 1: Run the full prompt-builder test file**

Run: `pytest tests/test_phantom_prompt_builders.py -v`
Expected: PASS — all tests (4 original + 6 new = 10 tests).

- [ ] **Step 2: Run the broader test suite to confirm nothing else broke**

Run: `pytest tests/ -q`
Expected: no new failures attributable to this change.

- [ ] **Step 3: Confirm the seam constants line up**

Run: `python -c "import phantom_webhook_receiver as p; print(p._goal_objective('s','u')); assert '\n' not in p._goal_objective('s','u')"`
Expected: prints the one-line objective; no AssertionError (single-line invariant holds, so `/goal` arg is safe in approach B).

---

## Self-Review

**Spec coverage:**
- §4 refactor (`_goal_objective`, `_goal_block`, `_durability_block`, `_session_block`) → Tasks 1, 2, 4. ✅
- §5 STANDING GOAL block → Task 1 + wired in Task 3. ✅
- §5 DURABILITY block → Task 2 + wired in Task 3. ✅
- §5 CHECKPOINT (session-gated, existing ingest-log endpoint) → Task 4. ✅
- §6 documented approach-B seam (not dead code) → Task 5. ✅
- §7 tests: single-line `_goal_objective`, goal/durability in both prompts, existing tests green → Tasks 1, 3, 6. ✅
- §8 scope guard: no config.yaml, no `--repeat` change, no new endpoint → honored (no task touches them). ✅

**Placeholder scan:** No TBD/TODO-as-placeholder. The only "TODO-like" content is the intentional, fully-specified approach-B seam comment (Task 5). Every code step shows complete code. ✅

**Type/name consistency:** `_goal_objective(scan_id, target_url)`, `_goal_block(scan_id, target_url)`, `_durability_block()`, `_checkpoint_block(session_id, scan_id, target_url)`, `_session_block(session_id, scan_id, target_url)` — signatures referenced identically across Tasks 1-5. The single-line invariant asserted in Task 1 and re-checked in Task 6 is consistent. ✅
