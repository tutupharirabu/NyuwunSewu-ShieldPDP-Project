# Phantom Persistent-Goal Budget Optimization — Design (Approach A)

**Date:** 2026-06-13
**Status:** Approved (design), pending implementation plan
**Scope:** `phantom_webhook_receiver.py` prompt builders + tests
**Author:** brainstormed with operator

---

## 1. Problem

The Phantom agent runs against a **hard Hermes turn budget of 90 turns** per execution.
The exploration prompt is fired as a **one-shot cron job** (`hermes cron create ... --repeat 1`).

The operator's concern (a hypothesis, not yet empirically observed): when the 90-turn
budget is exhausted, Hermes **compacts its context**, and **finding details that live
only in the context window are lost** — partial evidence, half-built exploit chains, and
the agent's mental note of which endpoints it already checked.

The operator wants Hermes' *persistent goals* concept
([docs](https://hermes-agent.nousresearch.com/docs/user-guide/features/goals#configuration))
to act as a durable layer so the limited budget is not wasted and finding detail survives.

## 2. Key constraints discovered

1. **Hermes goal-state is small.** Per the docs, `SessionDB.state_meta` (`goal:<session_id>`)
   persists only: goal text, status, turn counter/budget, and a **subgoal list**. It is a
   *checklist*, **not** a store for large evidence blobs. Relying on goal-state to hold
   finding *detail* would still lose that detail on compaction.
2. **`hermes` is not available in the dev environment** (it runs on the production host).
   We **cannot verify** whether this Hermes build actually ships the native `goals` /
   `/goal` engine. The design must not depend on unverified native support.
3. **Confirmed findings are already durable** once submitted: the current prompt already
   instructs `POST /findings/ingest` "as you go", and submitted findings live in the
   ShieldPDP DB — context compaction cannot touch them.

Therefore the fear decomposes into two distinct needs:
- **Confirmed finding detail** → must be flushed to durable backend storage *before*
  spending more turns (already partly designed; needs hardening).
- **Unfinished work** (in-progress validation, remaining endpoint queue) → kept as a
  lightweight **resume checklist**.

## 3. Chosen approach: A (prompt hardening) as the foundation for B (native goals)

Approach A changes **only the prompt builders + tests**. It establishes every *text
contract* that the native goal engine (Approach B) will later consume verbatim, so
enabling B becomes additive, not a rewrite.

Rejected for now:
- **B (native goal engine)** — more faithful to the docs but depends on unverified Hermes
  support; still requires A's "flush" rule regardless. Deferred; A is its foundation.
- **C (checkpoint-file across cron ticks)** — most robust but most code and most failure
  modes (state sync, finding dedup). Overkill for a hypothesis. Out of scope.

### Guiding principle
> **Hermes context is volatile; the ShieldPDP backend is durable.** Any confirmed finding
> is flushed to durable storage *before* spending further turns. The persistent goal in A
> is a *text contract* (standing objective + done-criteria + resume checklist) later
> consumed as-is by the native goal engine in B.

## 4. Code structure (refactor for B-readiness)

In `phantom_webhook_receiver.py`, extract small blocks shared by both the internal and
external prompt builders:

- `_goal_objective(scan_id, target_url) -> str`
  A **single line, no newlines.** Example:
  `"Validate and submit EVERY confirmed finding for scan {scan_id} on {target_url}, then mark the session completed (or refused)."`
  In A it is embedded as text. In **B the same string becomes the `/goal` argument** —
  one source, two consumers. (Single-line invariant is what makes it safe as a `/goal` arg.)

- `_goal_block(scan_id, target_url) -> str`
  A `== STANDING GOAL ==` block wrapping `_goal_objective(...)`, plus **DONE CRITERIA**
  written in **judge-evaluable** language so B's goal-judge can reuse it verbatim. Done
  only when: every prioritized validation category has been attempted, every confirmed
  finding has been submitted via `/findings/ingest`, and the session has been marked
  `completed` (or `refused`).

- `_durability_block() -> str`
  The **"flush before spend"** rule plus an explicit context-compaction warning.

- `_shared_blocks(...)` — unchanged responsibility (SUBMISSION + HARD RULES) but now
  references the durability rule.

Both `_build_internal_prompt` and `_build_external_prompt` insert `_goal_block(...)` and
`_durability_block()` at the appropriate position. No duplicated logic.

## 5. New block contents

**STANDING GOAL** — placed immediately after the AUTHORIZATION block, prominent:
```
== STANDING GOAL (your single objective for this whole run) ==
<one-line objective from _goal_objective>
DONE CRITERIA — you are finished ONLY when:
  - every prioritized validation category has been attempted, AND
  - every confirmed finding has been submitted via POST /findings/ingest, AND
  - the session has been marked completed (or refused).
Treat every turn as spent toward this goal; do not wander.
```

**DURABILITY** — directly answers the compaction fear:
```
== DURABILITY (CRITICAL — your context is volatile) ==
Your Hermes context WILL be compacted near the turn limit. Anything living ONLY in
context — partial evidence, half-built exploit chains, your note of which endpoints
you already checked — is LOST on compaction. The ShieldPDP backend is your ONLY
persistent memory. Therefore: the MOMENT a finding is confirmed, submit it via
POST /findings/ingest BEFORE doing anything else. Never hold a confirmed finding to
"batch later." Capture request+response evidence into the submission at the moment of
confirmation.
```

**CHECKPOINT** — resume groundwork using the **existing** session-log endpoint:
At key milestones and whenever the agent senses it is near the turn budget, push a
progress checkpoint via `POST /agent-sessions/{session_id}/ingest-log` with a `details`
object: categories completed, endpoints remaining, what is in progress. This is a durable
trail + operator visibility, and the material a future Approach-B agent reads on resume.
(Only emitted when a `session_id` is present, i.e. inside the existing `session_block`.)

## 6. Upgrade path to B (prepared, not built)

Enabling B later = three small additions, with **no change to A's blocks**:
1. A `use_native_goal` flag in `_create_exploration_job`; when true, **prepend**
   `f"/goal {_goal_objective(...)}\n\n"` above the prompt.
2. Add a `goals.max_turns` + `auxiliary.goal_judge` block to `~/.hermes/config.yaml`.
3. The goal-judge consumes the DONE CRITERIA from `_goal_block` verbatim.

A deliberately leaves this seam as a **documented TODO**, not dead code.

## 7. Testing (extend `tests/test_phantom_prompt_builders.py`)

- `_goal_objective(...)` returns a **single line** (no `\n`) containing both `scan_id` and
  `target_url` — proving it is safe as a future `/goal` argument.
- Internal **and** external prompts contain: the standing-goal objective text, durability
  keywords (`compact` / `volatile` / `durable`), and the checkpoint instruction.
- Existing tests stay green: owned-lab framing, RoE embedding, default-RoE, extraction
  warning.

## 8. Scope guard (deliberately NOT in A)

- Does **not** touch `config.yaml`; does **not** enable the native goal engine.
- Does **not** change `--repeat 1` to multi-tick; does **not** add a checkpoint state-file
  (that is Approach C).
- Does **not** add any new backend endpoint — reuses existing `/findings/ingest` and
  `/agent-sessions/{session_id}/ingest-log`.
