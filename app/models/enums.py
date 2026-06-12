import uuid
from datetime import datetime, timezone
from enum import Enum

from sqlalchemy import DateTime
from sqlalchemy.orm import Mapped, mapped_column


def new_id() -> str:
    return str(uuid.uuid4())


def now_utc() -> datetime:
    return datetime.now(timezone.utc)


class ScanStatus(str, Enum):
    QUEUED = "queued"
    RUNNING = "running"
    STOPPING = "stopping"
    STOPPED = "stopped"
    COMPLETED = "completed"
    FAILED = "failed"


class FindingStatus(str, Enum):
    OPEN = "Open"
    ASSIGNED = "Assigned"
    IN_PROGRESS = "In Progress"
    RETEST = "Re-Test"
    CLOSED = "Closed"
    ACCEPTED_RISK = "Accepted Risk"
    FALSE_POSITIVE = "False Positive"


class Severity(str, Enum):
    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class SessionStatus(str, Enum):
    """Lifecycle of a Phantom agent exploration session.

    ``REFUSED`` is distinct from ``FAILED``: it means the agent deliberately
    declined to continue because an action collided with its non-offensive
    policy / rules of engagement — not a technical error.
    """

    IDLE = "idle"
    EXPLORING = "exploring"
    PENDING_APPROVAL = "pending_approval"
    APPROVED = "approved"
    DENIED = "denied"
    COMPLETED = "completed"
    FAILED = "failed"
    REFUSED = "refused"


class EngagementMode(str, Enum):
    """How an agent engagement is authorized.

    ``INTERNAL`` (SAFE): owned / pre-prod target, authorization on file.
    ``EXTERNAL`` (NSFW): authorized testing of a live / public-facing system,
    scope and limits derived from an attached Rules-of-Engagement document
    (or a versioned conservative default).
    """

    INTERNAL = "internal"
    EXTERNAL = "external"


class AgentActionPhase(str, Enum):
    """Canonical vocabulary for an agent session's ``current_action``.

    The agent reports free-text actions; ``normalize_action_phase`` maps those
    (or an explicit ``action_phase`` value) onto these stable values so the UI
    can render a uniform, descriptive label per phase.
    """

    INITIALIZING = "initializing"
    RECON = "recon"
    ENUMERATING_ACCOUNTS = "enumerating_accounts"
    TESTING_IDOR = "testing_idor"
    TESTING_AUTHZ = "testing_authz"
    TESTING_AUTH = "testing_auth"
    TESTING_INJECTION = "testing_injection"
    TESTING_INFO_DISCLOSURE = "testing_info_disclosure"
    SUBMITTING_FINDING = "submitting_finding"
    AWAITING_APPROVAL = "awaiting_approval"
    SUMMARIZING = "summarizing"
    COMPLETED = "completed"
    REFUSED = "refused"
    FAILED = "failed"
    UNKNOWN = "unknown"


# Human-readable label per phase (the frontend keeps its own copy for display;
# this is the source of truth shared by the agent prompt and any server logs).
ACTION_PHASE_LABELS: dict[AgentActionPhase, str] = {
    AgentActionPhase.INITIALIZING: "Initializing session",
    AgentActionPhase.RECON: "Recon & endpoint mapping",
    AgentActionPhase.ENUMERATING_ACCOUNTS: "Registering / enumerating test accounts",
    AgentActionPhase.TESTING_IDOR: "Testing IDOR / BOLA",
    AgentActionPhase.TESTING_AUTHZ: "Testing authorization / privilege escalation",
    AgentActionPhase.TESTING_AUTH: "Testing authentication / session / JWT",
    AgentActionPhase.TESTING_INJECTION: "Testing injection (XSS / SQLi)",
    AgentActionPhase.TESTING_INFO_DISCLOSURE: "Testing info disclosure / misconfig",
    AgentActionPhase.SUBMITTING_FINDING: "Submitting confirmed finding",
    AgentActionPhase.AWAITING_APPROVAL: "Awaiting operator approval",
    AgentActionPhase.SUMMARIZING: "Summarizing results",
    AgentActionPhase.COMPLETED: "Exploration complete",
    AgentActionPhase.REFUSED: "Halted by non-offensive policy",
    AgentActionPhase.FAILED: "Exploration failed",
    AgentActionPhase.UNKNOWN: "Working…",
}

# Keyword → phase rules, evaluated in order; the first phrase found in the
# lowercased free-text wins. Refusal phrases are checked first so a decline is
# never misread as ordinary testing.
_PHASE_KEYWORDS: tuple[tuple[tuple[str, ...], AgentActionPhase], ...] = (
    (
        # High-precision refusal phrases only: this phase flips the session to
        # the REFUSED status, so broad words ("policy", "out of scope") that
        # appear in benign pentest logs are deliberately excluded.
        (
            "refus",  # refuse / refusing / refused
            "non-offensive",
            "non offensive",
            "decline to continue",
            "decline to proceed",
            "declining to",
            "will not proceed",
            "won't proceed",
            "will not continue",
            "won't continue",
            "cannot continue",
            "can't continue",
            "cannot assist",
            "can't assist",
            "against my guidelines",
            "against policy",
            "policy prohibits",
            "violates policy",
            "ethical guidelines",
        ),
        AgentActionPhase.REFUSED,
    ),
    (("idor", "bola", "object reference", "cross-account", "swap"), AgentActionPhase.TESTING_IDOR),
    (("privilege", "authorization", "authz", "admin-only", "forced brows", "verb tamper"), AgentActionPhase.TESTING_AUTHZ),
    (("register", "usera", "userb", "create account", "enumerat"), AgentActionPhase.ENUMERATING_ACCOUNTS),
    (("jwt", "token", "login", "session", "auth", "password", "rate-limit", "rate limit"), AgentActionPhase.TESTING_AUTH),
    (("xss", "sqli", "sql injection", "inject", "payload"), AgentActionPhase.TESTING_INJECTION),
    (("disclosure", "misconfig", "nuclei", "nikto", "header", "verbose error", "debug"), AgentActionPhase.TESTING_INFO_DISCLOSURE),
    (("submit", "finding confirmed", "reporting finding"), AgentActionPhase.SUBMITTING_FINDING),
    (("approval", "awaiting"), AgentActionPhase.AWAITING_APPROVAL),
    (("recon", "endpoint map", "crawl", "discovery", "readiness"), AgentActionPhase.RECON),
    (("summary", "summariz", "concluding", "wrap up", "wrap-up"), AgentActionPhase.SUMMARIZING),
    (("start", "begin", "initial"), AgentActionPhase.INITIALIZING),
    (("complete", "done", "finished"), AgentActionPhase.COMPLETED),
    (("fail", "error", "crash"), AgentActionPhase.FAILED),
)


def normalize_action_phase(
    explicit: str | None = None,
    *texts: str | None,
) -> AgentActionPhase:
    """Resolve a canonical :class:`AgentActionPhase`.

    Prefers ``explicit`` when it is already a valid phase value (the agent sends
    ``action_phase``). Otherwise keyword-matches the free-text ``texts`` (e.g.
    ``current_action`` / log message). Falls back to ``UNKNOWN``.
    """
    if explicit:
        try:
            return AgentActionPhase(explicit.strip().lower())
        except ValueError:
            pass

    for text in (explicit, *texts):
        if not text:
            continue
        haystack = text.lower()
        for phrases, phase in _PHASE_KEYWORDS:
            if any(phrase in haystack for phrase in phrases):
                return phase
    return AgentActionPhase.UNKNOWN


class TimestampMixin:
    created_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime(timezone=True), default=now_utc, onupdate=now_utc, nullable=False
    )
