"""
GitHub CARINA Dispatcher Gateway — Debug Template

This script models a GitHub webhook intake pipeline that routes events through 
the CARINA (Command Autonomous Routing and Intake Notary Agent) dispatcher. 
It includes mock signature failures and a three-tier security boundary check.

Sections:
  1. Imports and constants
  2. Exceptions
  3. Data models
  4. Security policy engine
  5. Signature verifier (with mock failure injection)
  6. Payload parser
  7. CARINA dispatcher
  8. Gateway entry point
  9. CLI runner
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import sqlite3
import time
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any
from uuid import uuid4

# ---------------------------------------------------------------------------
# 1. Constants
# ---------------------------------------------------------------------------

GITHUB_SIGNATURE_HEADER = "X-Hub-Signature-256"
GITHUB_EVENT_HEADER = "X-GitHub-Event"
GITHUB_DELIVERY_HEADER = "X-GitHub-Delivery"

WEBHOOK_SECRET = os.environ.get("GITHUB_WEBHOOK_SECRET", "dev-secret-change-me")

# Set MOCK_SIG_FAILURE=1 to force a signature failure on every request.
MOCK_SIG_FAILURE = os.environ.get("MOCK_SIG_FAILURE", "0") == "1"

LOG_LEVEL = os.environ.get("LOG_LEVEL", "DEBUG")

logging.basicConfig(
    level=getattr(logging, LOG_LEVEL),
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
)
log = logging.getLogger("carina.gateway")

# ---------------------------------------------------------------------------
# 2. Exceptions
# ---------------------------------------------------------------------------


class GatewayError(Exception):
    """Base class for all gateway errors."""


class SignatureVerificationError(GatewayError):
    """The request signature is invalid or missing."""


class PayloadParseError(GatewayError):
    """The payload is not valid JSON or has missing fields."""


class SecurityDenyError(GatewayError):
    """The security policy denied this event."""


class DispatchError(GatewayError):
    """The CARINA dispatcher failed to route this event."""


class IntakeAuthorizationError(GatewayError):
    """The intake layer attempted to represent or grant execution authority."""


# ---------------------------------------------------------------------------
# 3. Data models
# ---------------------------------------------------------------------------


class SecurityDecision(str, Enum):
    ALLOW = "ALLOW"
    APPROVAL_REQUIRED = "APPROVAL_REQUIRED"
    DENY = "DENY"


class IntakePhase(str, Enum):
    INTENT = "INTENT"
    EVIDENCE = "EVIDENCE"
    DECISION = "DECISION"


@dataclass(frozen=True)
class IntakeRecord:
    record_id: str
    phase: IntakePhase | str
    repo_full_name: str
    issue_number: int
    issue_title: str
    issue_body: str
    issue_url: str
    actor: str
    delivery_id: str
    read_only: bool = True
    authorization_granted: bool = False
    authorization_authority: str = "CARINA_ONLY"


@dataclass(frozen=True)
class InboundRequest:
    delivery_id: str
    event_type: str
    raw_signature: str
    raw_body: bytes
    received_at: float = field(default_factory=time.time)


@dataclass(frozen=True)
class ParsedEvent:
    delivery_id: str
    event_type: str
    action: str
    actor: str
    repo_full_name: str
    payload: dict[str, Any]


@dataclass(frozen=True)
class SecurityResult:
    decision: SecurityDecision
    reason: str
    rule_id: str


@dataclass(frozen=True)
class DispatchResult:
    dispatch_id: str
    event_type: str
    decision: SecurityDecision
    routed_to: str | None
    message: str


# ---------------------------------------------------------------------------
# 4. Security policy engine
# ---------------------------------------------------------------------------

# Each rule is a tuple: (rule_id, actor_prefix, event_type, action, decision, reason).
# Rules are evaluated top to bottom. The first match wins.
# Use "*" to match any value.

SECURITY_RULES: list[tuple[str, str, str, str, SecurityDecision, str]] = [
    # Deny bots that are not explicitly trusted.
    (
        "RULE-001",
        "dependabot",
        "pull_request",
        "opened",
        SecurityDecision.APPROVAL_REQUIRED,
        "Dependabot PRs require a human review before dispatch.",
    ),
    (
        "RULE-002",
        "github-actions",
        "*",
        "*",
        SecurityDecision.DENY,
        "github-actions actor is not permitted to trigger CARINA.",
    ),
    # Deny destructive branch actions from any actor.
    (
        "RULE-003",
        "*",
        "delete",
        "*",
        SecurityDecision.DENY,
        "Branch or tag deletion events are blocked.",
    ),
    # Require approval for repository visibility changes.
    (
        "RULE-004",
        "*",
        "repository",
        "publicized",
        SecurityDecision.APPROVAL_REQUIRED,
        "Repository visibility change requires manual approval.",
    ),
    # Allow standard pull-request and push events from human actors.
    (
        "RULE-005",
        "*",
        "pull_request",
        "opened",
        SecurityDecision.ALLOW,
        "Standard PR opened event.",
    ),
    (
        "RULE-006",
        "*",
        "pull_request",
        "synchronize",
        SecurityDecision.ALLOW,
        "PR synchronize event.",
    ),
    (
        "RULE-007",
        "*",
        "push",
        "*",
        SecurityDecision.ALLOW,
        "Push event allowed.",
    ),
    # GitHub issue intake is coordination/evidence only. These rules allow
    # normalization into read-only CARINA intake records, never authorization.
    (
        "RULE-008",
        "*",
        "issues",
        "opened",
        SecurityDecision.ALLOW,
        "Issue opened event may enter the read-only intake ledger.",
    ),
    (
        "RULE-009",
        "*",
        "issues",
        "edited",
        SecurityDecision.ALLOW,
        "Issue edits may add read-only evidence.",
    ),
    (
        "RULE-010",
        "*",
        "issues",
        "reopened",
        SecurityDecision.ALLOW,
        "Reopened intake issue may be re-evaluated.",
    ),
    # Deny everything else by default.
    (
        "RULE-999",
        "*",
        "*",
        "*",
        SecurityDecision.DENY,
        "No rule matched. Default deny.",
    ),
]


def _match(pattern: str, value: str) -> bool:
    """Return True if pattern is '*' or equals value."""
    return pattern == "*" or pattern == value


def evaluate_security(event: ParsedEvent) -> SecurityResult:
    """
    Evaluate the event against the security rule table.
    Return the first matching SecurityResult.
    """
    log.debug(
        "Security check — actor=%s event_type=%s action=%s repo=%s",
        event.actor,
        event.event_type,
        event.action,
        event.repo_full_name,
    )

    for rule_id, actor_prefix, event_type, action, decision, reason in SECURITY_RULES:
        actor_match = _match(actor_prefix, event.actor) or event.actor.startswith(actor_prefix)
        event_match = _match(event_type, event.event_type)
        action_match = _match(action, event.action)

        if actor_match and event_match and action_match:
            log.info(
                "Security rule matched — rule=%s decision=%s reason=%s",
                rule_id,
                decision.value,
                reason,
            )
            return SecurityResult(decision=decision, reason=reason, rule_id=rule_id)

    # This line is only reachable if RULE-999 is removed. Guard against that.
    log.critical("No security rule matched. This is a configuration error.")
    return SecurityResult(
        decision=SecurityDecision.DENY,
        reason="Security engine reached the end without a match. Default deny.",
        rule_id="RULE-FALLBACK",
    )


# ---------------------------------------------------------------------------
# 5. Signature verifier
# ---------------------------------------------------------------------------


def verify_signature(request: InboundRequest, secret: str) -> None:
    """
    Verify the HMAC-SHA256 signature from GitHub.

    GitHub sends: X-Hub-Signature-256: sha256=<hex_digest>

    Raises SignatureVerificationError on any failure.
    The function logs the exact failure reason before raising.
    """
    log.debug("Verifying signature for delivery=%s", request.delivery_id)

    # --- Mock failure injection ---
    if MOCK_SIG_FAILURE:
        log.error(
            "MOCK_SIG_FAILURE is enabled. "
            "Injecting a forced signature verification failure for delivery=%s.",
            request.delivery_id,
        )
        raise SignatureVerificationError(
            f"[MOCK] Forced signature failure for delivery={request.delivery_id}. "
            "Disable MOCK_SIG_FAILURE to use real verification."
        )

    # --- Real verification ---
    sig_header = request.raw_signature.strip()

    if not sig_header:
        log.error(
            "Missing signature header for delivery=%s. "
            "GitHub should always send '%s'. "
            "Check that the webhook is configured with a secret.",
            request.delivery_id,
            GITHUB_SIGNATURE_HEADER,
        )
        raise SignatureVerificationError(
            f"Signature header is missing. delivery={request.delivery_id}"
        )

    if not sig_header.startswith("sha256="):
        log.error(
            "Signature has wrong prefix for delivery=%s. "
            "Expected 'sha256=...', got prefix '%s...'.",
            request.delivery_id,
            sig_header[:10],
        )
        raise SignatureVerificationError(
            f"Signature prefix is invalid. Expected 'sha256='. delivery={request.delivery_id}"
        )

    provided_digest = sig_header[len("sha256="):]

    if not provided_digest:
        log.error(
            "Signature header has prefix 'sha256=' but no digest. delivery=%s",
            request.delivery_id,
        )
        raise SignatureVerificationError(
            f"Signature digest is empty. delivery={request.delivery_id}"
        )

    expected_digest = hmac.new(
        key=secret.encode("utf-8"),
        msg=request.raw_body,
        digestmod=hashlib.sha256,
    ).hexdigest()

    if not hmac.compare_digest(provided_digest, expected_digest):
        # Log lengths, not values, to avoid leaking the secret or a valid digest.
        log.error(
            "Signature mismatch for delivery=%s. "
            "Provided digest length=%d, expected digest length=%d. "
            "Possible causes: wrong secret configured in GitHub, "
            "payload was modified in transit, or a replay attack.",
            request.delivery_id,
            len(provided_digest),
            len(expected_digest),
        )
        raise SignatureVerificationError(
            f"Signature mismatch. delivery={request.delivery_id}"
        )

    log.debug("Signature verified OK for delivery=%s", request.delivery_id)


# ---------------------------------------------------------------------------
# 6. Payload parser
# ---------------------------------------------------------------------------


def parse_event(request: InboundRequest) -> ParsedEvent:
    """
    Parse the raw JSON body into a ParsedEvent.
    Raises PayloadParseError on any structural problem.
    """
    log.debug("Parsing payload for delivery=%s", request.delivery_id)

    try:
        data: dict[str, Any] = json.loads(request.raw_body)
    except json.JSONDecodeError as exc:
        log.error(
            "JSON decode failed for delivery=%s. "
            "Offset=%d, error=%s. "
            "Check that Content-Type is application/json.",
            request.delivery_id,
            exc.pos,
            exc.msg,
        )
        raise PayloadParseError(
            f"JSON decode error at offset {exc.pos}: {exc.msg}. delivery={request.delivery_id}"
        ) from exc

    required_top_level = ["repository", "sender"]
    for field_name in required_top_level:
        if field_name not in data:
            log.error(
                "Payload missing required field '%s' for delivery=%s. "
                "Present keys: %s.",
                field_name,
                request.delivery_id,
                list(data.keys()),
            )
            raise PayloadParseError(
                f"Missing required field '{field_name}'. delivery={request.delivery_id}"
            )

    action = data.get("action", "")
    actor = data.get("sender", {}).get("login", "unknown")
    repo_full_name = data.get("repository", {}).get("full_name", "unknown/unknown")

    log.debug(
        "Parsed event — type=%s action=%s actor=%s repo=%s",
        request.event_type,
        action,
        actor,
        repo_full_name,
    )

    return ParsedEvent(
        delivery_id=request.delivery_id,
        event_type=request.event_type,
        action=action,
        actor=actor,
        repo_full_name=repo_full_name,
        payload=data,
    )


# ---------------------------------------------------------------------------
# 7. Read-only GitHub intake bridge
# ---------------------------------------------------------------------------

_ALLOWED_INTAKE_PHASES = frozenset(phase.value for phase in IntakePhase)


def _phase_value(phase: IntakePhase | str) -> str:
    return phase.value if isinstance(phase, IntakePhase) else str(phase)


def validate_intake_record(record: IntakeRecord) -> IntakeRecord:
    """
    Enforce the authorization ceiling for GitHub-derived intake records.

    This layer may represent INTENT, EVIDENCE, or DECISION only. It cannot
    create AUTHORIZED state, grant authority, or become writable execution
    state. CARINA remains the sole authority for execution transitions.
    """
    phase = _phase_value(record.phase)

    if phase not in _ALLOWED_INTAKE_PHASES:
        raise IntakeAuthorizationError(
            f"GitHub intake phase '{phase}' is forbidden. "
            "Only INTENT, EVIDENCE, and DECISION are accepted."
        )
    if not record.read_only:
        raise IntakeAuthorizationError("GitHub intake records must remain read-only.")
    if record.authorization_granted:
        raise IntakeAuthorizationError(
            "GitHub intake cannot grant execution authorization."
        )
    if record.authorization_authority != "CARINA_ONLY":
        raise IntakeAuthorizationError(
            "Authorization authority must remain CARINA_ONLY."
        )

    return record


def map_issue_to_intake_record(event: ParsedEvent) -> IntakeRecord | None:
    """
    Normalize portfolio issue lifecycle events into a read-only CARINA record.

    Mapping:
      [Idea] opened/reopened -> INTENT
      [Idea] edited          -> EVIDENCE
      [Collaboration]        -> DECISION

    Proof records belong to verification, not intake, and ordinary issues are
    ignored by this bridge.
    """
    if event.event_type != "issues":
        return None

    issue = event.payload.get("issue")
    if not isinstance(issue, dict):
        raise PayloadParseError(
            f"Issues event is missing an issue object. delivery={event.delivery_id}"
        )

    title = str(issue.get("title", "")).strip()
    action = event.action

    if title.startswith("[Idea]:"):
        if action in ("opened", "reopened"):
            phase = IntakePhase.INTENT
        elif action == "edited":
            phase = IntakePhase.EVIDENCE
        else:
            return None
    elif title.startswith("[Collaboration]:"):
        if action not in ("opened", "edited", "reopened"):
            return None
        phase = IntakePhase.DECISION
    else:
        return None

    try:
        issue_number = int(issue["number"])
    except (KeyError, TypeError, ValueError) as exc:
        raise PayloadParseError(
            f"Intake issue number is missing or invalid. delivery={event.delivery_id}"
        ) from exc

    record = IntakeRecord(
        record_id=(
            f"github:{event.repo_full_name}:issue:{issue_number}:"
            f"{event.delivery_id}"
        ),
        phase=phase,
        repo_full_name=event.repo_full_name,
        issue_number=issue_number,
        issue_title=title,
        issue_body=str(issue.get("body") or ""),
        issue_url=str(issue.get("html_url") or ""),
        actor=event.actor,
        delivery_id=event.delivery_id,
    )
    return validate_intake_record(record)


def serialize_intake_record(record: IntakeRecord) -> dict[str, Any]:
    """Return the canonical ledger payload after enforcing the safety ceiling."""
    validate_intake_record(record)
    return {
        "record_id": record.record_id,
        "record_type": "github_intake",
        "phase": _phase_value(record.phase),
        "read_only": True,
        "authorization": {
            "granted": False,
            "authority": "CARINA_ONLY",
        },
        "source": {
            "provider": "github",
            "repository": record.repo_full_name,
            "issue_number": record.issue_number,
            "issue_url": record.issue_url,
            "delivery_id": record.delivery_id,
            "actor": record.actor,
        },
        "content": {
            "title": record.issue_title,
            "body": record.issue_body,
        },
    }


def append_intake_record(
    record: IntakeRecord,
    sink,
) -> dict[str, Any]:
    """
    Append a validated intake payload through a caller-supplied ledger sink.

    The sink receives evidence only. This function has no authorization or
    execution method by design.
    """
    payload = serialize_intake_record(record)
    sink(payload)
    return payload


def _validate_serialized_intake_payload(payload: dict[str, Any]) -> None:
    phase = str(payload.get("phase", ""))
    authorization = payload.get("authorization")
    if phase not in _ALLOWED_INTAKE_PHASES:
        raise IntakeAuthorizationError(
            f"Serialized intake phase '{phase}' is forbidden."
        )
    if payload.get("read_only") is not True:
        raise IntakeAuthorizationError("Serialized intake must be read-only.")
    if not isinstance(authorization, dict):
        raise IntakeAuthorizationError("Serialized intake authorization metadata is required.")
    if authorization.get("granted") is not False:
        raise IntakeAuthorizationError("Serialized intake cannot grant authorization.")
    if authorization.get("authority") != "CARINA_ONLY":
        raise IntakeAuthorizationError("Serialized intake authority must be CARINA_ONLY.")


class SQLiteIntakeLedger:
    """
    Durable, append-only storage for GitHub intake evidence.

    This ledger is deliberately separate from CARINA execution state. Its
    schema can store only INTENT, EVIDENCE, and DECISION records. Re-delivered
    GitHub events are idempotent through the record_id primary key.
    """

    def __init__(self, path: str | Path):
        self.path = Path(path).expanduser()
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._initialize()

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self.path)
        connection.row_factory = sqlite3.Row
        return connection

    def _initialize(self) -> None:
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS github_intake_records (
                    record_id TEXT PRIMARY KEY,
                    phase TEXT NOT NULL
                        CHECK (phase IN ('INTENT', 'EVIDENCE', 'DECISION')),
                    payload_json TEXT NOT NULL,
                    created_at REAL NOT NULL
                )
                """
            )

    def append(self, payload: dict[str, Any]) -> bool:
        _validate_serialized_intake_payload(payload)
        record_id = str(payload.get("record_id", "")).strip()
        if not record_id:
            raise PayloadParseError("Serialized intake record_id is required.")

        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":"))
        with self._connect() as connection:
            cursor = connection.execute(
                """
                INSERT OR IGNORE INTO github_intake_records
                    (record_id, phase, payload_json, created_at)
                VALUES (?, ?, ?, ?)
                """,
                (record_id, payload["phase"], encoded, time.time()),
            )
            return cursor.rowcount == 1

    def read_all(self) -> list[dict[str, Any]]:
        with self._connect() as connection:
            rows = connection.execute(
                """
                SELECT payload_json
                FROM github_intake_records
                ORDER BY created_at ASC, record_id ASC
                """
            ).fetchall()
        return [json.loads(row["payload_json"]) for row in rows]


# ---------------------------------------------------------------------------
# 8. CARINA dispatcher
# ---------------------------------------------------------------------------

# Route table maps (event_type, action) to a destination queue or handler name.
# Use "*" to match any action.
DISPATCH_ROUTES: dict[tuple[str, str], str] = {
    ("pull_request", "opened"): "carina.queue.pr_review",
    ("pull_request", "synchronize"): "carina.queue.pr_review",
    ("push", "*"): "carina.queue.ci_trigger",
    ("repository", "publicized"): "carina.queue.security_audit",
    ("issues", "opened"): "carina.ledger.intake_readonly",
    ("issues", "edited"): "carina.ledger.intake_readonly",
    ("issues", "reopened"): "carina.ledger.intake_readonly",
}


def _resolve_route(event: ParsedEvent) -> str | None:
    """Return the destination queue for this event, or None if no route exists."""
    key = (event.event_type, event.action)
    if key in DISPATCH_ROUTES:
        return DISPATCH_ROUTES[key]
    wildcard_key = (event.event_type, "*")
    if wildcard_key in DISPATCH_ROUTES:
        return DISPATCH_ROUTES[wildcard_key]
    return None


def dispatch(event: ParsedEvent, security: SecurityResult) -> DispatchResult:
    """
    Route the event to the correct CARINA queue based on security decision.

    DENY    — log and reject. Do not route.
    APPROVAL_REQUIRED — log and hold. Route to the approval queue.
    ALLOW   — route to the resolved destination queue.
    """
    dispatch_id = str(uuid4())
    log.info(
        "Dispatching delivery=%s dispatch_id=%s decision=%s",
        event.delivery_id,
        dispatch_id,
        security.decision.value,
    )

    if security.decision == SecurityDecision.DENY:
        log.warning(
            "Event DENIED. delivery=%s rule=%s reason=%s",
            event.delivery_id,
            security.rule_id,
            security.reason,
        )
        return DispatchResult(
            dispatch_id=dispatch_id,
            event_type=event.event_type,
            decision=SecurityDecision.DENY,
            routed_to=None,
            message=f"Denied by {security.rule_id}: {security.reason}",
        )

    if security.decision == SecurityDecision.APPROVAL_REQUIRED:
        approval_queue = "carina.queue.approval_pending"
        log.warning(
            "Event held for approval. delivery=%s rule=%s queue=%s",
            event.delivery_id,
            security.rule_id,
            approval_queue,
        )
        return DispatchResult(
            dispatch_id=dispatch_id,
            event_type=event.event_type,
            decision=SecurityDecision.APPROVAL_REQUIRED,
            routed_to=approval_queue,
            message=f"Held by {security.rule_id}: {security.reason}",
        )

    # SecurityDecision.ALLOW path.
    destination = _resolve_route(event)

    if destination is None:
        log.error(
            "No route found for event_type=%s action=%s delivery=%s. "
            "Add an entry to DISPATCH_ROUTES or handle this event type.",
            event.event_type,
            event.action,
            event.delivery_id,
        )
        raise DispatchError(
            f"No route for event_type={event.event_type} action={event.action}. "
            f"delivery={event.delivery_id}"
        )

    log.info(
        "Event routed. delivery=%s destination=%s",
        event.delivery_id,
        destination,
    )
    return DispatchResult(
        dispatch_id=dispatch_id,
        event_type=event.event_type,
        decision=SecurityDecision.ALLOW,
        routed_to=destination,
        message="Routed successfully.",
    )


# ---------------------------------------------------------------------------
# 8. Gateway entry point
# ---------------------------------------------------------------------------


def handle_github_event(
    event_type: str,
    delivery_id: str,
    raw_signature: str,
    raw_body: bytes,
    intake_sink=None,
    webhook_secret: str | None = None,
) -> DispatchResult:
    """
    Run the full intake pipeline for one GitHub webhook event.

    Steps:
      1. Build InboundRequest.
      2. Verify signature.
      3. Parse payload.
      4. Evaluate security policy.
      5. Dispatch to CARINA.

    Each step raises a typed exception on failure.
    The caller is responsible for catching and converting these to HTTP responses.
    """
    log.info(
        "Intake started — event_type=%s delivery=%s body_bytes=%d",
        event_type,
        delivery_id,
        len(raw_body),
    )

    request = InboundRequest(
        delivery_id=delivery_id,
        event_type=event_type,
        raw_signature=raw_signature,
        raw_body=raw_body,
    )

    verify_signature(request, webhook_secret or WEBHOOK_SECRET)
    event = parse_event(request)
    security = evaluate_security(event)

    if (
        intake_sink is not None
        and security.decision == SecurityDecision.ALLOW
        and event.event_type == "issues"
    ):
        record = map_issue_to_intake_record(event)
        if record is not None:
            append_intake_record(record, intake_sink)

    result = dispatch(event, security)

    log.info(
        "Intake complete — dispatch_id=%s decision=%s routed_to=%s",
        result.dispatch_id,
        result.decision.value,
        result.routed_to,
    )
    return result


# ---------------------------------------------------------------------------
# 9. CLI runner — simulate webhook events for local debugging
# ---------------------------------------------------------------------------

# Each scenario is (label, event_type, actor, action, repo).
DEBUG_SCENARIOS: list[tuple[str, str, str, str, str]] = [
    ("Human opens PR", "pull_request", "alice", "opened", "org/repo"),
    ("Dependabot opens PR", "pull_request", "dependabot[bot]", "opened", "org/repo"),
    ("GitHub Actions push", "push", "github-actions", "pushed", "org/repo"),
    ("Human push", "push", "bob", "pushed", "org/repo"),
    ("Branch delete", "delete", "carol", "*", "org/repo"),
    ("Repo publicized", "repository", "dave", "publicized", "org/repo"),
    ("Unknown event type", "workflow_run", "eve", "completed", "org/repo"),
]


def _build_mock_body(actor: str, action: str, repo: str) -> bytes:
    """Build a minimal GitHub webhook JSON payload."""
    payload = {
        "action": action,
        "sender": {"login": actor},
        "repository": {"full_name": repo},
    }
    return json.dumps(payload).encode("utf-8")


def _sign_body(body: bytes, secret: str) -> str:
    """Return the HMAC-SHA256 signature header value for a body."""
    digest = hmac.new(
        key=secret.encode("utf-8"),
        msg=body,
        digestmod=hashlib.sha256,
    ).hexdigest()
    return f"sha256={digest}"


def run_debug_scenarios() -> None:
    """Run all debug scenarios and print a summary table."""
    separator = "-" * 90
    print(separator)
    print(f"{'Scenario':<32} {'Decision':<20} {'Routed To / Message'}")
    print(separator)

    for label, event_type, actor, action, repo in DEBUG_SCENARIOS:
        body = _build_mock_body(actor=actor, action=action, repo=repo)
        delivery_id = str(uuid4())[:8]

        # Use a bad signature for the mock-failure scenario if the env var is set.
        if MOCK_SIG_FAILURE:
            signature = "sha256=badsignature"
        else:
            signature = _sign_body(body, WEBHOOK_SECRET)

        try:
            result = handle_github_event(
                event_type=event_type,
                delivery_id=delivery_id,
                raw_signature=signature,
                raw_body=body,
            )
            decision = result.decision.value
            detail = result.routed_to or result.message
        except SignatureVerificationError as exc:
            decision = "SIG_FAIL"
            detail = str(exc)
        except PayloadParseError as exc:
            decision = "PARSE_ERR"
            detail = str(exc)
        except SecurityDenyError as exc:
            decision = "SEC_DENY"
            detail = str(exc)
        except DispatchError as exc:
            decision = "DISPATCH_ERR"
            detail = str(exc)
        except Exception as exc:  # noqa: BLE001
            decision = "UNKNOWN_ERR"
            detail = str(exc)

        print(f"{label:<32} {decision:<20} {detail}")

    print(separator)


if __name__ == "__main__":
    print("\n=== CARINA Gateway — Debug Mode ===\n")
    print(f"MOCK_SIG_FAILURE : {MOCK_SIG_FAILURE}")
    print(f"WEBHOOK_SECRET   : {'(set from env)' if os.environ.get('GITHUB_WEBHOOK_SECRET') else '(default dev value)'}")
    print(f"LOG_LEVEL        : {LOG_LEVEL}\n")
    run_debug_scenarios()
