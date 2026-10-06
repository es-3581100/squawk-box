from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any
import json
import re
import uuid

EVENT_SCHEMA = "donsquad-ledger/event-v1"
REPAIR_SCHEMA = "donsquad-ledger/repair-v1"
REDUCER_VERSION = "squawk-box/reducer-v1"
MAX_EVENT_BYTES = 64 * 1024
SEGMENT_MAX_BYTES = 64 * 1024 * 1024
SEGMENT_MAX_EVENTS = 10_000

ID_PREFIXES = {
    "event": "evt_",
    "task": "tsk_",
    "attempt": "att_",
    "agentRun": "run_",
    "session": "ses_",
    "context": "ctx_",
    "decision": "dec_",
    "claim": "clm_",
    "failure": "fail_",
    "artifact": "art_",
    "artifactVersion": "av_",
    "evidenceBundle": "evb_",
    "authorityObservation": "auth_",
    "checkpoint": "cp_",
    "repair": "rpr_",
}

REPORTER_TYPES = {"manager", "human", "donsquad", "agentRun", "tool"}

# Existing kind@version semantics are permanent. New versions/kinds may be added.
KIND_REPORTERS: dict[tuple[str, int], set[str]] = {
    ("submission.rejected", 1): {"manager"},
    ("task.created", 1): {"human", "donsquad"},
    ("task.completion_proposed", 1): {"agentRun"},
    ("task.status_changed", 1): {"human", "donsquad"},
    ("attempt.started", 1): {"manager"},
    ("attempt.completed", 1): {"manager", "agentRun"},
    ("agent_run.started", 1): {"manager"},
    ("agent_run.completed", 1): {"manager"},
    ("context.supplied", 1): {"manager"},
    ("handoff.recorded", 1): {"human", "donsquad"},
    ("decision.proposed", 1): {"agentRun", "human", "donsquad"},
    ("decision.resolved", 1): {"human", "donsquad"},
    ("claim.asserted", 1): {"agentRun", "human", "donsquad", "manager", "tool"},
    ("claim.assessed", 1): {"manager"},
    ("claim.retracted", 1): {"agentRun", "human", "donsquad"},
    ("evidence.recorded", 1): REPORTER_TYPES,
    ("artifact.registered", 1): {"manager"},
    ("artifact.version_observed", 1): {"manager"},
    ("artifact.presence_observed", 1): {"manager"},
    ("failure.recorded", 1): REPORTER_TYPES,
    ("failure.status_changed", 1): {"manager", "human", "donsquad"},
    ("authority.observed", 1): {"manager"},
    ("checkpoint.recorded", 1): {"manager"},
    ("payload.purged", 1): {"manager"},
    ("event.correction_recorded", 1): {"manager"},
}

TASK_TRANSITIONS = {
    "PLANNED": {"READY", "CANCELLED", "SUPERSEDED"},
    "READY": {"ACTIVE", "BLOCKED", "CANCELLED", "SUPERSEDED"},
    "ACTIVE": {"BLOCKED", "NEEDS_RETRY", "COMPLETE", "FAILED", "CANCELLED", "SUPERSEDED"},
    "BLOCKED": {"ACTIVE", "FAILED", "CANCELLED", "SUPERSEDED"},
    "NEEDS_RETRY": {"ACTIVE", "FAILED", "CANCELLED", "SUPERSEDED"},
    "COMPLETE": set(),
    "FAILED": set(),
    "CANCELLED": set(),
    "SUPERSEDED": set(),
}
ATTEMPT_OUTCOMES = {"SUCCEEDED", "FAILED_RETRYABLE", "FAILED_TERMINAL", "BLOCKED", "INTERRUPTED", "ABANDONED"}
DECISION_STATES = {"PROPOSED", "ACCEPTED", "REJECTED", "DEFERRED", "EXPERIMENTAL", "SUPERSEDED"}
CLAIM_SUPPORT_STATES = {"UNVERIFIED", "SUPPORTED", "CONTRADICTED", "RETRACTED"}
CLAIM_FRESHNESS = {"CURRENT", "STALE"}
FAILURE_STATES = {"OPEN", "UNDER_INVESTIGATION", "RESOLVED", "ACCEPTED_RISK", "WONT_FIX"}
AUTHORITY_STATES = {"AUTHORIZED", "NOT_AUTHORIZED", "PENDING", "EXPIRED", "UNKNOWN", "OUT_OF_SCOPE"}
AUTHORITY_SOURCES = {"human_message", "policy_artifact_version", "signed_capability", "external_authority_system"}
CAPTURE_STATES = {"CAPTURED", "REFERENCED_EXTERNAL", "OMITTED_SENSITIVE", "OMITTED_TOO_LARGE", "UNAVAILABLE", "PURGED"}

_ID_RE = re.compile(r"^[a-z][a-zA-Z0-9]*_[0-9a-f]{32}$")


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z")


def new_id(kind: str) -> str:
    try:
        prefix = ID_PREFIXES[kind]
    except KeyError as exc:
        raise ValueError(f"unknown id kind: {kind}") from exc
    return prefix + uuid.uuid4().hex


def validate_id(value: str, kind: str | None = None) -> bool:
    if not isinstance(value, str) or not _ID_RE.fullmatch(value):
        return False
    if kind is None:
        return True
    return value.startswith(ID_PREFIXES[kind])


def canonical_json(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)


def canonical_line(value: Any) -> bytes:
    return (canonical_json(value) + "\n").encode("utf-8")


@dataclass(frozen=True)
class Cursor:
    segment: int
    line: int

    def to_dict(self) -> dict[str, int]:
        return {"segment": self.segment, "line": self.line}

    def label(self) -> str:
        return f"{self.segment:06d}:{self.line}"
