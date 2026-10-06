from __future__ import annotations

from copy import deepcopy
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable
from contextlib import contextmanager
import hashlib
import json
import os
import re

try:
    import fcntl
except ImportError:  # pragma: no cover - v0 strong writer path is POSIX
    fcntl = None

from .errors import IntakeRejected, LedgerError, ReplayBlocked
from .model import (
    ATTEMPT_OUTCOMES,
    AUTHORITY_SOURCES,
    AUTHORITY_STATES,
    CLAIM_FRESHNESS,
    CLAIM_SUPPORT_STATES,
    DECISION_STATES,
    EVENT_SCHEMA,
    FAILURE_STATES,
    KIND_REPORTERS,
    MAX_EVENT_BYTES,
    REDUCER_VERSION,
    REPAIR_SCHEMA,
    SEGMENT_MAX_BYTES,
    SEGMENT_MAX_EVENTS,
    TASK_TRANSITIONS,
    Cursor,
    canonical_json,
    canonical_line,
    new_id,
    now_iso,
    validate_id,
)

_SUBMISSION_RE = re.compile(r"^[A-Za-z0-9._:/+-]{1,160}$")


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _parse_time(value: str) -> datetime:
    if not isinstance(value, str):
        raise ValueError("timestamp must be a string")
    text = value[:-1] + "+00:00" if value.endswith("Z") else value
    dt = datetime.fromisoformat(text)
    if dt.tzinfo is None:
        raise ValueError("timestamp must include an offset")
    return dt.astimezone(timezone.utc)


def _safe_json_loads(text: str) -> Any:
    def pairs(items: list[tuple[str, Any]]) -> dict[str, Any]:
        out: dict[str, Any] = {}
        for key, value in items:
            if key in out:
                raise ValueError(f"duplicate JSON key: {key}")
            out[key] = value
        return out

    def bad_constant(value: str) -> None:
        raise ValueError(f"non-finite JSON number: {value}")

    return json.loads(text, object_pairs_hook=pairs, parse_constant=bad_constant)


class LedgerStore:
    """Canonical append-only store plus deterministic replay entrypoint."""

    def __init__(self, root: str | Path):
        self.root = Path(root).resolve()
        self.config_path = self.root / "ledger.json"
        self.events_dir = self.root / "events"
        self.payloads_dir = self.root / "payloads" / "sha256"
        self.pending_dir = self.root / "pending"
        self.repairs_path = self.root / "repairs.jsonl"
        self.generated_dir = self.root / "generated"
        self.lock_path = self.root / ".writer.lock"

    def initialize(
        self,
        *,
        build_id: str,
        allowed_roots: list[str] | None = None,
        writer_isolation: str = "cooperative_same_uid",
    ) -> dict[str, Any]:
        if self.config_path.exists():
            raise LedgerError(f"ledger already initialized: {self.config_path}")
        if writer_isolation not in {"os_separated", "cooperative_same_uid"}:
            raise LedgerError("writerIsolation must be os_separated or cooperative_same_uid")
        self.events_dir.mkdir(parents=True, exist_ok=True)
        self.payloads_dir.mkdir(parents=True, exist_ok=True)
        self.pending_dir.mkdir(parents=True, exist_ok=True)
        self.generated_dir.mkdir(parents=True, exist_ok=True)
        config = {
            "schemaVersion": "donsquad-ledger/config-v1",
            "buildId": build_id,
            "createdAt": now_iso(),
            "writerIsolation": writer_isolation,
            "allowedRepositoryRoots": allowed_roots or [],
            "eventSchema": EVENT_SCHEMA,
            "repairSchema": REPAIR_SCHEMA,
            "reducerCompatibility": [REDUCER_VERSION],
            "limits": {
                "maxCanonicalEventBytesIncludingLf": MAX_EVENT_BYTES,
                "segmentMaxBytes": SEGMENT_MAX_BYTES,
                "segmentMaxEvents": SEGMENT_MAX_EVENTS,
            },
        }
        self._atomic_write_json(self.config_path, config)
        self.repairs_path.touch(exist_ok=False)
        with self.repairs_path.open("rb") as f:
            os.fsync(f.fileno())
        _fsync_dir(self.root)
        return config

    def require_initialized(self) -> dict[str, Any]:
        if not self.config_path.is_file():
            raise LedgerError(f"not a ledger: {self.root}")
        config = _safe_json_loads(self.config_path.read_text(encoding="utf-8"))
        if config.get("schemaVersion") != "donsquad-ledger/config-v1":
            raise LedgerError("unsupported ledger config schema")
        return config

    def put_payload(self, data: bytes, *, media_type: str = "application/octet-stream") -> dict[str, Any]:
        self.require_initialized()
        digest = _sha256_bytes(data)
        destination = self.payloads_dir / digest[:2] / digest
        destination.parent.mkdir(parents=True, exist_ok=True)
        if destination.exists():
            if destination.read_bytes() != data:
                raise LedgerError("payload digest collision")
        else:
            tmp = destination.with_name(destination.name + ".tmp")
            with tmp.open("xb") as f:
                f.write(data)
                f.flush()
                os.fsync(f.fileno())
            os.replace(tmp, destination)
            _fsync_dir(destination.parent)
        return {
            "mediaType": media_type,
            "size": len(data),
            "digest": {"digestType": "payload_bytes", "algorithm": "sha256", "value": digest},
            "storageClass": "content_addressed_local",
            "locator": f"payloads/sha256/{digest[:2]}/{digest}",
            "captureState": "CAPTURED",
        }

    def purge_payload(
        self,
        digest: str,
        *,
        reason: str,
        secret_class: str | None,
        authorized_by: str,
        submission_id: str,
    ) -> dict[str, Any]:
        self.require_initialized()
        if not re.fullmatch(r"[0-9a-f]{64}", digest):
            raise IntakeRejected("invalid sha256")
        path = self.payloads_dir / digest[:2] / digest
        size = path.stat().st_size if path.exists() else None
        if path.exists():
            path.unlink()
            _fsync_dir(path.parent)
        event = self.submit(
            reporter_type="manager",
            reporter_id="squawk-box-manager",
            submission_id=submission_id,
            body={
                "kind": "payload.purged",
                "kindVersion": 1,
                "subject": {"type": "payload", "id": f"sha256:{digest}"},
                "payload": {
                    "digest": {"digestType": "payload_bytes", "algorithm": "sha256", "value": digest},
                    "size": size,
                    "reason": reason,
                    "secretClass": secret_class,
                    "authorizedBy": authorized_by,
                },
            },
        )
        return event

    def submit(
        self,
        *,
        reporter_type: str,
        reporter_id: str,
        submission_id: str,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        self.require_initialized()
        with self.writer_lock():
            return self._submit_locked(reporter_type=reporter_type, reporter_id=reporter_id, submission_id=submission_id, body=body)

    def _submit_locked(
        self,
        *,
        reporter_type: str,
        reporter_id: str,
        submission_id: str,
        body: dict[str, Any],
    ) -> dict[str, Any]:
        self.recover_pending()
        if not _SUBMISSION_RE.fullmatch(submission_id):
            raise IntakeRejected("invalid submissionId")
        if reporter_type not in {"manager", "human", "donsquad", "agentRun", "tool"}:
            raise IntakeRejected(f"unknown reporter type: {reporter_type}")
        if not isinstance(reporter_id, str) or not reporter_id or len(reporter_id) > 256:
            raise IntakeRejected("invalid channel-bound reporter id")
        normalized = self._validate_submission_body(body)
        kind_key = (normalized["kind"], normalized["kindVersion"])
        allowed = KIND_REPORTERS.get(kind_key)
        if allowed is None:
            raise IntakeRejected(f"unregistered event kind/version: {kind_key[0]}@{kind_key[1]}")
        if reporter_type not in allowed:
            raise IntakeRejected(f"reporter {reporter_type} cannot record {kind_key[0]}@{kind_key[1]}")

        request_digest = _sha256_bytes(canonical_json(normalized).encode("utf-8"))
        prior = self.find_submission(reporter_type, reporter_id, submission_id)
        if prior is not None:
            if prior.get("submission", {}).get("digest") != request_digest:
                raise IntakeRejected("SUBMISSION_ID_REUSE_CONFLICT")
            return prior

        event = {
            "schemaVersion": EVENT_SCHEMA,
            "eventId": new_id("event"),
            "kind": normalized["kind"],
            "kindVersion": normalized["kindVersion"],
            "recordedAt": now_iso(),
            "r