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
            "reportedBy": {"type": reporter_type, "id": reporter_id, "boundBy": "channel"},
            "submission": {"id": submission_id, "digest": request_digest},
            "subject": normalized["subject"],
            "context": normalized.get("context", {}),
            "evidenceRefs": normalized.get("evidenceRefs", []),
            "authorityRefs": normalized.get("authorityRefs", []),
            "relations": normalized.get("relations", []),
            "payload": normalized.get("payload", {}),
        }
        if "occurredAt" in normalized:
            event["occurredAt"] = normalized["occurredAt"]
        line = canonical_line(event)
        if len(line) > MAX_EVENT_BYTES:
            raise IntakeRejected("EVENT_TOO_LARGE")
        pending = self.pending_dir / f"{event['eventId']}.json"
        self._atomic_write_bytes(pending, line)
        self._append_event_line(line)
        pending.unlink()
        _fsync_dir(self.pending_dir)
        return event

    def record_repair(
        self,
        *,
        action: str,
        cursor: Cursor | None,
        event_id: str | None,
        reason: str,
        authorized_by: str,
        target_repair_id: str | None = None,
    ) -> dict[str, Any]:
        self.require_initialized()
        with self.writer_lock():
            return self._record_repair_locked(
                action=action, cursor=cursor, event_id=event_id, reason=reason,
                authorized_by=authorized_by, target_repair_id=target_repair_id,
            )

    def _record_repair_locked(
        self,
        *,
        action: str,
        cursor: Cursor | None,
        event_id: str | None,
        reason: str,
        authorized_by: str,
        target_repair_id: str | None = None,
    ) -> dict[str, Any]:
        if action not in {"QUARANTINE", "REVOKE_QUARANTINE"}:
            raise LedgerError("unsupported repair action")
        if action == "QUARANTINE" and cursor is None and event_id is None:
            raise LedgerError("quarantine requires cursor or eventId")
        if action == "REVOKE_QUARANTINE" and not target_repair_id:
            raise LedgerError("revoke requires targetRepairId")
        repair = {
            "schemaVersion": REPAIR_SCHEMA,
            "repairId": new_id("repair"),
            "action": action,
            "reason": reason,
            "authorizedBy": {"type": "human", "ref": authorized_by},
            "authorizedAt": now_iso(),
        }
        if cursor is not None:
            repair["cursor"] = cursor.to_dict()
        if event_id is not None:
            repair["eventId"] = event_id
        if target_repair_id:
            repair["targetRepairId"] = target_repair_id
        line = canonical_line(repair)
        with self.repairs_path.open("ab") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        _fsync_dir(self.root)
        return repair

    def replay(self, *, as_of: str | None = None) -> dict[str, Any]:
        self.require_initialized()
        self.recover_pending()
        reducer = Reducer(as_of=as_of or now_iso())
        events, cursors, warnings = self._read_events_for_replay()
        reducer.warnings.extend(warnings)
        repairs = self._load_repairs()
        effective_quarantines = _effective_quarantines(repairs)

        # Corrections are valid events, not repair records. Precompute their final replacement.
        correction_map: dict[str, dict[str, Any]] = {}
        for event in events:
            if event is None or event.get("kind") != "event.correction_recorded":
                continue
            payload = event.get("payload", {})
            target = payload.get("targetEventId")
            replacement = payload.get("replacement")
            if isinstance(target, str) and isinstance(replacement, dict):
                correction_map[target] = replacement

        seen_ids: set[str] = set()
        last_cursor: Cursor | None = None
        for event, cursor in zip(events, cursors):
            last_cursor = cursor
            q = _is_quarantined(event, cursor, effective_quarantines)
            if q:
                reducer.anomalies.append({"type": "QUARANTINED", "cursor": cursor.to_dict(), "eventId": event.get("eventId") if event else None})
                continue
            if event is None:
                raise ReplayBlocked(f"corrupt complete event at {cursor.label()} without authorized quarantine")
            event_id = event.get("eventId")
            if not isinstance(event_id, str):
                raise ReplayBlocked(f"event without eventId at {cursor.label()}")
            if event_id in seen_ids:
                raise ReplayBlocked(f"duplicate eventId {event_id} at {cursor.label()}")
            seen_ids.add(event_id)
            if event.get("schemaVersion") != EVENT_SCHEMA:
                raise ReplayBlocked(f"unsupported event schema at {cursor.label()}")
            if (event.get("kind"), event.get("kindVersion")) not in KIND_REPORTERS:
                reducer.semantic_anomaly(event, cursor, "unknown event kind/version")
                continue
            effective = event
            if event_id in correction_map and event.get("kind") != "event.correction_recorded":
                effective = _apply_correction(event, correction_map[event_id])
            reducer.apply(effective, cursor)

        state = reducer.finalize(last_cursor)
        state["repairs"] = {"count": len(repairs), "activeQuarantines": len(effective_quarantines)}
        return state

    def find_submission(self, reporter_type: str, reporter_id: str, submission_id: str) -> dict[str, Any] | None:
        for event, _cursor in self.iter_parseable_events(include_corrupt=False):
            if event.get("reportedBy", {}).get("type") != reporter_type:
                continue
            if event.get("reportedBy", {}).get("id") != reporter_id:
                continue
            if event.get("submission", {}).get("id") == submission_id:
                return event
        return None

    def recover_pending(self) -> list[str]:
        if not self.pending_dir.exists():
            return []
        recovered: list[str] = []
        known = {event.get("eventId") for event, _ in self.iter_parseable_events(include_corrupt=False)}
        for pending in sorted(self.pending_dir.glob("evt_*.json")):
            data = pending.read_bytes()
            try:
                event = _safe_json_loads(data.decode("utf-8"))
            except Exception as exc:
                raise ReplayBlocked(f"malformed pending event {pending}: {exc}") from exc
            event_id = event.get("eventId")
            if event_id not in known:
                if not data.endswith(b"\n"):
                    data += b"\n"
                self._append_event_line(data)
                known.add(event_id)
                recovered.append(event_id)
            pending.unlink()
            _fsync_dir(self.pending_dir)
        return recovered

    def iter_parseable_events(self, *, include_corrupt: bool = False) -> Iterable[tuple[dict[str, Any], Cursor]]:
        for path in self._segment_paths():
            segment = int(path.stem)
            data = path.read_bytes()
            lines = data.splitlines(keepends=True)
            for idx, raw in enumerate(lines, 1):
                if not raw.endswith(b"\n"):
                    continue
                try:
                    event = _safe_json_loads(raw.decode("utf-8"))
                except Exception:
                    if include_corrupt:
                        continue
                    continue
                if isinstance(event, dict):
                    yield event, Cursor(segment, idx)

    @contextmanager
    def writer_lock(self):
        """Serialize cooperative local writers. Not a same-UID security boundary."""
        if fcntl is None:
            raise LedgerError("v0 writer lock requires POSIX fcntl")
        self.root.mkdir(parents=True, exist_ok=True)
        with self.lock_path.open("a+b") as lock:
            fcntl.flock(lock.fileno(), fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(lock.fileno(), fcntl.LOCK_UN)

    def _validate_submission_body(self, body: dict[str, Any]) -> dict[str, Any]:
        if not isinstance(body, dict):
            raise IntakeRejected("submission body must be an object")
        forbidden = {"eventId", "recordedAt", "reportedBy", "submission", "schemaVersion"}
        if forbidden & set(body):
            raise IntakeRejected(f"manager-owned fields supplied: {sorted(forbidden & set(body))}")
        allowed = {"kind", "kindVersion", "occurredAt", "subject", "context", "evidenceRefs", "authorityRefs", "relations", "payload"}
        unknown = set(body) - allowed
        if unknown:
            raise IntakeRejected(f"unknown submission fields: {sorted(unknown)}")
        kind = body.get("kind")
        version = body.get("kindVersion")
        if not isinstance(kind, str)