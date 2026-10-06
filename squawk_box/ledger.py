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
        if not isinstance(kind, str) or not kind:
            raise IntakeRejected("kind is required")
        if type(version) is not int or version < 1:
            raise IntakeRejected("kindVersion must be a positive integer")
        subject = body.get("subject")
        if not isinstance(subject, dict) or set(subject) != {"type", "id"}:
            raise IntakeRejected("subject must contain exactly type and id")
        if not isinstance(subject["type"], str) or not isinstance(subject["id"], str) or not subject["id"]:
            raise IntakeRejected("invalid subject")
        if "occurredAt" in body:
            try:
                _parse_time(body["occurredAt"])
            except Exception as exc:
                raise IntakeRejected(f"invalid occurredAt: {exc}") from exc
        for name in ("evidenceRefs", "authorityRefs"):
            value = body.get(name, [])
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise IntakeRejected(f"{name} must be a string array")
            if len(value) != len(set(value)):
                raise IntakeRejected(f"{name} must not contain duplicates")
        relations = body.get("relations", [])
        if not isinstance(relations, list):
            raise IntakeRejected("relations must be an array")
        for rel in relations:
            if not isinstance(rel, dict) or set(rel) != {"rel", "target"}:
                raise IntakeRejected("relation must have rel and target")
            if not isinstance(rel["rel"], str):
                raise IntakeRejected("relation rel must be string")
            target = rel["target"]
            if not isinstance(target, dict) or set(target) != {"type", "id"}:
                raise IntakeRejected("relation target must have type and id")
        if not isinstance(body.get("context", {}), dict) or not isinstance(body.get("payload", {}), dict):
            raise IntakeRejected("context and payload must be objects")
        return deepcopy(body)

    def _segment_paths(self) -> list[Path]:
        if not self.events_dir.exists():
            return []
        return sorted(self.events_dir.glob("[0-9][0-9][0-9][0-9][0-9][0-9].jsonl"))

    def _active_segment(self) -> Path:
        paths = self._segment_paths()
        if not paths:
            path = self.events_dir / "000001.jsonl"
            path.touch()
            _fsync_dir(self.events_dir)
            return path
        return paths[-1]

    def _append_event_line(self, line: bytes) -> Cursor:
        if not line.endswith(b"\n"):
            raise LedgerError("canonical event append must end with LF")
        if len(line) > MAX_EVENT_BYTES:
            raise LedgerError("EVENT_TOO_LARGE")
        path = self._active_segment()
        self._truncate_torn_tail(path)
        event_count = sum(1 for raw in path.read_bytes().splitlines(keepends=True) if raw.endswith(b"\n"))
        size = path.stat().st_size
        if size + len(line) > SEGMENT_MAX_BYTES or event_count >= SEGMENT_MAX_EVENTS:
            self._seal_segment(path)
            next_num = int(path.stem) + 1
            path = self.events_dir / f"{next_num:06d}.jsonl"
            path.touch(exist_ok=False)
            _fsync_dir(self.events_dir)
            event_count = 0
        with path.open("ab") as f:
            f.write(line)
            f.flush()
            os.fsync(f.fileno())
        _fsync_dir(self.events_dir)
        return Cursor(int(path.stem), event_count + 1)

    def _truncate_torn_tail(self, path: Path) -> None:
        data = path.read_bytes()
        if not data or data.endswith(b"\n"):
            return
        pos = data.rfind(b"\n")
        keep = 0 if pos < 0 else pos + 1
        with path.open("r+b") as f:
            f.truncate(keep)
            f.flush()
            os.fsync(f.fileno())
        _fsync_dir(self.events_dir)

    def _seal_segment(self, path: Path) -> None:
        digest = _sha256_bytes(path.read_bytes())
        seal = path.with_suffix(".sha256")
        self._atomic_write_bytes(seal, (digest + "\n").encode("ascii"))

    def _verify_closed_segments(self) -> None:
        paths = self._segment_paths()
        for path in paths[:-1]:
            seal = path.with_suffix(".sha256")
            if not seal.is_file():
                raise ReplayBlocked(f"closed segment missing seal: {path.name}")
            expected = seal.read_text(encoding="ascii").strip()
            actual = _sha256_bytes(path.read_bytes())
            if expected != actual:
                raise ReplayBlocked(f"closed segment digest mismatch: {path.name}")

    def _read_events_for_replay(self) -> tuple[list[dict[str, Any] | None], list[Cursor], list[dict[str, Any]]]:
        self._verify_closed_segments()
        events: list[dict[str, Any] | None] = []
        cursors: list[Cursor] = []
        warnings: list[dict[str, Any]] = []
        paths = self._segment_paths()
        for p_index, path in enumerate(paths):
            segment = int(path.stem)
            raw_data = path.read_bytes()
            lines = raw_data.splitlines(keepends=True)
            for idx, raw in enumerate(lines, 1):
                cursor = Cursor(segment, idx)
                if not raw.endswith(b"\n"):
                    if p_index == len(paths) - 1 and idx == len(lines):
                        warnings.append({"type": "TORN_TAIL_IGNORED", "cursor": cursor.to_dict()})
                        continue
                    raise ReplayBlocked(f"unterminated record before active tail at {cursor.label()}")
                try:
                    decoded = raw.decode("utf-8")
                    event = _safe_json_loads(decoded)
                    if not isinstance(event, dict):
                        raise ValueError("event must be object")
                except Exception:
                    event = None
                events.append(event)
                cursors.append(cursor)
        return events, cursors, warnings

    def _load_repairs(self) -> list[dict[str, Any]]:
        repairs: list[dict[str, Any]] = []
        if not self.repairs_path.exists():
            return repairs
        for idx, raw in enumerate(self.repairs_path.read_bytes().splitlines(keepends=True), 1):
            if not raw.endswith(b"\n"):
                raise ReplayBlocked(f"torn repair overlay at line {idx}")
            try:
                record = _safe_json_loads(raw.decode("utf-8"))
            except Exception as exc:
                raise ReplayBlocked(f"malformed repair overlay at line {idx}: {exc}") from exc
            if not isinstance(record, dict) or record.get("schemaVersion") != REPAIR_SCHEMA:
                raise ReplayBlocked(f"unauthorized/invalid repair overlay record at line {idx}")
            if record.get("authorizedBy", {}).get("type") != "human" or not record.get("authorizedBy", {}).get("ref"):
                raise ReplayBlocked(f"repair overlay lacks human authorization at line {idx}")
            repairs.append(record)
        return repairs

    def _atomic_write_json(self, path: Path, value: Any) -> None:
        self._atomic_write_bytes(path, (canonical_json(value) + "\n").encode("utf-8"))

    def _atomic_write_bytes(self, path: Path, data: bytes) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_name(path.name + ".tmp")
        with tmp.open("xb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        _fsync_dir(path.parent)


class Reducer:
    def __init__(self, *, as_of: str):
        self.as_of = as_of
        self.as_of_dt = _parse_time(as_of)
        self.tasks: dict[str, Any] = {}
        self.attempts: dict[str, Any] = {}
        self.agent_runs: dict[str, Any] = {}
        self.contexts: dict[str, Any] = {}
        self.handoffs: list[Any] = []
        self.decisions: dict[str, Any] = {}
        self.claims: dict[str, Any] = {}
        self.evidence: dict[str, Any] = {}
        self.artifacts: dict[str, Any] = {}
        self.artifact_versions: dict[str, Any] = {}
        self.artifact_presence: dict[str, Any] = {}
        self.failures: dict[str, Any] = {}
        self.authorities: dict[str, Any] = {}
        self.checkpoints: dict[str, Any] = {}
        self.payload_purges: list[Any] = []
        self.completion_proposals: list[Any] = []
        self.corrections: list[Any] = []
        self.edges: list[dict[str, Any]] = []
        self.incoming: dict[str, list[dict[str, Any]]] = {}
        self.outgoing: dict[str, list[dict[str, Any]]] = {}
        self.anomalies: list[dict[str, Any]] = []
        self.warnings: list[dict[str, Any]] = []
        self.indeterminate_subjects: dict[str, str] = {}

    def semantic_anomaly(self, event: dict[str, Any], cursor: Cursor, reason: str) -> None:
        subject = event.get("subject", {})
        subject_id = subject.get("id") if isinstance(subject, dict) else None
        self.anomalies.append({
            "type": "SEMANTIC_ANOMALY",
            "cu