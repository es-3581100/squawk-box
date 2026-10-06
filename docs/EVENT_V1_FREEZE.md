# Event v1 Freeze Surface

Status: **v0.1 implementation candidate**.

This document identifies the irreversible history boundary. HTML layout, search implementation, Matrix schema, JSON-LD vocabulary, and future event kinds are intentionally not frozen here.

## Frozen envelope semantics

A canonical event contains manager-owned envelope identity and submitted state content. Manager-owned fields are not legal submission fields.

Required manager-owned semantics:

```text
schemaVersion = donsquad-ledger/event-v1
eventId        opaque evt_ ID assigned by manager
recordedAt     manager time
reportedBy     identity bound by intake channel
submission     submission ID + digest
```

Submitted content:

```text
kind
kindVersion
subject
context
evidenceRefs
authorityRefs
relations
payload
optional occurredAt
```

Physical segment/line order is canonical ordering. No reporter-supplied sequence number exists.

## Idempotency

Dedupe key:

```text
(reportedBy.type, reportedBy.id, submission.id)
```

A retry with the same normalized body returns the original event. A different body under the same key is rejected as `SUBMISSION_ID_REUSE_CONFLICT`.

## Initial reporter capability matrix

The executable registry is mirrored in `schemas/event-kinds-v1.json` and `squawk_box.model.KIND_REPORTERS`.

The key safety distinctions are:

- agents may report/propose;
- manager may record/observe;
- reducer may derive;
- human/DonSquad may resolve project decisions;
- only manager records external authority observations;
- ledger authority observations are evidence, not permission tokens.

## Writer durability

The manager uses:

1. canonicalize and validate;
2. write event to `pending/` and fsync;
3. append exact JSON line to active segment and fsync;
4. fsync event directory;
5. remove pending copy and fsync pending directory;
6. acknowledge.

On restart, pending records are deduplicated by event ID and appended when absent.

The active segment is cooperative-locked. This prevents accidental local concurrent writers; it is not security against a same-UID actor.

## Event size and segmentation

Canonical event lines are bounded to 64 KiB UTF-8 including LF. Large free-form material belongs in detached payloads.

Default rollover is a transport/storage choice, not event meaning:

- 64 MiB, or
- 10,000 events,

whichever comes first.

Closed segments are SHA-256 sealed. The active segment is not sealed until rollover.

## Replay anomalies

- torn active tail → ignored as non-event; next writer truncates it;
- malformed complete event → `REPLAY_BLOCKED` unless repair overlay quarantines it;
- closed segment digest mismatch → `REPLAY_BLOCKED`;
- duplicate event ID → `REPLAY_BLOCKED`;
- semantic transition anomaly → effect rejected, affected subject indeterminate, unrelated replay continues when bounded;
- malformed/unauthorized repair overlay → `REPLAY_BLOCKED`.

## Repair overlay

`repairs.jsonl` is append-only exceptional replay control. It may quarantine by event ID or physical cursor and may later revoke a prior quarantine.

A repair must contain an explicit human authorization reference. The v0 CLI records that reference but cannot cryptographically prove the human source; strong deployment must bind it through an authenticated channel.

Ordinary valid-but-wrong history does not use repair. It uses `event.correction_recorded`.

## Reducer determinism

Every state projection records:

```text
reducerVersion
asOf
sourceCursor
```

Same events + same repairs + same reducer version + same `asOf` must produce identical derived state.

## Payload policy

Captured payloads are addressed by SHA-256 and stored once. Event history references them.

The current implementation supports capture and purge. Secret-class detection, digest withholding for low-entropy secrets, and policy-driven automatic redaction are intentionally future work; they do not alter the event envelope.

After a purge, projections must be regenerated so captured secret text cannot survive in generated caches.

## Typed identity

Entity IDs carry prefixes (`tsk_`, `att_`, `dec_`, `clm_`, `art_`, `av_`, etc.). Digests are typed separately (`artifact_bytes`, `payload_bytes`, `source_bytes`, later `structural`, `semantic_graph`). A digest is not an entity ID.

## Supplied context wording

The entity is `SuppliedContextSet`, not a claim about everything an agent knew. It records material supplied by the manager. Tool/file-read telemetry, when available, belongs in separate evidence.
