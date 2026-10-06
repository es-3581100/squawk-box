# Squawk Box

**Squawk Box** is a local-first, append-only build continuity ledger for long multi-agent engineering work.

It is designed around one rule:

> **Never overwrite history to make the present easier to understand. Derive the present from history instead.**

The canonical store is JSONL history plus detached content-addressed payloads and an exceptional repair overlay. Current state, graph indexes, briefs, search indexes, and the hyperlinked HTML view are disposable projections.

Squawk Box does **not** turn `PASS`, `APPROVED`, a hash match, a remembered claim, or a ledger status into authority. It records what was observed and derives navigable state; authority remains external.

## Current v0.2.1 slice

Implemented now:

- append-only `event-v1` JSONL history;
- explicit `kind@version` registry and reporter capability matrix;
- channel-bound reporter identity (manager constructs `reportedBy`);
- durable submission IDs with retry dedupe and reuse-conflict rejection;
- 64 KiB canonical event-line bound;
- detached SHA-256 payload store;
- torn-tail recovery and pending-event recovery;
- sealed closed JSONL segments;
- separate human-authorized `repairs.jsonl` quarantine overlay for unreplayable history;
- correction events for valid-but-wrong historical facts;
- deterministic reducer scoped by `reducerVersion + asOf + source cursor`;
- semantic-anomaly containment (`INDETERMINATE` subject rather than silent skip);
- typed tasks, attempts, agent runs, supplied context, decisions, claims, evidence bundles, artifacts/versions, failures, authority observations, checkpoints;
- artifact-version changes mark directly bound claims stale;
- authority observations can expire as a function of `asOf`;
- canonical directed relations with generated incoming/outgoing indexes;
- compact Markdown build briefs;
- self-contained offline `ledger.html` with stable entity anchors, search, timeline, and backreferences;
- type-aware task/attempt/failure/artifact projections that omit irrelevant fields;
- first-class Attempts navigation and entity pages;
- derived Build Story projections in JSON, Markdown, and HTML with provenance labels;
- semantic `<dl><dt><dd>` field rendering with literal `Label: value` text boundaries for generic HTML→text extraction;
- no remote CSS, JavaScript, fonts, or data dependencies;
- BSD-2-Clause license.

Not yet implemented: Unix-socket service identity, OS-separated service packaging, Matrix projection, JSON-LD/RDF projection, SQLite acceleration, semantic search, or a Rust implementation. Those are downstream surfaces and do not require changing `event-v1`.

## Trust modes

Every ledger declares one of:

- `os_separated` — intended strong deployment: agent processes cannot directly write the canonical ledger directory and submit through a separately privileged manager channel.
- `cooperative_same_uid` — development mode. The writer lock prevents accidental concurrent appends, **but a same-UID actor can still rewrite files directly**. Do not treat this mode as tamper protection.

The current CLI can exercise both formats, but actual process/UID separation is a deployment responsibility not fabricated by a config string.

## Quick start

No third-party Python packages are required. Python 3.11+ is enough.

```bash
python -m squawk_box init .ledger --build-id my-build

TASK=$(python -m squawk_box new-id task)
cat > /tmp/task.json <<JSON
{
  "kind": "task.created",
  "kindVersion": 1,
  "subject": {"type": "task", "id": "$TASK"},
  "payload": {
    "externalKey": "chunk-01",
    "title": "First build task",
    "objective": "Preserve build continuity"
  }
}
JSON

python -m squawk_box submit .ledger \
  --reporter-type human \
  --reporter-id user \
  --submission-id create-chunk-01 \
  --body /tmp/task.json

python -m squawk_box render .ledger --as-of 2026-10-06T12:00:00Z
```

Open:

```text
.ledger/generated/ledger.html
```

For local browser fragments, use a real `file://` URI so `#...` is treated as a URL fragment rather than part of the filename:

```bash
LEDGER="$(realpath .ledger/generated/ledger.html)"
nohup xdg-open "file://$LEDGER#Build%20Story" >/dev/null 2>&1 &
```

Other useful fragments include `#Attempts`, `#Failures`, `#Artifacts`, and `#Timeline`.

The URL fragment for an entity is stable:

```text
ledger.html#e-tsk_<opaque-id>
```

## Canonical layout

```text
.ledger/
├── ledger.json
├── events/
│   ├── 000001.jsonl
│   ├── 000001.sha256      # when segment is closed
│   └── ...
├── payloads/
│   └── sha256/aa/<digest>
├── pending/               # crash-recovery staging, normally empty
├── repairs.jsonl          # exceptional replay-control overlay
└── generated/             # disposable/rebuildable
    ├── current-state.json
    ├── graph-index.json
    ├── search-index.json
    ├── build-stories.json
    ├── briefs/
    └── ledger.html
```

`generated/` is never canonical. Delete it freely and run `render` again.

## Submission identity and exactly-once recording

A submitter chooses a `submissionId` and may retry until it receives an acknowledgement. The canonical dedupe key is:

```text
(bound reporter identity, submissionId)
```

The manager stores a digest of the normalized submitted body.

- same reporter + same submission ID + same body → returns the already-recorded event;
- same reporter + same submission ID + different body → `SUBMISSION_ID_REUSE_CONFLICT`;
- acknowledgement occurs only after the event line has been fsynced.

This yields at-least-once submission with exactly-once canonical recording under the manager model.

## Large content

Do not stuff giant commands, transcripts, prompts, stdout, schemas, or artifact bodies into event JSON. Store them once:

```bash
python -m squawk_box payload-put .ledger huge-command.txt --media-type text/plain
```

Then reference the returned payload object from an evidence event.

## Repair versus correction

These are intentionally different.

**Correction event** — a valid historical event was factually wrong. The original remains navigable, but a later manager correction supplies its current state effect.

**Repair overlay** — replay cannot safely reach later history because a canonical record itself is malformed/corrupt. A human-authorized quarantine in `repairs.jsonl` lets replay explicitly skip that record. The original bytes remain visible.

```bash
python -m squawk_box repair-quarantine .ledger \
  --segment 1 --line 42 \
  --reason 'historical record corrupted' \
  --authorized-by user
```

Repairs are exceptional. They are not a convenient way to rewrite normal build history.

## Security boundary

The ledger can record that:

- an event was durably appended;
- one recorded event preceded another;
- a manager observed exact artifact bytes/digest;
- an agent reported a claim;
- a review referenced an artifact version;
- an external authority source was observed in some state.

It cannot prove from status strings alone that:

- a claim is true;
- a test actually ran;
- a printed `PASS` is legitimate;
- a hash means approval;
- an accepted design grants runtime authority;
- a stale authority observation is still current;
- memory is fresh.

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) and [docs/EVENT_V1_FREEZE.md](docs/EVENT_V1_FREEZE.md).

## Tests

```bash
python -m unittest discover -s tests -v
```

The v0.2.1 suite covers intake ownership, idempotency conflict, capability rejection, retry/history semantics, staleness, time-dependent authority, corruption/repair, torn tails, payload purge, HTML data escaping, deterministic replay, the Retry2→Retry3 type-aware Build Story projection, and literal extractor-safe field separators.

## License

BSD-2-Clause.
