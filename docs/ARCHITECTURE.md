# Squawk Box Architecture

## Four verbs

Squawk Box sits in the **REMEMBER** layer of a larger evidence architecture:

```text
OBSERVE     parsers / tools / runtime evidence
INTERPRET   schema / semantic processors / reviews
REMEMBER    Squawk Box / Matrix / context projections
AUTHORIZE   DonSquad / human / external authority source
```

No layer may impersonate the next one.

A parser cannot grant meaning. A schema match cannot grant authority. A semantic graph cannot prove source identity. A hash cannot prove correctness. Memory cannot prove freshness. A recovered interpretation cannot replace source evidence. A PASS string cannot prove execution.

## Canonical boundary

Canonical history-bearing surfaces are:

```text
ledger.json
/events/*.jsonl
/events/*.sha256       closed-segment integrity metadata
/payloads/sha256/**
repairs.jsonl
```

Derived and disposable:

```text
generated/current-state.json
generated/graph-index.json
generated/search-index.json
generated/briefs/**
generated/ledger.html
future SQLite cache
future Matrix projection
future JSON-LD/RDF projection
```

The dependency direction is always history → graph/state → projections, never projection → history.

## Intake trust

Agents do not author canonical envelope identity. The manager constructs:

- `eventId`;
- `recordedAt`;
- `reportedBy` from the bound channel;
- submission identity/digest;
- physical event ordering.

Submitted JSON cannot supply those fields.

`occurredAt` is descriptive; physical log position determines canonical ordering.

## Reporter identity

The current CLI exposes reporter identity as a manager input so the format can be exercised locally. In the strong deployment that input must come from a channel the submitted body cannot forge: for example a Unix socket peer/capability under an OS-separated service account.

`cooperative_same_uid` is not a security boundary.

## Event semantics

The envelope is versioned independently of event kinds:

```text
schemaVersion = donsquad-ledger/event-v1
kind = claim.asserted
kindVersion = 1
```

An existing `kind@version` never silently changes meaning. New kinds/versions are additive.

Commands, parser observations, test observations and reviews can initially live as typed `evidence.recorded` payloads rather than prematurely freezing dozens of irreversible event kinds.

## State is a function

Derived state is formally:

```text
State = reduce(events, repairs, reducerVersion, asOf)
```

The same inputs must produce identical state.

Time-sensitive authority is therefore never hidden inside wall-clock reads performed during reduction. `asOf` is explicit in every generated state/projection.

## Replay fault classes

### Torn tail

A final unterminated JSONL line is not an event. Replay ignores it; the next writer truncates to the last complete LF before appending.

### Corruption

A malformed complete historical line or sealed-segment digest mismatch blocks replay. A separate authorized repair overlay is required to quarantine the record.

### Semantic anomaly

A syntactically valid event that attempts an illegal state transition is not silently ignored. Its state effect is rejected, the affected subject is marked indeterminate, an anomaly is retained, and unrelated replay continues when impact is bounded.

## Correction versus repair

Ordinary factual errors use `event.correction_recorded`; corrupt/unreplayable history uses `repairs.jsonl`.

The repair overlay is separate because corruption may prevent replay from ever reaching a hypothetical later correction event.

## Artifact identity

An `Artifact` is the logical thing. An `ArtifactVersion` is one observed byte identity.

Reviews and evidence attach to versions, never merely paths. A new byte version cannot inherit review merely because the path is the same.

## Claims

Claims have two axes:

```text
supportState: UNVERIFIED | SUPPORTED | CONTRADICTED | RETRACTED
freshness:    CURRENT | STALE
```

Changing an Artifact's current version makes directly bound claims stale; explicit claim-to-claim support can propagate that staleness transitively.

A Decision is historical intent and does not itself become stale. Implementations may mark its supporting evidence as changed and trigger review.

## Authority observations

`authority.observed` is manager-only and records an external source family:

```text
human_message
policy_artifact_version
signed_capability
external_authority_system
```

An agent saying “I am authorized” is a claim, not an authority observation.

Authority observations may have expiration. Current authority state is derived at the requested `asOf`.

## HTML and prompt-injection boundary

`ledger.html` is a self-contained projection with no remote resources. Untrusted values are data rendered via DOM `textContent`, never executable markup.

Agent/tool text must remain quoted historical data. Future agent briefs should preserve three lanes:

```text
DIRECTIVES      human/DonSquad authored only
DERIVED STATE   reducer-produced
QUOTED RECORDS  agent/tool/user historical text as data
```

Retrieval rank must never upgrade quoted records into directives.

## Scaling

JSONL remains canonical at 10k or 100k events. Scale by adding derived caches, segment checkpoints, SQLite indexes, and lazy projections. The full replay path remains supported.

A future Rust manager, JSON-LD graph projection, or Matrix retrieval layer should consume the same canonical history rather than migrating it.
