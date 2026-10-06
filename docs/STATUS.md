# Build Status

## 0.2.0 — type-aware narrative projections

Canonical history and `event-v1` are unchanged.

Implemented on top of the v0.1 continuity core:

- type-aware Task, Attempt, Failure, Artifact, ArtifactVersion, Claim, Decision, Authority, AgentRun, and Checkpoint rendering;
- first-class Attempts navigation;
- derived `build-stories.json` and `briefs/build-stories.md`;
- Build Story HTML view with per-fact provenance labels;
- timeline change summaries for task status, attempts, failures, and artifact observations;
- semantic `<dl><dt><dd>` field boundaries rather than one generic entity field bucket;
- irrelevant/absent fields are omitted from entity cards;
- artifact-version pages expose exact size, SHA-256, persistence, path, and producing attempt;
- failure pages expose domain, symptom, root cause, survived/invalidated refs, task/attempt bindings, and resolution;
- attempt pages expose outcome, retry lineage, changed dimensions, semantic/materialization results, and related failures/artifacts;
- regression fixture for the real Retry2→Retry3 transport-only schema-materialization story.

The test suite now includes the narrative/projection regression in addition to the v0.1 adversarial ledger tests.

Remote CI continues to exercise Python 3.11, 3.12, 3.13, and 3.14, including the fresh-checkout demo before installation.

Current trust deployment in local CLI use is normally `cooperative_same_uid`. Strong OS-separated manager/socket identity remains the next security-hardening slice.

Still deliberately deferred: Matrix, JSON-LD/RDF, SQLite, semantic search, and Rust runtime replacement.
