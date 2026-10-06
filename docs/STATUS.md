# Build Status

## 0.1.0 — first executable continuity slice

Implemented and locally verified:

- Phase-0 irreversible format surfaces;
- Phase-1 JSONL writer, pending recovery and reducer;
- exceptional repair overlay;
- detached payload storage/purge history;
- basic graph/backreferences and staleness;
- compact Markdown projections;
- self-contained offline HTML map;
- 16 unit tests passing under Python stdlib only.

Current trust deployment in local CLI use is normally `cooperative_same_uid`. Strong OS-separated manager/socket identity is the next security-hardening slice.

Deliberately deferred projections: Matrix, JSON-LD/RDF, SQLite.
