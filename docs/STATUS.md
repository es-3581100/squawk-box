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
- 16 unit tests passing under Python stdlib only;
- direct example execution from an uninstalled fresh source checkout.

Remote CI exercises Python 3.11, 3.12, 3.13, and 3.14. For every version it runs the Retry2→Retry3 demo before installation, installs the package, runs the adversarial unit suite, reruns the demo, runs `compileall`, and strictly parses the JSON schema files.

Current trust deployment in local CLI use is normally `cooperative_same_uid`. Strong OS-separated manager/socket identity is the next security-hardening slice.

Deliberately deferred projections: Matrix, JSON-LD/RDF, SQLite.
