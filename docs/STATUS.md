# Build Status

## 0.2.1 — extractor-readable field boundaries

Canonical history and `event-v1` remain unchanged.

This patch closes the generic HTML→text readability gap found by feeding Squawk Box views through IngestWowww:

- rendered field labels now carry a literal `: ` separator, so concatenating extractors see `Status: COMPLETE` instead of `StatusCOMPLETE`;
- provenance labels carry a literal leading separator, so extracted text reads `COMPLETE [derived]`;
- the projection regression locks those literal field/provenance separators;
- README local-launch examples now use a real `file://` URI and detached `xdg-open`, avoiding the earlier pseudo-path fragment mistake;
- package version is 0.2.1.

The v0.2 type-aware projections, Build Story, first-class Attempts, timeline summaries, and exact artifact identity surfaces are otherwise unchanged.

Remote CI continues to exercise Python 3.11, 3.12, 3.13, and 3.14, including fresh-checkout demo execution before installation.

Current trust deployment remains `cooperative_same_uid`. Strong OS-separated manager/socket identity is still deferred.

Next product slice: ingest one real DonSquad lifecycle automatically without giving the worker direct canonical-ledger ownership.
