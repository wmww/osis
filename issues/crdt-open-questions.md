# CRDT open questions
> Summary: Remaining details in the merge model (notes/crdt-sync.md) after the 2026-10-14 decisions: text linearization spec, one accepted caveat to confirm, state-size benchmark.
> Tags: crdt, sync, api

Context: notes/crdt-sync.md. Decided: text/list CRDT in v1, no CRDT concepts in the API, LWW reset is the only removal, undo per actor by default with an admin view of all changes (2026-10-12), one conflict rule everywhere with author dots and no causal contexts, recursive merge for every composite type, `set_aspect` defaults to diff, backfill rule, no tombstone compaction in v1 (2026-10-14).

- Text CRDT: linearization function must be specced fully before code (tree order, sibling key = pos write time, cycle breaking, unknown anchors); state size target 1.5x-3x on the automerge-paper trace. If the benchmark misses, consider stability-based GC (notes/crdt-sync.md, Removal).
- Cross-aspect atomicity is lost against a purged aspect in old commits; accepted caveat, confirm.
