# CRDT open questions
> Summary: Remaining details in the merge model (notes/crdt-sync.md) after the 2026-10-14 decisions. Horizon-based tombstone compaction is proposed and awaits owner confirmation; the rest is spec work or confirmations.
> Tags: crdt, sync, api

Context: notes/crdt-sync.md. Decided: text/list CRDT in v1, no CRDT concepts in the API, LWW reset is the only removal, undo per actor by default with an admin view of all changes (2026-10-12), one conflict rule everywhere with author dots and no causal contexts, recursive merge for every composite type, `set_aspect` defaults to diff, backfill rule (2026-10-14).

- Tombstone compaction by staleness horizon H (notes/crdt-sync.md, Removal): confirm the contract "sync at least once per H or pending edits are lost", pick H, and spec the fold of anchoring tombstones so join of states compacted to different horizons is well-defined. Covers text tombstones and LWW set/map tombstones alike.
- Text CRDT: linearization function must be specced fully before code (tree order, sibling key = pos write time, cycle breaking, unknown anchors, folded compound keys); state size target 1.5x-3x on the automerge-paper trace.
- Cross-aspect atomicity is lost against a purged aspect in old commits; accepted caveat, confirm.
