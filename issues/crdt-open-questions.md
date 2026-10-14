# CRDT open questions
> Summary: Remaining undecided details in the merge model (notes/crdt-sync.md) after the 2026-10-14 decisions (LWW-element sets, dots everywhere, no contexts, no mv, set_aspect = diff). All are details or confirmations, none change state format.
> Tags: crdt, sync, api

Context: notes/crdt-sync.md. Decided: text/list CRDT in v1, no CRDT concepts in the API, LWW reset is the only removal, undo per actor by default with an admin view of all changes (2026-10-12), one conflict rule everywhere with author dots and no causal contexts, `set_aspect` defaults to diff (2026-10-14).

- Backfill: a revoked writer minting a write with a dot below a published statement is a detectable reuse; needs a deterministic winner (e.g. the statement wins, the write is invalid).
- Enum: same-case payload merge is deferred; whole-value LWW for now. Can be a later schema knob.
- Text CRDT: linearization function must be specced fully before code (tree order, sibling key = pos write time, cycle breaking, unknown anchors); state size target 1.5x-3x on the automerge-paper trace.
- Compaction of tombstone-bloated text (reset + reinsert) loses concurrent edits; rare or never, confirm.
- Cross-aspect atomicity is lost against a purged aspect in old commits; accepted caveat, confirm.
- LWW-element-set tombstones: confirm the per-removed-element cost is acceptable for large churny sets, or that a periodic reset covers it.
