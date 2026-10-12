# CRDT open questions
> Summary: Undecided points in the merge model (notes/crdt-sync.md): set/map context vs LWW-element, dots on registers for revocation and backfill, set_aspect default, mv register exposure, enum payload merge. Model as a whole is still proposal.
> Tags: crdt, sync, api

Context: notes/crdt-sync.md. Decided: text/list CRDT in v1, no CRDT concepts in the API, LWW reset is the only removal, undo per actor by default with an admin view of all changes (2026-10-12). Everything else is proposal and needs confirming or deciding, ideally by building and testing.

- set/map: OR-set/OR-map with causal context vs LWW-element-set (one tombstone per removed element until reset). Decides whether causal contexts exist at all.
- Registers carry only a timestamp, but revocation un-merge (notes/permissions.md, Costs) needs every state element attributable to an author node and droppable by dot. Add a dot to registers, or find another attribution.
- Backfill: a revoked writer minting a write with a dot below a published statement is a detectable reuse; needs a deterministic winner.
- `set_aspect` default: structural diff vs replace (reset).
- Expose a multi-value (`mv`) register to apps in v1, or LWW only?
- Enum: same-case payload merge is deferred; whole-value LWW for now.
- Text CRDT: linearization function must be specced fully before code (tree order, sibling key = pos write time, cycle breaking, unknown anchors); state size target 1.5x-3x on the automerge-paper trace.
- Compaction of tombstone-bloated text (reset + reinsert) loses concurrent edits; rare or never, confirm.
- Cross-aspect atomicity is lost against a purged aspect in old commits; accepted caveat, confirm.
