# Public API crate
> Summary: Build the `osis` crate per notes/api.md on the node engine: the `Osis` handle, reads (untyped `Value`, typed per path with path errors), listeners (fire for local changes too), `Mutator` with structural-diff `set_aspect`, replace, path ops, placement at creation, atomic multi-thing commit, signals, diagnostics channel, undo views, large values materialized and streamed, a text editing session, minimal queries, move resolution inside every call, identity/sharing/sync configuration surface, and the shape iterated with the example apps.
> Tags: api, tests

Crate: `osis`. Depends on: osis-node (and re-exports from core/schema). Unblocks: apps-e2e, cli.
Spec: spec/requirements.md (API section), spec/versioning.md §5 (typed reads), spec/permissions.md §7 (resolution), spec/data-model.md §6 (large values usable materialized and streamed). Notes: notes/api.md (fixed directions, sketch, queries, diagnostics), notes/ephemeral.md (signals API), notes/crdt.md (editing-session rule, undo). Spec trumps this plan. The API shape is not decided (owner): shape it with the examples and refactor freely; keep the fixed directions.

## Deliverables
- `Osis` handle (cloneable, thread-safe; many per database; database drops with the last), `open(config)` with store path/backend choice, identity (new node, restore from card, pair), servers list; `Error` with stable categories.
- Reads: `get_aspect(tid, ak) -> Value`, `get_typed::<T>(tid, ak)`, per-path typed reads, `list_aspects(tid)`, groups and `/groups`; every tid input and output resolved through moves; `Tid` equality is plain bits with an explicit `same_thing(a, b)`.
- Listeners: `listen_aspect`, `listen_aspect_mut`, `listen_signals`, `listen_diagnostics`, invoked once before returning (not signals), `ListenerId` cancellation; fire for local writes too.
- `Mutator`: `create_thing(Placement)` (group or explicit `Local`; unplaced-after-commit diagnostic), `set_aspect` (diff), `replace_aspect`, `remove_aspect`, path ops (set field, set case, insert/remove/move index, add/remove key, splice text, increment, undelete), retention/expiry overrides per aspect, `commit()` atomic across things; `delete_thing` defined as remove known aspects + placements.
- Signals: `send_signal(tid, kind, value, target?)`.
- Undo: per-actor derived stack (`undo()`, `redo()`, `history(scope)`), admin view listing others' changes with undo; "silent no-op where compacted" reported.
- Large values: `get_bytes_stream`, `get_text_range`, streaming writes building chunk trees (plans/large-values.md), listeners on a large value without materializing.
- Text editing session: buffer that commits on pause/blur, cut/paste with remembered ranges.
- Queries (minimal, local, rebuildable indexes): things in a group (transitive) with an aspect, ordered by a field or by commit time (display time = min(ts, receipt)), paged, with a range listener; backlinks by tid. Enough for the example apps; a design pass is a later plan.
- Sharing surface: grant/change/remove, make link, redeem link, recovery card, contact card, move thing, label management (which groups sync to which servers), diagnostics for removed-device and stranded.
- Schema integration: load `.osis` at runtime or via generated types; typed writes validated against the writer's schema.
- Docs: rustdoc examples on every public item; a `docs`-free README in the crate.

## Steps
- [ ] Handle, errors, reads/listeners/mutator over the engine events; tests with an in-memory node.
- [ ] Signals, undo, diagnostics; typed reads with generated types from osis-schema codegen.
- [ ] Large values, text sessions; queries; sharing surface wrapping flows.
- [ ] Iterate with examples/notes and examples/chat (plans/apps-e2e.md) and refactor; write notes/api.md "Decided shape" section.

## Done when
The example apps need nothing the API does not provide; every fixed direction in notes/api.md is honoured and tested; notes/api.md updated to the decided shape. Delete this plan.

## Progress
