# Public API crate
> Summary: Build the `osis` crate to the shape in notes/api.md on the node engine: typed aspect and signal keys, synchronous reads with `at()` paths and a materialization bound, atomic `Watch`/RAII `Subscription` on one dispatcher thread, the `Write` batch (`set`/`edit`/`replace`/`remove`, path ops, explicit owner and placement, local rights check, no silent split), signals, undo and history, large-value streaming, text sessions, minimal live queries, the sharing/device/link/card surface, sync configuration and status with async only where another node is waited on, diagnostics, one `Error`; iterated with the example apps.
> Tags: api, tests

Crate: `osis`. Depends on: osis-node (re-exports from core/schema). Unblocks: apps-e2e, cli.
Spec: spec/requirements.md (API section, Offline), spec/versioning.md §5 (typed reads), spec/permissions.md §2 (roster read), §5.3 (pre-sync), §7 (resolution), spec/data-model.md §6 (large values materialized and streamed), spec/crdt.md §9 (what `set` means), spec/sync.md §9 (signals). Notes: notes/api.md (the shape, footguns, rejected shapes), notes/ephemeral.md, notes/crdt.md (editing-session rule, undo hints). Spec trumps this plan. The shape is the target; refactor freely with the examples but keep the fixed directions and keep every closed footgun closed (notes/api.md lists them; each has a test).

## Deliverables
- Handle: `Osis` (clone, send, sync; database closes with the last handle), `create` (returns the recovery card), `open`, `restore`, `pair`, `Config` (store, optional runtime handle, servers, `materialize_limit`, `idle_commit`), `node()`, `me()`, `close()`. Background work on the handle's tokio runtime; app-facing futures resolved by channels (runtime-agnostic, tested from a non-tokio executor).
- Keys: `AspectKey` trait and `Aspect<T>` / `Signal<T>` (from osis-schema), `Ak` as the untyped key, `osis::core` typed constants for the core aspects; `Path` and `p!`.
- Reads: `get`, `at(tid, key)` with `get`, per-path typed and untyped reads, `len`, `stream` (`Read + Seek`, lazy chunks), `read(|r|)` consistent view, `aspects`, `groups_of`, `roster`, `role_on`; the materialization bound (`TooLarge`); every tid in and out resolved through moves; `same_thing`.
- Watching: `Watch<T>` (atomic with the current value; `current`, `changed`, `changed_timeout`, `on_change`), `on_change` with the initial call through the dispatcher, `watch_thing`, `watch_roster`, `watch_status`; RAII `Subscription` with `detach`; one dispatcher thread per database, commit order, after durability, never under a lock, API usable from callbacks, coalescing; `Change` with origin, actor, node, `ts`, `received`.
- `Write`: `create(owner, Place)`, `at(tid, key)` with `set` (diff vs current), `edit(base, new)` (diff base→new as path ops, sequences rebased; crdt provides the diff and rebase), `replace`, `remove`, `expires_at/in`, `retention`, path ops (`set`, `replace`, `remove`, `set_case`, `insert`, `delete`, `move`, `splice`, `undelete`, `add`, `remove_elem`, `put`, `remove_key`, `inc`, `observe`, `set_stream`), `place`, `unplace`, `add_subgroup`, `remove_subgroup`, `delete(tid)`; `commit` (atomic, `TooLarge` instead of splitting) and `commit_split`; `#[must_use]`, `write_with`; rights checked locally (`Permission`, `UnknownThing`); `NotSynced` diagnostic after commit; own watches fire after durability.
- Signals: `send_signal(tid, key, value, Target)`, `on_signal`.
- Undo: `UndoScope`, `undo`, `redo`, `history` with `Undoable | Undone | Dropped(reason)`, `undo_commit`.
- Text session: `edit_text` buffer with remote merge callbacks, cut/paste with remembered ranges, commit on `commit()`, idle and drop.
- Queries (minimal): `query(in_group, with(key), order by time or field, page) -> Live<Vec<Hit>>` with a watch on the visible range; `backlinks`. Local rebuildable indexes sharded per aspect.
- Sharing: `grant`, `change_edge`, `demote` (`Demotion { sync: Required | Try | Skip, backdate }`, the pre-sync via flows), `leave`, `pair_offer`, `devices`, `remove_device`, `make_link`, `redeem`, `links`, `revoke_link`, `contact_card`, `import_contact`, `move_thing`; bearer `open_link` if time allows.
- Sync: `ServerAddr`, `servers`/`add_server`/`remove_server`, `sync(group, servers)`, `unsync`, `sync_policy`, `status`, `wait_synced`, `sync_now`, `export_bundle`, `import_bundle`.
- Diagnostics: `on_diagnostic`, structured, deduped and rate-limited by the engine; the required kinds (removed-device, stranded, not-synced, demotion proceeded unsynced).
- `Error` with the categories of notes/api.md; peer problems never become errors.
- Docs: rustdoc example on every public item; a README in the crate with the notes-app walk-through; a "Footguns" section pointing at `edit` vs `set`, the bound, `commit_split`, `Place`.

## Steps
- [ ] Keys, `Error`, handle over the engine with the memory store and no network: reads, `at()` paths, `Write` with every op, create/place, commit with local rights check and `TooLarge`; tests per op and per closed footgun (`edit` keeps a concurrent remote field write that `set` would clobber; bound; must-use; no split).
- [ ] Dispatcher, `Watch`, `Subscription`, `on_change` initial call, `watch_thing`; signals; undo and history; diagnostics; typed reads and writes through generated types from osis-schema codegen (the notes schema).
- [ ] Large values (bound, `stream`, `set_stream`, path reads O(entry)); text sessions; queries and backlinks.
- [ ] Sharing, devices, links, cards, move; sync configuration, status, `wait_synced`, bundles; async surface tested from a plain executor; `Demotion` policies end to end in the simulator.
- [ ] Iterate with examples/notes and examples/chat (plans/apps-e2e.md); refactor; write the "Implementation" section of notes/api.md (what differs from the shape and why).

## Done when
The example apps need nothing the API does not provide; every fixed direction and every closed footgun in notes/api.md has a test; the async surface runs from a non-tokio executor; notes/api.md updated to what was built. Delete this plan.

## Progress
