# Rust API
> Summary: Early API sketch (`Osis` handle, listeners, function list) plus fixed directions. The API is NOT decided: shape it during implementation and refactor as example apps show what works (owner). Fixed: plain values and listeners, no CRDT concepts; large values usable both materialized and streamed.

## Status (owner)
The sketch below is the owner's earlier idea; do not follow it where it conflicts with the project's needs. Fixed directions:
- Plain values and listeners, no CRDT concepts (notes/crdt.md).
- Large values: getting a string as one `String` is allowed; there must also be tools to read, edit and listen to a large value without materializing it.
- Undo: per actor by default; plus a view of all available changes in scope from which an admin may remove others' (notes/crdt.md).

## `Osis`
Main interface. A cloneable, thread-safe handle to an internal `Database`, which owns the aspect map, sync engine, etc. Many `Osis` handles per `Database`; the `Database` drops with the last handle.

## Listeners
- Callback is invoked once before the listen call returns (not for signals).
- Returns an opaque `ListenerId` for cancellation.
- Local changes fire listeners locally: a committed write fires matching aspect listeners and a sent signal fires matching signal listeners on the same node, with no other node connected, including listeners of the app (and `Osis` handle) that made the change.

## Functions
- `async Osis::get_aspect(&self, tid, ak) -> Result<Value>`
- `Osis::text_search(&self, aspect: Option<&Ak>, query: &[&str]) -> AsyncIter<(Tid, Ak, Value)>`
- `Osis::mutate(&self) -> Mutator`
- `async Osis::listen_aspect(&self, tid, ak, callback: async value -> ()) -> Result<ListenerId>`
- `async Osis::listen_aspect_mut(&self, tid, ak, callback: async (value, mutator) -> ()) -> Result<ListenerId>`
- `Mutator::create_thing(&mut self) -> Tid`
- `Mutator::delete_thing(&mut self, tid)`
- `Mutator::set_aspect(&mut self, tid, ak, value)`: structural diff by default (concurrent edits elsewhere in the value survive); an explicit replace variant resets the aspect. Path-based ops to add: set field, insert/remove index, add/remove key, splice text, increment (notes/crdt.md).
- `Mutator::remove_aspect(&mut self, tid, ak)`
- `async Mutator::commit(self) -> Result<()>`: one atomic commit for every touched thing, across owners and reader sets (spec/sync.md §3, Projection).
- `async Osis::send_signal(&self, tid, kind, value) -> Result<()>`, `async Osis::listen_signals(&self, tid, kind, callback: async value -> ()) -> Result<ListenerId>`: never stored, reach local listeners plus connected nodes only (decided, notes/ephemeral.md).

## Queries apps will want (direction, not specified)
The chat deep dive showed that per-aspect reads and text search are not enough for any list-like UI. Expect to grow most of a slow, not very feature-rich database on top of the lighter local store, over time; a dedicated design pass should shape it. The kinds of things apps need, kept loose on purpose:
- Things in a group (transitively) that carry a given aspect, ordered by a field or by commit time, paged, with a listener for changes inside the visible range (a chat timeline, a feed, an inbox).
- Backlinks: things whose values reference a given tid, resolved through aliases (reactions and replies pointing at a message, "where is this note linked").
- Filters over aspect values (unread, by author actor, by tag) and counts, live.
- Local-only indexes that are rebuildable and shardable per aspect, since the local store erases by key (notes/local-store.md).
None of this touches the wire; it is local API work.

## Typed reads (decided; spec/versioning.md §5)
Typed reads fail with an error carrying the path on an unknown enum case, a field type mismatch or a missing required field; they are also available per path so an app can skip one bad element of a large collection. The untyped `Value` API always works. App types are views over the wire type, generated or hand-written in the app; transitions and the form-choice policy are codegen conventions (notes/versioning.md).

## Tids and hand-over (spec/permissions.md §7)
A thing gains a new tid when it is handed over, and a new identity per branch when an actor above it forks; old tids are aliases. Sharing never changes a tid.
- Every call that takes a tid resolves aliases internally; listeners registered under an old tid keep firing. Apps never resolve in order to access.
- Values returned to apps have known aliases replaced by the current tid (typed tids and `osis://` links in markdown), so tids read from osis compare equal. Resolution is a read-time view: stored bytes and hashes are untouched, and `set_aspect` diffs against the resolved view, so writing a value back does not rewrite references. An app pins a reference by writing it explicitly.
- Explicit call only for identity: comparing a tid the app kept (memory, config, URL) with one read later. `Tid` equality is plain bits and cannot consult the database.

## Diagnostics channel (decided; shape is proposal)
A place to dump problems such as a colliding record from a peer, a hand-over fork, or rejected writes from a revoked actor. Apps may log, surface or ignore it. Correctness never depends on anyone seeing or reacting to it.
- Shape: `Osis::listen_diagnostics(callback) -> ListenerId`, structured events (kind, tids involved, peer). Default sink is the log.
- A peer must not be able to flood it: dedupe per (kind, tid), rate-limit per peer.
