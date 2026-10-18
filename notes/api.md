# Rust API
> Summary: Fixed API directions (plain values and listeners, no CRDT concepts, large values materialized and streamed, alias resolution inside every call, typed-read failures, diagnostics channel) plus an early sketch of the `Osis` handle and its functions. The API is NOT decided: shape it during implementation and refactor as example apps show what works (owner).

## Fixed directions (owner)
- Plain values and listeners, no CRDT concepts (notes/crdt.md).
- Large values: getting a string as one `String` is allowed; there must also be tools to read, edit and listen to a large value without materializing it.
- Undo: per actor by default; plus a view of all available changes in scope from which an admin may remove others' (notes/crdt.md).
- Listeners fire for local changes too: a committed write fires matching aspect listeners and a sent signal fires matching signal listeners on the same node, including those of the app and handle that made the change.

## Sketch (starting point, not a decision)
`Osis`: a cloneable, thread-safe handle to an internal `Database` (aspect map, sync engine, store); many handles per database, which drops with the last handle. Listeners are invoked once before the listen call returns (not for signals) and return a `ListenerId` for cancellation.
- `async Osis::get_aspect(&self, tid, ak) -> Result<Value>`
- `Osis::text_search(&self, aspect: Option<&Ak>, query: &[&str]) -> AsyncIter<(Tid, Ak, Value)>`
- `Osis::mutate(&self) -> Mutator`
- `async Osis::listen_aspect(&self, tid, ak, callback: async value -> ()) -> Result<ListenerId>`
- `async Osis::listen_aspect_mut(&self, tid, ak, callback: async (value, mutator) -> ()) -> Result<ListenerId>`
- `Mutator::create_thing(&mut self) -> Tid`, `Mutator::delete_thing(&mut self, tid)`
- `Mutator::set_aspect(&mut self, tid, ak, value)`: structural diff by default (concurrent edits elsewhere in the value survive); an explicit replace variant resets the aspect. Path ops to add: set field, insert/remove index, add/remove key, splice text, increment (spec/crdt.md §5).
- `Mutator::remove_aspect(&mut self, tid, ak)`
- `async Mutator::commit(self) -> Result<()>`: one atomic commit for every touched thing, across owners and reader sets (spec/sync.md §3, Projection).
- `async Osis::send_signal(&self, tid, kind, value)`, `async Osis::listen_signals(&self, tid, kind, callback)`: never stored, reach local listeners plus connected nodes only (notes/ephemeral.md).

## Queries apps will want (direction, not specified)
Per-aspect reads and text search are not enough for any list-like UI. Expect to grow most of a slow, not very feature-rich database on top of the local store, over time; a dedicated design pass should shape it. Kinds of things apps need:
- Things in a group (transitively) that carry a given aspect, ordered by a field or by commit time, paged, with a listener for changes inside the visible range (a chat timeline, a feed, an inbox).
- Backlinks: things whose values reference a given tid, resolved through aliases.
- Filters over aspect values (unread, by author actor, by tag) and counts, live.
- Ordering by commit time should tolerate a sender's skewed clock, e.g. display time = min(`ts`, local receipt time).
- Local-only indexes that are rebuildable and shardable per aspect, since the local store erases by key (notes/local-store.md).
None of this touches the wire.

## Typed reads (decided; spec/versioning.md §5)
Typed reads fail with an error carrying the path on an unknown enum case, a type mismatch or a missing required field; they are also available per path so an app can skip one bad element of a large collection. The untyped `Value` API always works. App types are views over the wire type, generated or hand-written in the app; transitions and the form-choice policy are codegen conventions (notes/versioning.md).

## Tids and hand-over (spec/permissions.md §7)
A thing gains a new tid when it is handed over, and a new identity per branch when an actor above it forks; old tids are aliases. Sharing never changes a tid.
- Every call that takes a tid resolves aliases internally; listeners registered under an old tid keep firing. Apps never resolve in order to access. Roster reads resolve `/members` keys too, since a handed-over actor is listed under its old tid.
- Values returned to apps have known aliases replaced by the current tid (typed tids and `osis://` links in markdown), so tids read from osis compare equal. Resolution is a read-time view: stored bytes and hashes are untouched, and `set_aspect` diffs against the resolved view, so writing a value back does not rewrite references. An app pins a reference by writing it explicitly.
- Explicit call only for identity: comparing a tid the app kept (memory, config, URL) with one read later. `Tid` equality is plain bits and cannot consult the database.

## Diagnostics channel (decided; shape is proposal)
A place to dump problems such as a colliding record from a peer, a hand-over fork, or rejected writes from a revoked actor. Apps may log, surface or ignore it; correctness never depends on anyone seeing it.
- Shape: `Osis::listen_diagnostics(callback) -> ListenerId`, structured events (kind, tids involved, peer). Default sink is the log.
- A peer must not be able to flood it: dedupe per (kind, tid), rate-limit per peer.
