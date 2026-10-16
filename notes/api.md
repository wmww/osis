# Rust API
> Summary: Early API sketch (`Osis` handle, listeners, function list) plus fixed directions. The API is NOT decided: shape it during implementation and refactor as example apps show what works (owner 2026-10-12). Fixed: plain values and listeners, no CRDT concepts; large values usable both materialized and streamed.

## Status (owner 2026-10-12)
The sketch below is the owner's earlier idea; do not follow it where it conflicts with the project's needs. Fixed directions:
- Plain values and listeners, no CRDT concepts (notes/crdt-sync.md).
- Large values: getting a string as one `String` is allowed; there must also be tools to read, edit and listen to a large value without materializing it.
- Undo: per actor by default; plus a view of all available changes in scope from which an admin may remove others' (notes/crdt-sync.md).

## `Osis`
Main interface. A cloneable, thread-safe handle to an internal `Database`, which owns the aspect map, sync engine, etc. Many `Osis` handles per `Database`; the `Database` drops with the last handle.

## Listeners
- Callback is invoked once before the listen call returns (not for signals).
- Returns an opaque `ListenerId` for cancellation.

## Functions
- `async Osis::get_aspect(&self, tid, ak) -> Result<Value>`
- `Osis::text_search(&self, aspect: Option<&Ak>, query: &[&str]) -> AsyncIter<(Tid, Ak, Value)>`
- `Osis::mutate(&self) -> Mutator`
- `async Osis::listen_aspect(&self, tid, ak, callback: async value -> ()) -> Result<ListenerId>`
- `async Osis::listen_aspect_mut(&self, tid, ak, callback: async (value, mutator) -> ()) -> Result<ListenerId>`
- `Mutator::create_thing(&mut self) -> Tid`
- `Mutator::delete_thing(&mut self, tid)`
- `Mutator::set_aspect(&mut self, tid, ak, value)`: structural diff by default (concurrent edits elsewhere in the value survive); an explicit replace variant resets the aspect (decided 2026-10-14). Path-based ops to add: set field, insert/remove index, add/remove key, splice text, increment (notes/crdt-sync.md).
- `Mutator::remove_aspect(&mut self, tid, ak)`
- `async Mutator::commit(self) -> Result<()>`
- `async Osis::send_signal(&self, tid, kind, value) -> Result<()>`, `async Osis::listen_signals(&self, tid, kind, callback: async value -> ()) -> Result<ListenerId>`: never stored, reach connected nodes only (decided 2026-10-15, notes/ephemeral.md).

## Typed reads (decided 2026-10-14, notes/versioning.md)
Typed reads fail with an error carrying the path on an unknown enum case, a field type mismatch or a missing required field; they are also available per path so an app can skip one bad element of a large collection. The untyped `Value` API always works. App types are views over the wire type, generated or hand-written in the app; transitions and the form-choice policy are codegen conventions (notes/versioning.md).

## Tids and hand-over (proposal, notes/permissions.md)
A thing gains a new tid when it is handed over, and a new identity per branch when an actor above it forks; old tids are aliases. Sharing never changes a tid.
- Every call that takes a tid resolves aliases internally; listeners registered under an old tid keep firing. Apps never resolve in order to access.
- Values returned to apps have known aliases replaced by the current tid (typed tids and `osis://` links in markdown), so tids read from osis compare equal. Resolution is a read-time view (2026-10-15): stored bytes and hashes are untouched, and `set_aspect` diffs against the resolved view, so writing a value back does not rewrite references. An app pins a reference by writing it explicitly.
- Explicit call only for identity: comparing a tid the app kept (memory, config, URL) with one read later. `Tid` equality is plain bits and cannot consult the database.

## Diagnostics channel (decided 2026-09-29; shape is proposal)
A place to dump problems such as a colliding record from a peer, a hand-over fork, or rejected writes from a revoked actor. Apps may log, surface or ignore it. Correctness never depends on anyone seeing or reacting to it.
- Shape: `Osis::listen_diagnostics(callback) -> ListenerId`, structured events (kind, tids involved, peer). Default sink is the log.
- A peer must not be able to flood it: dedupe per (kind, tid), rate-limit per peer.
