# Rust API
> Summary: Early API sketch (`Osis` handle, listeners, function list) plus directions: the API is NOT decided and is to be worked out during implementation and refactored as example projects show what works (owner 2026-10-12). Fixed points: plain values and listeners, no CRDT concepts; large values usable both materialized and streamed.

## Status (owner 2026-10-12)
The sketch below is the owner's earlier idea. Do not follow it closely where it conflicts with the project's needs; shape the API while implementing and refactor as example apps reveal what works. Fixed directions:
- Plain values and listeners, no CRDT concepts (notes/crdt-sync.md).
- Large values: encourage but do not require good handling. Getting a string as one `String` is allowed; there must also be tools to read, edit and listen to a large value without materializing it into one buffer. No further owner input needed now.
- Undo: per actor by default; plus a view of all available changes in scope from which an admin may remove others' (notes/crdt-sync.md).

## `Osis`
Main interface. A cloneable, thread-safe handle to an internal `Database`, which owns the aspect map, sync engine, etc. Many `Osis` handles per `Database`; the `Database` drops with the last handle.

## Listeners
- Callback is invoked once before the listen call returns.
- Returns an opaque `ListenerId` for cancellation.

## Functions
- `async Osis::get_aspect(&self, tid, ak) -> Result<Value>`
- `Osis::text_search(&self, aspect: Option<&Ak>, query: &[&str]) -> AsyncIter<(Tid, Ak, Value)>`
- `Osis::mutate(&self) -> Mutator`
- `async Osis::listen_aspect(&self, tid, ak, callback: async value -> ()) -> Result<ListenerId>`
- `async Osis::listen_aspect_mut(&self, tid, ak, callback: async (value, mutator) -> ()) -> Result<ListenerId>`
- `Mutator::create_thing(&mut self) -> Tid`
- `Mutator::delete_thing(&mut self, tid)`
- `Mutator::set_aspect(&mut self, tid, ak, value)`
- `Mutator::remove_aspect(&mut self, tid, ak)`
- `async Mutator::commit(self) -> Result<()>`

## Pending additions (proposal, see notes/crdt-sync.md)
Path-based ops: set field, insert/remove index, add/remove key, splice text, increment. `set_aspect` as structural-diff convenience plus an explicit replace variant. Default (diff vs replace) undecided.

## Tids and hand-over (proposal, see notes/permissions.md)
A thing gains a new tid each time its ownership, or that of an actor above it, is handed over; old tids are aliases. Sharing uses membership edges and never changes a tid; hand-over is only for moving a thing out of its owner's tree.
- Every call that takes a tid resolves aliases internally; listeners registered under an old tid keep firing. Apps never resolve in order to access.
- Values returned to apps have known aliases replaced by the current tid, so tids read from osis compare equal. Stored bytes and hashes are unaffected; writing such a value back performs the rewrite.
- Explicit call only for identity: comparing a tid the app kept (memory, config, URL) with one read later. `Tid` equality is plain bits and cannot consult the database.

## Diagnostics channel (decided by owner 2026-09-29; shape is proposal)
A place to dump problems such as a colliding record from a peer, a double hand-over, or rejected writes from a revoked actor. Apps may log, surface or ignore it. Correctness never depends on anyone seeing or reacting to it.
- Shape: `Osis::listen_diagnostics(callback) -> ListenerId`, structured events (kind, tids involved, peer). Default sink is the log.
- A peer must not be able to flood it: dedupe per (kind, tid), rate-limit per peer.
