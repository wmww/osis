# Rust API
> Summary: `Osis` handle, listener semantics and the initial function list; decided by owner, formerly spec/api.md. CRDT work implies path-based mutation ops still to be added; API exposes plain values only, no CRDT concepts.

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
A thing gains a new tid each time its ownership, or that of an actor above it, is handed over; old tids are aliases. Apps should avoid ownership changes where membership changes will do.
- Every call that takes a tid resolves aliases internally; listeners registered under an old tid keep firing. Apps never resolve in order to access.
- Values returned to apps have known aliases replaced by the current tid, so tids read from osis compare equal. Stored bytes and hashes are unaffected; writing such a value back performs the rewrite.
- Explicit call only for identity: comparing a tid the app kept (memory, config, URL) with one read later. `Tid` equality is plain bits and cannot consult the database.

## Diagnostics channel (decided by owner 2026-09-29; shape is proposal)
A place to dump problems such as a colliding record from a peer, a double hand-over, or rejected writes from a revoked actor. Apps may log, surface or ignore it. Correctness never depends on anyone seeing or reacting to it.
- Shape: `Osis::listen_diagnostics(callback) -> ListenerId`, structured events (kind, tids involved, peer). Default sink is the log.
- A peer must not be able to flood it: dedupe per (kind, tid), rate-limit per peer.
