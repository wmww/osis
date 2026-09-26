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
