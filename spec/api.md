# API

## `Osis`
The main interface of osis is the `Osis` type. `Osis` acts as a handle to an internal `Database`. The underlying `Database` owns an aspect map, sync engine, etc. `Osis` can be cloned and passed between threads, many instances can be connected to the same internal `Database`. When all `Osis` instances for a `Database` are dropped, the `Database` is dropped.

## Listeners
- When a listener is added its callback is invoked initially before the listen call returns
- When a listener is added an opaque ID is returned, which can be used to cancel the listener

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
