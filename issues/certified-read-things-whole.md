# Certified: the read things read from the whole sync set
> Summary: `sync::certified` derives the read things from `sync_set()` whole, one O(things) set diff per change of the sync set.
> Priority: low
> Tags: engine, sync, performance

- `Engine::read_things` derives the read things from `sync_set()` whole: one O(things) set diff per change of the sync set (every thing made). Per sync ID entries would make it per change.
