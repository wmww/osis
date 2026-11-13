# Unbounded writes leave no per-write data: leftovers
> Summary: Built: stored state stays flat with writes for one writer's whole replaces and for several writers under automatic compaction (spec/commits.md §5 Own replaces, Forgetting; `growth::single_writer_replace_grows_nothing`, `several_writers_grow_nothing`, `several_writers_expiring_grow_nothing`). Left: work per write grows with commits held whole for an uncovered part, very large fields, and the user-facing wording.
> Priority: normal
> Tags: engine, node, spec, tess-call

## Left
- A commit with a part no own replace covers (a part on an aspect another writer compacts, a part a setting keeps) stays whole until a snapshot covers that part too, and is judged again on each later own replace of its covered aspects (node-sync `drop_covered`, `left.wait`): work per write grows with such commits held. Storage does not: the next snapshot of the other aspect drops the part, and the commit is forgotten.
- A snapshot rewrites the whole field, so a very large field needs a snapshot that links existing pages (none allowed today): each compaction of it writes and uploads the whole field.
- spec/requirements.md should state the visible guarantee (storage follows live data and kept history, not the number of writes) and the best-effort limits, in user terms, never naming snapshots; wording goes to Tess.
