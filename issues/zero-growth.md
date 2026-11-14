# Unbounded writes leave no per-write data: leftovers
> Summary: Stored state should stay flat with writes for one writer's whole replaces and for several writers under automatic compaction (spec/commits.md §5 Own replaces, Forgetting); on the rebuilt sync it grows (osis-sync `growth::repro_*`). Left also: work per write grows with commits held whole for an uncovered part, very large fields, and the user-facing wording.
> Priority: normal
> Tags: engine, spec, tess-call

**Tess question:** approve requirements wording for spec/requirements.md, in user terms: "storage follows live data and kept history, not the number of writes", plus best-effort limits (a commit with a part another writer must cover stays whole until covered; a very large field is rewritten whole on each compaction)?

## Left
- **The rebuilt sync grows** (osis-sync `growth::repro_single_writer_replace_grows_nothing_spec_commits_5`, `repro_several_writers_grow_nothing_spec_commits_5`, ignored): node 0 replaces thing 0's value 6 then 60 times, with node 1 keeping it unread and node 2 reading (or writing in turn); past the tombstone lifetime the readers' engines hold more at 60 (single writer: 69 to 82 rows, 377 to 444 KB; per-commit rows `c/` 50 to 122 and `bp/` 153 to 261 at node 0) while node 1's engine stays flat; every store holds a few more rows (24 to 29) with fewer bytes and blobs. Replaced own commits are not forgotten; whether the engine or sync's hold on their entries keeps them is not narrowed.
- A commit with a part no own replace covers (a part on an aspect another writer compacts, a part a setting keeps) stays whole until a snapshot covers that part too, and is judged again on each later own replace of its covered aspects (`retention::memory::drop_covered`): work per write grows with such commits held. Storage does not: the next snapshot of the other aspect drops the part, and the commit is forgotten.
- A snapshot rewrites the whole field, so a very large field needs a snapshot that links existing pages (none allowed): each compaction of it writes and logs the whole field.
- spec/requirements.md should state the visible guarantee (storage follows live data and kept history, not the number of writes) and the best-effort limits, in user terms, never naming snapshots; wording goes to Tess.
