# meta-part-state
- My phase-1 grep for `Meta` field readers excluded `core/node/src/sync/` (it was off-limits to edit), so I reported "nothing outside the engine reads these fields". Three sync files do (inbound.rs, memory.rs, pass/delete.rs): the edit there is an accessor swap only. Grep the whole tree for readers even where you may not edit.
- `CommitDigest` (the `check_index` comparison) left out `whole` and `own_replaces`, so a live index whose own replaces differed from a load from the records went unseen; `whole` is in the digest now.
