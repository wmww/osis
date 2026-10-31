# A Set into another's ephemeral entry reads only where the entry was never held
> Summary: b's `Set` into a's map entry expiring later than the entry: once the entry expires (or is superseded, spec/sync.md §9) its holders hold its writes value-less and read the key absent, while a node that never held the entry (restarted after the expiry) joins b's write alone and reads b's value. Reads differ until b's write expires.
> Tags: crdt, ephemeral

Repro: `ephemeral::repro_set_into_expired_entry_differs` (osis-node, ignored). Found in review 2 of eph-churn by the randomized `random_churn` oracle (seed 85 with `Set` in its mix); superseding makes it more frequent (an entry "expires early"), but it is expiry's (spec/crdt.md §4.7): a write into a record outliving the record's creation.

Directions: a write into a record whose creation is not held reads as absent (anchor-only, as at the holders); or a write into another's record expires no later than the record (clamp at write time is impossible: the writer may not know the record's expiry; a received entry carries its commit's `expires`, so the writer could clamp to it).

The `random_churn` oracle writes no `Set` until this is fixed: put it back in its mix then.
