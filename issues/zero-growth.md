# Storage flat with writes: leftovers
> Summary: Stored state stays flat with replacing writes (osis-sync `growth::*_grow_nothing_spec_commits_5`, the S1 arms); what the tests still allow is bounded and not per write. Left: work per write grows with commits held whole for an uncovered part, a very large field rewritten whole per compaction, and whether to state the stronger property in requirements.
> Priority: low
> Tags: engine, spec, tess-call

## What the tests allow, and why each is no leak
- `growth::flat` (6 vs 60 more writes): a store's attribution rows (`B/`, `W/`) at most one per entry; 64 B for a counter that widened; pages are not counted (their layout follows the write history within a bound).
- S1 (`growth::as_fresh`, released things, expiry, history, grants and declines): the schemas a node learned (`d/`, its own); `cv/` at most one row per held snapshot; set tombstones in the roots' `holds.0` and `tickets.0`, a few bytes per removal (`TOMBSTONE_BYTES`, issues/storage-owners.md 12: spec/requirements.md Scale states it, "a few bytes each" per removal; no cover can drop one without losing a removal's finality).

## Left
- A commit with a part no own replace covers (a part on an aspect another writer compacts, a part a setting keeps) stays whole until a snapshot covers that part too, and is judged again at each later own replace of its covered aspects (spec/commits.md §5 Own replaces): work per write grows with such commits held. Storage does not: the other aspect's next snapshot drops the part and the commit is forgotten.
- A snapshot rewrites the whole field, so each compaction of a very large field writes and logs it whole (no snapshot links existing pages).
- **Tess question**: spec/requirements.md Scale already says state grows "a few bytes each" per edit and removal. What is built is stronger for replaces (nothing per replace once covered, only set removals leave bytes). State it ("storage follows live data, kept history and removals from sets, not the number of replacing writes", best effort as above), or leave the weaker line?
