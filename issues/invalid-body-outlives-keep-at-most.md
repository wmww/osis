# A body of an invalid delta stays past its keep at most
> Summary: spec/commits.md §5: a write of a delta invalid here does not die, so its body has no bound and stays, value included, at every node holding it, until a flip, purge, expiry, absolute bound or cover. Under keep at most 0 too. Nobody reads it, but the bytes outlive the promise. A valid write an un-merge took (nested under an entry whose creation is invalid) has no death either: same effect.
> Tags: engine, retention, security

Seen with `order::body_past_bound`, which skips such bodies: 180 such bodies held past the bound over 10 seeds from 61810000 of `arrival_order_alike_large` (`t:gone.0`, `t:gonemap.0`, snapshots too). Honest shape: a writer's write under keep at most racing its demotion; otherwise a forged write, so a hostile writer can park bytes at every reader for good, within its storage limits.

A validity flip can bring the write back, which is why it keeps its body. Options: count an invalid write dead from the `ts` of the fall (a later flip back reads less, the stated exception on keep-at-most data), or state the limit. Rule call: Tess.
