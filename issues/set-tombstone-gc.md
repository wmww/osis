# Drop set and bag tombstone GC?
> Summary: Set/bag tombstone GC by received-dot ranges needs the `W` fold, the "dropped dot joins to nothing" rule and makes snapshots differ between nodes that ran GC and those that did not; the reference model does not implement it. Maps keep tombstones until a reset anyway.
> Tags: owner-call, crdt

spec/crdt.md §5.5 lets a node drop a set tombstone once it has applied both the add and the reset, folding the reset into `W`. Cost of keeping GC: received-dot range bookkeeping in the merge layer, the fold, a special join rule for late records of dropped dots, and non-identical snapshots across nodes (allowed, but one more thing to test). Cost of dropping it: about 10 bytes per removed element until the next reset of the set, the same growth class as tension 14 (sequences) and as maps today. Recommendation: drop GC for uniformity unless the owner expects sets with very high removal churn and no resets.
