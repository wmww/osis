# A commit waits forever for a body deleted with no carrier
> Summary: Atomic apply waits for every missing part under a synced label unless it expired, was purged or a later snapshot lists it. A body with no live write under keep at most is deleted at hosts with no carrier snapshot (spec/commits.md §5), so a node that later receives the same commit's other body waits forever, and that body's live writes never show there.
> Tags: engine, sync, spec

## Repro sketch
1. Schema: on thing t, aspect `m` with retention `writer`, keep at most 0 after replaced; aspect `k` with default retention. Both are under one label.
2. Node A writes c1 = {m: "x", k: 1}. The two parts differ in retention class, so c1 uploads as two blobs (spec/sync.md §3 Projection).
3. A writes c2 = {m: "y"}. c1's `m` body now has no live write, so A drops it in the killing transaction and deletes it at hosts in the same sync (`retention::check_at_most`, the at-most-0 path; node-sync `pass/delete.rs`).
4. Fresh node B syncs t. It gets c1's `k` blob and c2, but never c1's `m` blob.
   - `apply::waits_for_deltas`: t is synced, `m` has no expiry, it was not purged, and no snapshot lists it (`receipt::listed`). So c1 pends `WaitDeltas` forever.
   - B reads `k` absent while A reads `k` = 1, until someone compacts `m`. Only explicit compaction is built.
5. Same with an absolute keep at most that has passed, and with D after replaced (a timed delete sent).

Engine-level test: ingest only c1's `k` projection plus c2 at a node syncing t, run `reexamine`, and assert that c1 applies. It fails today. A node-level test should drive the real deletion.

## Options
1. A missing part whose delta has a keep at most counts as held (relative: always; absolute: once passed), and it joins as a late part if it arrives. Atomic visibility is then not guaranteed for commits that mix keep-at-most deltas with others (a requirements "Atomic" compromise, like issues/session-sources.md rule 5). The final state is order independent. Simplest.
2. The node that deletes such a body first writes a snapshot of the aspect, so `listed` sees it. That costs a commit per drop under at most 0 (disappearing messages), which is the cost at-most 0 is meant to avoid.
3. Writers split such commits by retention class. That loses the atomicity the app asked for, so it is no better than 1.

Recommend 1. It needs an owner call because it is an "Atomic" compromise.
