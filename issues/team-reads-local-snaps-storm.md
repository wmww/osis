# team_reads_member_thing: a writer's local passes judge without the label's cover
> Summary: sim `team_reads_member_thing` setup 72407225782 seed 72407225794 (on main alike) storms: writer node d9Yb places, in its own served state (`body_sends` with no host), a fresh blob {s:map.0, s:count.0} of commit 3984b3d7 under labels 36a0ae5b and af25d728 that writer OtXQ (which dropped the map.0 delta under its snapshot 5895ffec, present at the host) deletes there as holding a dropped delta, its live count.0 carried by OtXQ's rewrite; the same for commit 19d01f7b. Within one instant d9Yb's passes for one label alternate between a `snaps` set holding 5895ffec (map.0 covered, needs only count.0: the rewrite holds it) and one without it (map.0 uncovered: places {map.0, count.0} again). Not the carrier rules of spec/sync.md §7 (those agree here).
> Priority: normal
> Tags: sync, tests

- Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 72407225794 --setup 72407225782 --only team_reads_member_thing`.
- Start at: why `w.snaps` (`work::aggregate`: snapshots with an entry under the label in this node's state) lacks 5895ffec in some passes of label 36a0ae5b at d9Yb; the thing is in three labels' closures (member's and team's), and the cover went up under one first.
