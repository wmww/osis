# Learning a thing is synced after another's parts applied: two exceptions
> Summary: Tess accepted the commit-across-things exception (spec/requirements.md). The roster snapshot shape is stated in spec/commits.md §4, not closed; spec/requirements.md does not list it yet: Tess's call. Delete once it does.
> Tags: spec, engine, sync

What a user sees (`flows::roster_copy_reads_at_each_node_*`): a node holding a holder's certificate copy of a roster snapshot, the rest away. Synced first: earlier roster, every write shows. Applied first: only the holder named holds a role, the others' writes on that thing hidden, old and new. The rest or a later whole snapshot ends it. Honest parties: only until the thing's first sync brings the rest. For good: a host hiding that body from a node just joining (it could hide those writes anyway), or the author losing its disk before placing it.

Why not closed:
- Commit across things: a part shown cannot wait again without an un-merge. Whether the thing is in the set can come from a `group.0` arriving after the part, and a header cannot tell whether a named thing will ever come. The un-merge makes every old commit across a group vanish on each join until the part comes, O(history). Never holding across things removes the atomicity requirements asks for. Holding until caught up trusts a host's word; a deadline gives slow honest hosts partial commits.
- Applying roster snapshots alone everywhere, as role commits: tried, closes it, but a syncer that reads a copy before the body loses the unnamed holders for that time, and a host hiding the body makes writes already shown vanish at long-running nodes for good. Hosts cannot otherwise take back what was delivered.
- Projecting a roster without its reset: tried, changes nothing alone. The walk makes a held snapshot the epoch start, reset or not (a copy naming bob, no reset, reads as with it). It needs epoch starts per holder (walk, rounds, incremental timelines): not simple.
- Taking a part-held snapshot out of the walk while its thing is synced (as a frontier away does): reads alike, about 50 lines and a new re-judge on every sync-set flip, for a shape where the host has no new power. Left out under Tess's line.

Tests: `waits::cross_thing_learned_late_*`, `flows::roster_snapshot_learned_late_*`, `flows::roster_copy_reads_at_each_node_*`; `waits::sync_set_of_final_group_reads_alike_in_any_order_*`; `order::learned_late_wait` plays these held sets without syncs.
