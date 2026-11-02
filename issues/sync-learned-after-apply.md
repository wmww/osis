# Learning a thing is synced after another's parts applied: two exceptions
> Summary: Owner accepted the commit-across-things exception (spec/requirements.md); the role-class snapshot shape is still to be looked at. What a node syncs is now a function of held data and what it was asked to sync, and a thing's parts wait alike synced or not. Two shapes stay: a commit across things, and a role-class snapshot, held in part when a thing enters the sync set after parts applied. Both differ only while a part stays away; a hostile author or host can make that forever. Open: does the snapshot shape affect who appears to hold a role, and can it be closed.
> Tags: spec, engine, sync

What remains (spec/commits.md §4 Exceptions): the same bodies, the same final sync set; the node that had the thing in its set first holds the commit whole, the one that applied first shows the parts on the other things (or the snapshot's part), its late part joining on arrival.

Why not closed:
- A part shown cannot wait again without an un-merge. Whether the thing is in the set can come from a `group.0` arriving after the part, so the only rules with no such flip decide from what arrives with the first part, the header: there is no way to tell from a header whether a named thing will ever come (another's private thing never does), and marking atomic classes in the header cannot say which label a device syncs.
- The un-merge: starting to sync a group makes every old commit across it and a synced group vanish until the part comes, O(history) work on every join for a shape that needs a part withheld for good. Out of proportion.
- Never holding across things removes the atomicity requirements asks for from every honest commit, to fix a shape needing a withheld part.
- Holding until caught up with the host, or a deadline: the first trusts a host's word for a release and misfires on uploads across labels; the second gives every honest slow host a partial commit.

Role-class snapshots: applying them alone everywhere (as role commits) would close it, but a syncer holding only a roster snapshot's projection reads its reset, and a host hiding the body could then make holders' writes vanish at long-running nodes, which holding whole prevents. Projecting a roster without its reset might close it, with a change to spec/permissions.md §6: issues/snapshot-created-copy-pends.md.

Tests: `waits::cross_thing_learned_late_stays_until_the_part_comes_*` and `flows::roster_snapshot_learned_late_stays_until_the_rest_comes_*` pin the shapes; `waits::sync_set_of_final_group_reads_alike_in_any_order_*` plays the sync set through `group.0` (the order harness toggles `set_syncing` directly and writes no `group.0`); `order::learned_late_wait` plays exactly these held sets without syncs, every other held set with syncs learned late and parts withheld.
