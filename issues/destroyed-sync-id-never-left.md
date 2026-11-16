# A destroyed thing's requests leave with their window
> Summary: Tess to confirm: a destroying request stays under the destroyed thing's own sync ID S only while the node keeps it (in force or needed, spec/commits.md §5), so a purge without `expires` empties S at the end of its window and a node away for the whole window never learns of the destruction.
> Priority: low
> Tags: sync, engine, tess-call

spec/sync-judgement.md §5 and the code (osis-sync `judge::doom`) agree with spec/commits.md §5 Destruction: what a destroyed thing keeps is bounded by live things, its requests included. The other reading (requests kept under S until their `expires`) keeps S, its request entries and the thing's secrets at every holder forever for a purge without `expires`, which breaks "releasing everything returns the node to its own identity" (spec/requirements.md), but would tell a node away past the window. The cost of this reading: such a node keeps the thing (spec/sync-judgement.md §5 Limit), against "destroys the thing at every node" (spec/requirements.md Deletion). Test: core/sync/tests/it/destruction.rs `a_destroyed_things_sync_id_empties_past_its_window_spec_sync_judgement_5`.
