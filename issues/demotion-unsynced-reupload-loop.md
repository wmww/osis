# demotion_unsynced seed 995988053764: one commit re-uploaded and deleted without end
> Summary: Sim `demotion_unsynced` seed 995988053764 is not quiescent (fails on main too, and on net-pull2): node 0, a writer, uploads commit 96ac2df9 (node 1's write, content of `s:map.0`/`s:reg.0`) to its host under a fresh blob ID every round and the copy is deleted again. A re-upload loop of one body, not issues/eph-churn-delete-upload-loop.md's snapshot storm. Not root-caused.
> Priority: normal
> Tags: node, sync, tests

Replay: `cargo run --bin sim-sweep -- --only demotion_unsynced --seeds 1 --from 995988053764` (`osis_sim::replay("demotion_unsynced", 995988053764)`). Failure at step 110: "not quiescent after 40 rounds; one more round changes" with pairs `s0 ... added BlobId(x): CommitId(96ac2df9..)` / `deleted BlobId(x)` for about 20 distinct x. Both nodes show `outstanding` requests on their host connection. Found by the net-pull2 review's sweep (30 seeds from 995988053760: 1 of 30).

Same shape in `coverer_revoked` seed 482913570221 (fails on main too): host s0 gets commit d907107e (node 1's write, `s:reg.0`/`s:tags.0`) added and deleted under ~20 fresh blob IDs per round, `outstanding 1` on nodes 0 and 2. Replay: `cargo run --bin sim-sweep -- --only coverer_revoked --seeds 1 --from 482913570221`.
