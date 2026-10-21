# stranded_reseal seed 23: a /label body ping-pongs under a label
> Summary: the sim sweep fails `stranded_reseal` seed 23 at step 120: after quiescence a server keeps adding and deleting the same membership commit's `/label` body (two blob IDs, one commit) under one label. Reproduces on main at 8ceefcf, so it predates the node-core merge.
> Tags: node, sync, tests

Repro: `cargo run -p osis-sim --release --bin sim-sweep -- --seeds 30` (or `osis_sim::replay("stranded_reseal", 23)`).

Seen: `s0 LabelId(ae2a980d…) added BlobId(9a9d65df…): CommitId(5b03f07b…) [(0, 0)] ["… /label"] kind Some(Membership)` and the same commit's other blob `ba85e765…` deleted, alternating. Likely two nodes disagree on which projection of the commit-form membership commit is the placed one (re-sealed boxes, certificate copies), so each pass replaces the other's.
