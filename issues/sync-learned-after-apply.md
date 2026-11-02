# When a node learns it syncs a thing decides whether a partial commit applies
> Summary: two nodes holding the same parts of a commit and syncing the same thing differ, for as long as the other part stays away: one started syncing first and holds the commit pending (`WaitDeltas`), the other applied it first and shows it. A node's sync set comes from what it holds (`sync_closure`), so arrival order can decide. Needs a spec decision.
> Tags: tests, spec, engine, sync

Repro (fails): `cargo test -p osis-node --test it -- --ignored repro_sync_learned_after_apply_spec_commits_4`.

spec/commits.md §4 allows it as written: atomic apply waits for deltas under a label the node syncs, pending commits are re-examined on a change, and "a delta of an already applied commit that arrives later (the node began syncing its label after applying) is joined on arrival". But spec/requirements.md Decentralization says state is a function of held data, and `SyncEngine::sync_closure` starts syncing a thing when a group's closure grows, which depends on what arrived. With every delta held in the end, the nodes agree (the order harness checks this, `Syncs::Late`); a part withheld for good is the difference, so the harness does not combine `Syncs::Late` with withheld parts.

Decide: accept it (say so in spec/commits.md: atomic apply is judged at arrival, not a function of the held set) or make it exact (an applied commit under a newly synced thing with a part missing goes back to waiting: an un-merge, costly).
