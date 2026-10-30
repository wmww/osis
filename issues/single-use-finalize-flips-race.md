# Auto-finalizing a single-use link mid-race reinstates a redeemer that already left K
> Summary: Branch until-link regression (sim link_race 31/200 seeds, main 0/200: "nodes disagree on who redeemed the link"). Node-sync finalizes a single-use link after the first self-removal it sees; a concurrent redemption with an earlier key that arrives after is dropped by the removal's frontier, which restores L's edge and makes the other redeemer the winner. That redeemer had concluded it lost and stopped syncing K's label, so it never gets the removal and keeps the other view.
> Tags: permissions, node, sim

Repro: `cargo run --bin sim-sweep -- --seeds 1 --from 5252 --only link_race` (also 9008, 9012, 9014, ...). In 5252: both redemptions by L carry the same `ts`; the sharer (node 0) received one, finished a pass, wrote the removal R (frontier: that redemption only), then received the other. Node 0: redeemer x joined. Node x lacks R, has no K label in `label_status`, and computes y as winner. y is excused (not on node 0's roster).

Before the branch the sim finalized by hand after both redemptions had spread; the osis layer's old `upkeep_links` had the same race (finalized on the roster change, no pass) but no scenario drove it.

Fix directions (pick one):
- The finalizer delivers R (with K's `/label` and the rotation's boxes) to the single remaining joiner's inbox, so a redeemer that dropped K learns it is in.
- A redeemer whose redemption lost keeps following K's label until a removal of L by an admin of K arrives (the finalization is the decision), then drops it.
- Keep the sim's agreement check honest either way: compare after the finalization has had time to spread.
