# Node-core residue: membership-heavy changes and rarely judged snapshot writes
> Summary: Granting someone new to a large tree re-checks every change in it (about 70 ms at 10^4 changes; linear); a validity flip re-reads every held change of the aspect; opening still reads every commit header. Writes a snapshot carries for a key actor (commit form), or an element creation with no stamp of its writer below it, are not judged on their own.
> Tags: node, permissions, performance

Repro: `cargo test --release -p osis-node --test scale -- --ignored --nocapture membership_change_and_open_cost`.

Done (notes/node.md: Validity, Snapshots vouch for nothing, Snapshots, Import, Open, Rollback): imports from compaction snapshots with the origin's schema, element-level judging of snapshot-carried writes, deaths in every held body carrying a write, the persisted index, journaled rollback, re-judging per changed timeline, `Timelines::update_touched`, `/groups` incremental, the deletion and re-snapshot queues removed.

Remaining:
- A change that perm evaluates anew (a member new to the component joins it, an out-of-order or dropping write, an epoch start change) re-judges every delta of the component: for one person's tree, every delta (perm's component granularity; issues/perm-eval-cost.md item 4 would give per-(node, thing) answers).
- A validity flip rebuilds the aspect from every held body (O(aspect history)); re-merging needs them (a register's earlier value comes back only from its body), un-merging alone would not.
- Open reads every commit record's head and header and every membership commit's `/members` and `/tenures` parts, and perm evaluates every component from scratch.
- Snapshot-carried writes of commit form (no author known) are neither judged nor given deaths; an element creation with no stamp of its node below it in the snapshot is not judged.
