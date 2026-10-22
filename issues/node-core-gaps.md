# Node-core residue: membership-heavy changes
> Summary: Granting someone new to a large tree re-checks every change in it (about 70 ms at 10^4 changes; linear); a validity flip re-reads every held change of the aspect; opening still reads every commit header and decodes every membership change.
> Tags: node, permissions, performance

Repro: `cargo test --release -p osis-node --test scale -- --ignored --nocapture membership_change_and_open_cost`.

Done (notes/node.md: Validity, Snapshots vouch for nothing, Snapshots, Import, Open, Rollback): saved membership walks restored at open, imports from compaction snapshots with the origin's schema, element-level judging of snapshot-carried writes, deaths in every held body carrying a write, the persisted index, journaled rollback, re-judging per changed timeline, `Timelines::update_touched`, `/groups` incremental, the deletion and re-snapshot queues removed.

Remaining:
- A change that perm evaluates anew (a member new to the component joins it, an out-of-order or dropping write, an epoch start change) re-judges every delta of the component: for one person's tree, every delta (perm's component granularity; issues/perm-eval-cost.md item 3 would give per-(node, thing) answers).
- A validity flip rebuilds the aspect from every held body (O(aspect history)); re-merging needs them (a register's earlier value comes back only from its body), un-merging alone would not.
- Open reads every commit record's head and header and decodes every membership commit's `/members` and `/tenures` parts (perm's inputs; the saved walks are matched against them): at 10^4 content plus 10^4 edge writes 145 ms and 190 ms of a 0.37 s open (notes/node.md Open). Perm's walk itself is restored (notes/permissions.md, Saved walks). Idea: persist perm's adapted records per commit in the index.
