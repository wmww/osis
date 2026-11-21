# Two removed keys' backdated lowerings hide each other from a node with no order
> Summary: In roles-model `paths` a node with no order of receipt (a new node's first sync) reads by the walk; where two removed keys each backdate a lowering of the same honest admin, trusting either removal alone changes nothing, so no dispute is shown and that admin's earlier writes are lost there with nothing to choose. Nodes that held the removals first are not affected. The story search's `dispute` baseline.
> Priority: low
> Tags: perm, security

**One backdated lowering** (roles-model `src/paths/tests.rs`, `a_removed_keys_backdated_lowering_drops_a_witness_write_for_good`, `first_received_trusts_a_removal_held_before_a_backdated_write`): H paired N5; B shared T1 with A2 at 2; X removed N5 at 3 listing H's grant, everyone received it; H removes X at 6 listing it. With N5's key the thief backdates a removal of B to 2, ordered after B's share. Read by the plain walk it applies (N5 an admin at 2), drops B's share, and X's removal of N5 drops it; B's share stays dropped. A node that held X's removal of N5 first trusts it (notes/write-path-design.md §1, First received, F2): its seeds take the backdated write before it acts. A node with no order (F3) reads by the walk and is shown X's removal of N5 as a dispute; choosing it brings the share back.

**Two** (`repro_two_backdated_lowerings_mask_each_other_where_nothing_is_trusted`; story moves 47 or 48 with 49 or 50): the thief also backdates a lowering of B with X's key, before H's removal of X. At a node with no order each lowering acts at its key and drops B's share; trusting X's removal of N5 alone leaves X's lowering acting, trusting H's removal of X alone leaves N5's, so neither removal is a dispute (notes/write-path-design.md §1 W10: one candidate at a time) and the node reads without A2's writes on T1 with nothing shown. Trusting both brings the share back. In the story's random worlds: 4 failing `dispute` checks in 1 world of 13,000 (moves 48 and 50), at the nodes trusting nothing (tools/known_failures.txt).

**What it is**: one of issues/admin-fights-not-always-shown.md's kind (a node's trust decides the reading only for two removals together), here with a loss: an honest admin's writes, at a node that took the walk's side (accepted for a new node: notes/disputes.md).

**Candidate, not modelled** (notes/write-path-design.md Open 2): a dispute is also any held lowering whose drops include a lowering that had applied with drops of its own, read from the walk with no trial walk. It would also show a removal whose trust changes nothing (a later applying lowering drops the same write), so it needs its own check against honest histories (`quiet`).

**Owed**
- The dispute rule for this case, or the decision that a node with no order may lose it unshown.
- The engine's default side recorded on arrival (engine `sides.rs`) by F1 to F5, with A1's walk.
