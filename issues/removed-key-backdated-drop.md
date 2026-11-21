# A removed key's backdated lowering drops honest writes for good
> Summary: In roles-model `paths` a key removed before the theft can backdate a lowering ordered before its own removal: it applies at its key, drops the honest writes resting on the lowered edge, its own removal then drops it, and drops stand. Designed: a node that held the removal before the backdated write trusts the removal, whose seeds take the write before it acts (notes/write-path-design.md §1, First received). Owed: the model cut to it, the masking case.
> Priority: normal
> Tags: perm, security

**World** (roles-model `src/paths/tests.rs`, `a_removed_keys_backdated_lowering_drops_a_witness_write_for_good`): H paired N5; B shared T1 with A2 at 2; X removed N5 at 3 listing H's grant, everyone received it; H removes X at 6 listing it. With N5's key the thief backdates a removal of B to 2, ordered after B's share. Read by the plain walk it applies (N5 an admin at 2), drops B's share, and X's removal of N5 drops it; B's share stays dropped. The story reaches it with moves 47, 48: every failure of the story's searches (`random_worlds_hold_large`, `small_family_holds_large`: liveness, KNOWN in tools/known_failures.txt).

**The rule** (notes/write-path-design.md §1, First received, F1): a node that receives an edge-class write ordered before a held, applying removal whose list leaves it out records that removal as trusted: it held the removal first. Trusted, the removal's seeds take the backdated write before the walk, so it never acts. The story gives its trusting nodes H's removal of X alone; with X's removal of N5 trusted where it was held first, liveness fails nowhere (a throwaway run: 3,000 random worlds, 190 failing checks to 0, nothing else failing).

**Owed**
- roles-model `paths`: trust sets from receipt order (notes/write-path-design.md §6, roles-model 3); then the two story properties' baselines leave tools/known_failures.txt.
- The engine's default side recorded on such an arrival (engine `sides.rs`), with A1's walk.
- A node with no order (a new node, a first sync) reads by the walk and is shown the removal as a dispute, except where two removed keys' backdated lowerings of one admin mask each other (notes/write-path-design.md Open 2).
