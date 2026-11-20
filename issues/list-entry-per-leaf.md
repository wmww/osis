# A list entry names its part on its leaf's thing alone
> Summary: At A3's leaf form a reader holding one sync ID sees only its things' leaves, so a list entry in thing t's leaf must name only its commit's parts on t (notes/evidence-model-findings.md 24); roles-model `paths` and osis-perm `paths` read an entry as naming every part of its commit, whatever leaf lists it.
> Priority: normal
> Tags: perm, roles-model

World (held-model `spec_gaps::gaps_a_list_entry_names_its_part_on_its_leafs_thing_alone`): Z writes one split commit, a part on D through [A, O] and a part on A directly; X removes Z from A listing the commit in D's leaf only. Read commit-wide, the node holding everything keeps Z's part on A (D's leaf names the commit); A's reader cannot hold D's leaf and drops it. held-model models the per-leaf reading (`World::own_leaf`, on), under which every stage holds.

Change, with A3's leaf brief (A1's whole list stays commit-wide until then):
- roles-model `paths::World::in_leaves`: under a leaf-form rule, an entry names `j` only from the leaf of `j`'s own thing (`frontier.get(&commits[j].on)`), so `listed` reads it per part; held-model then drops its `own_leaf` regrouping.
- osis-perm `paths` `content.rs` `listed` (and the frontier's role entries if they move to leaves, OPEN 4): the namers of a delta on t are t's leaf's entries.
- The writer lists a commit in the leaf of each thing it has a part on resting on the lowered edge (notes/a2-spec/permissions.md §5.1 (A3)).
