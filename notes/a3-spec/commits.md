# A3 draft: spec/commits.md
> Summary: Draft spec text for stage A3 (not in spec, not built): §4 Unjudgeable's leaf clause read only where the lowering cuts the part; Provisional: an act after a complete pass is reversed also by a removal written earlier whose copy had not reached the sync ID's sources (finding 29). Map: notes/a3-spec/README.md.

Written over notes/a2-spec/commits.md. Replaces its **(A3)** Unjudgeable sub-bullet and the last sentence of Provisional. Every other bullet *stands*.

## 4. Verification and application
- **Unjudgeable**, the leaf sub-bullet: it has no edge-class part, rests on the edge of a held lowering that cuts it (notes/a3-spec/permissions.md §5.1 Reading a list: the lowering takes away what the part needs there, by the held chained writes on that edge), the lowering's list root holds a pair for the part's thing, and the node does not hold that leaf.
- **Provisional**, its last sentence: a later write can still move the verdict after a complete pass (a backdated removal, a re-grant), and so can a removal written earlier whose copy had not reached S's sources when the pass ran (its delivery duty runs in its runner's passes: notes/a3-spec/permissions.md §4 The delivery duty); each is a new input at S, and these acts' own rules answer it as they answer any (a promoted body judged invalid leaves the store, a vouch whose removal is void counts nothing).
