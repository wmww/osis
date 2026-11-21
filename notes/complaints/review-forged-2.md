# review-forged-2
> Summary: reviewer complaints for forged-dead-write (second version).

- The wire rule (§3.3 rule 7, a position or flag write on `Derived(d)` stamped with dot `d`) has no hand test of the behaviour it prevents (the order-dependent top-2 loss), only of the rejection; with the rule off in both decoders the crdt differential passes at Plain and Small, so the 5 seeds the branch cites are not reproducible from the tree.
- A `tools/heavy --short` of `crdt_equals_model_large` at `OSIS_FULL=1` stops at its CPU cap (120 CPU-s in 17 s): a fix-disabled probe at Large needs a full hold.
- `git rebase origin/main` conflicted on notes/priorities.md (main added a line next to the one the branch drops): a priorities list edited by both sides conflicts on every such branch.
