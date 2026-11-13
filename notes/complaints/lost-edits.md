# lost-edits
> Summary: Workflow notes from the lost-edits branch (honest writes at a removed node's rotation).

- The epochs model's merge named every honest fork (an oracle-ish choice no node can make), so the model never showed the bug the engine had; aligning it with the spec's roster rule exposed a second hole (a sibling's line on the removed node's rotation). Models that encode "honest" from the history instead of what a node can read hide exactly these bugs.
- `epochs-exh` with family C grown 4x ran 8,300-9,000 CPU-s, and `1000000 epochs` 4,900-5,300 (heavy limit 5,060). Review split family C into `epochs-exh-c` (trimmed to 4,500 CPU-s) and set the random size to 800,000.
- Review: the model's merge still filtered by the oracle's `hostile` flag; naming from what the merger holds alone (as the spec) found nothing in 200k random and A-C, so the flag went.
- Review: `roster_epochs` read uncounted removals (a removed node can forge one at its old epoch); a probe for it found a pre-existing hole (issues/merge-renames-removed-nodes-removal.md) and an engine debug-assert (issues/merge-at-removed-node-stale-epochs.md).
- Three 1M random runs each found one more oracle refinement (a removed node's own pre-removal rotation was classed as a sibling's concurrent epoch, awareness of a removal whose chain was not held, the fork window when dropping forks flips the followed line): small hand reproductions of each would have been cheaper; a `print_world` that emits a Rust test would help.
- An outsider drops an invalid commit's body; a test that names it later must offer the body again (`send(..., &[w])` twice), which reads like a test hack until one knows.
