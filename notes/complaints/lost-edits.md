# lost-edits
> Summary: Workflow notes from the lost-edits branch (honest writes at a removed node's rotation).

- The epochs model's merge named every honest fork (an oracle-ish choice no node can make), so the model never showed the bug the engine had; aligning it with the spec's roster rule exposed a second hole (a sibling's line on the removed node's rotation). Models that encode "honest" from the history instead of what a node can read hide exactly these bugs.
- `epochs-exh` with family C grown 4x ran 8,300-9,000 CPU-s, and `1000000 epochs` 4,900-5,300 (heavy limit 5,060): the `heavy` limit for these searches needs raising, or family C trimming.
- Three 1M random runs each found one more oracle refinement (a removed node's own pre-removal rotation was classed as a sibling's concurrent epoch, awareness of a removal whose chain was not held, the fork window when dropping forks flips the followed line): small hand reproductions of each would have been cheaper; a `print_world` that emits a Rust test would help.
- An outsider drops an invalid commit's body; a test that names it later must offer the body again (`send(..., &[w])` twice), which reads like a test hack until one knows.
