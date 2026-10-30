# A writer's cover that is not a join makes holders diverge
> Summary: holders drop the commits a valid cover lists as absorbed without checking that the cover contains them, and without rebuilding the state. A writer can publish a "cover" of its own commits that omits their writes: nodes that held those commits keep showing them, while late joiners and nodes that later rebuild the aspect do not. The divergence lasts. Medium.
> Tags: security, engine, ephemeral

Scenario. Writer W sends commit W1 setting aspect X to `a`. Then it sends C, a plain ephemeral commit by W whose part on X carries no write covering W1's dot but lists W1 as absorbed. W deletes W1 at the servers (level-3 key).
- Holders that had W1: `drop_absorbed` (core/engine/src/ephemeral/remote.rs:1018) forgets W1. `forget_held` (:1049) leaves the state alone, so X still reads `a`.
- Nodes that join later get only C: X is empty.
- A holder that rebuilds X (`rebuild_aspect` after a validity change, or a presence drop on the aspect) loses `a`, while the others keep it.

`may_absorb` limits this to W's own commits, so W gains no new power over others' data. What breaks is convergence among holders that share a path (spec/requirements.md). Honest covers are joins by construction (notes/ephemeral.md Own covers: "dropping what it absorbs never changes a holder's state"), and nothing checks that.

Fix direction: drop an absorbed commit only if, on each of its aspects, the cover's valid fragment already contains its fragment (`j = cover; j.join(part); j == cover`, as `one_minting` does). Otherwise keep it held, so every holder computes the same join. Or rebuild the affected aspects after a drop, so that state is always the own writes joined with the valid held parts. That costs a rebuild per cover.
