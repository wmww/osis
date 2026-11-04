# Section owner chain: quadratic key derivation per section
> Summary: `Engine::derived_through` derives a section's thing secret from every listed owner the node holds epochs of, each through the nearer part of the chain: up to MAX_OWNER_DEPTH²/2 ≈ 2000 `ActorEpochs::derived` calls per section when a writer lists one held tid 64 times (nothing rejects a repeated tid). Measured ~28 ms per section (release, six epochs per role); an 8 MiB blob holds ~7000 such sections: minutes of CPU per open at every reader, and a blob is opened several times (ingest, `genuine`, `sealed_sections`).
> Tags: security, engine

Any writer of a label can do it (its own commit, aspects on made-up tids). Fix candidates: reject an owner chain with a repeated tid (spec/wire.md §4; honest chains never repeat), and derive once along the chain from the far end, merging each member's held epochs in (`derived` is per epoch, so the result is the same set), making the cost linear in the depth.
