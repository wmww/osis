# A refused cover cannot absorb another's cover spanning a one-part aspect
> Summary: Sim `ephemeral` seed 83: node 2 (reaches only the capped s0) holds its own cover of a window's notes and state, refused at s0; s0 holds node 0's cover, which also carries another window's `/e/state`. Node 2's forced compaction skips that aspect (one held part: `compact_ephemeral_if` picks only aspects with two or more), so node 0's cover is never absorbed and deleted at s0, node 2's writes never fit and stay out (divergence at quiescence).
> Tags: node, engine, sim

- Repro: `osis_sim::replay("ephemeral", 83)` (ignored test `repro_ephemeral_seed_83` in core/test/sim/tests/it/net.rs).
- History: the seed first showed a message storm: a commit holding only `/created` of a thing the cover carries no record for was counted covered (never dropped), so `covered.len() >= 2` and `frees` passed at every refusal and a fresh cover went up and was refused thousands of times. Fixed (sim-ephemeral review): a `/created` part counts as covered only for things whose records the cover carries (`Engine::record_chain`).
- Wanted: a forced compaction for a refused own cover also picks one-part aspects whose held commit spans picked aspects, when absorbing that commit deletes an entry at the refusing server (the one-part exclusion exists to stop a lone cover being compacted into itself).
