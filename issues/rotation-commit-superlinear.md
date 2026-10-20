# Committing a rotation of a large roster is superlinear
> Summary: A read+write rotation commit for a roster of N writers takes 0.16 s at N = 100 and 29 s at N = 1000 (sealing is 0.3 s of it); the commit bytes are linear (2.7 KB per member) but the engine's commit path is about O(N^2) in path ops on one aspect. Rosters of thousands are a requirement (spec/requirements.md, Scale).
> Tags: performance, node, crdt

Repro: `cargo test --release -p osis-node --test scale roster_removal_cost -- --ignored --nocapture` (one `Mutation` of 2(N-1) `/secrets` box sets plus history and `/keys`).

| roster | commit bytes | per remaining member | seal | `Engine::commit` |
|---|---|---|---|---|
| 100 | 272 KB (2 blobs) | 2747 B | 36 ms | 0.16 s |
| 1000 | 2.70 MB (32 blobs) | 2707 B | 0.29 s | 28.7 s |

Not profiled. Likely the per-path-op cost on a growing map state (each op clones or rescans the joined map, notes/crdt.md "Not yet"), i.e. the same root as issues/node-state-not-paged.md; a batch of path ops on one aspect should apply in one pass.
