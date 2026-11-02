# ownerless (lodestar-ownerless)
- `roles_model::digest` draws every model's histories from one rng: changing `joint::random_hist` moved the edges and snapshot digests too, so the digest no longer checks those models' refactors across this change. Separate rngs per model would keep them independent.
- Adding a variant to `CreationRecord` touched about 20 hand-rolled owner-chain loops (`MAX_OWNER_DEPTH` walks in engine, ephemeral, labeling, secrets); most just want `record.owner()`. A shared chain iterator would make the next change one place.
- First design (record edge only, no `roles.0` entry) failed at the first removal: edge ops are derived from resets of known entries, so an edge with no CRDT entry cannot be removed. Worth a line in notes/permissions.md Implementation (added under Ownerless things).
- osis-node `tests/it/flows.rs` helpers (`people`, `spread`, `carry`) are private, so every role-flow test lands in that 2700-line file.
- Tier 1 took 580 s wall at load 36-52 (others' runs), against about 45 s quiet.
- Review: the box ran at load 28-38; a one-test `cargo test -p osis-node` rebuild took 183 s.
- Review: `roles-model` has no seed knob (fixed 0x5eed), so "fresh range" is impossible for it; an env var or arg would help.
