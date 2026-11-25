# Engine evidence trails held-model
> Summary: The engine's evidence derivation (`osis_engine::evidence`) lacks the keyset seed, so the model differential runs with held-model's `Rule::keysets` off; and the derivation's delete-key steps have no model oracle (held-model has no steps).
> Priority: normal
> Tags: engine, tests

- **Keyset seed** (notes/a3-spec/README.md Open 8): not built; `tests/it/evidence/mod.rs` `derived()` compares the derivation with the model's `Rule::keysets` off. The A3 build adds the seed and drops `derived()`.
- **Steps** (notes/a2-spec/README.md Open 3, 13): the derivation's step evidence (`Del`, `Step`) is checked by hand worlds only (`tests/it/evidence/steps.rs`); held-model `evidence` with steps would make it a differential.

## The derivation's input
`evidence::held` `copy_parts` reads a commit's parts from its header, not from what the node holds (`Meta::hold`): a part dropped as covered, purged or never received still feeds its path's edges and delete keys into S's evidence while the header is held. spec/permissions.md §4 derives evidence "of what the node holds … of each body under S"; decide whether a lasting header (spec/commits.md §5, must-hold) keeps its parts' evidence, then feed the derivation that. The model differential cannot see it: both the incremental and the from-scratch builds read `copy_parts` (notes/evidence-derivation.md: the engine-input adapter is not built).
