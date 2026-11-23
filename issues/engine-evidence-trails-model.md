# Engine evidence trails held-model
> Summary: The engine's evidence derivation (`osis_engine::evidence`) lacks the keyset seed, so the model differential runs with held-model's `Rule::keysets` off; and the derivation's delete-key steps have no model oracle (held-model has no steps).
> Priority: normal
> Tags: engine, tests

- **Keyset seed** (notes/a3-spec/README.md Open 8): not built; `tests/it/evidence/mod.rs` `derived()` compares the derivation with the model's `Rule::keysets` off. The A3 build adds the seed and drops `derived()`.
- **Steps** (notes/a2-spec/README.md Open 3, 13): the derivation's step evidence (`Del`, `Step`) is checked by hand worlds only (`tests/it/evidence/steps.rs`); held-model `evidence` with steps would make it a differential.
