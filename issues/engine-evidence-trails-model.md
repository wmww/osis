# Engine evidence trails held-model
> Summary: The engine's evidence derivation (`osis_engine::evidence`) still builds per-thing leaves the design dropped (a lowering's list is whole in every copy) and lacks the keyset seed; five leaf tests are ignored and the model differential runs with the keyset seed off until A2 rebuilds the derivation.
> Priority: normal
> Tags: engine, tests

held-model's evidence is cut to notes/write-path-design.md §2 (E4, D1 to D3, D2 keysets); the engine's derivation is not (notes/redesign-plan.md: D2 is models only, A2 rebuilds evidence).
- **Leaves** (`Config::leaves`, `evidence/leaves.rs`, `LeafWhy`): built unused. The model has no leaves, so `core/engine/tests/it/evidence/a3.rs`'s five tests have no oracle and are ignored naming this issue. The A2 build deletes the leaf code and those tests.
- **Keyset seed** (notes/a3-spec/README.md Open 8): not built; `evidence/mod.rs` `derived()` compares the derivation with the model's `Rule::keysets` off. The A2/A3 build adds the seed and drops `derived()`.
