# spec-consistency
- `cargo test -- --ignored paths:: _plain` ORs its two filters: it ran every ignored `paths::` test (repro_ and `_large` included, 7 min) instead of the `_plain` ones. Name each `_plain` test.
- Finding which generators write a shape: a temporary panic in `World::put` plus the `_plain` runs answered it; there is no cheaper census of what the model's generators write.
