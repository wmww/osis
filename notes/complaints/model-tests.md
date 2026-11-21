# model-tests complaints
> Summary: Footguns met consolidating roles-model's and held-model's tests.

- A citation check limited to notes/ and issues/ misses osis-perm: 102 of roles-model's `paths/tests.rs` hand-world names are cited by `core/perm/tests/it/paths/hand*.rs` (perm mirrors them by name). Grep `core/` too before merging or renaming a model test.
- Swapping a test helper for a "superset" one (spec_evidence's `fails` for spec_open10's) passed the default tests and failed a `_plain` property (P10 is OPEN 10's, failing under plain `Rule::fixed`): run the crate's `_plain` properties before committing a helper change, not only `cargo test -p`.
