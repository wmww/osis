# roles-model-cleanup
> Summary: workflow snags met while trimming roles-model.

- The brief expected dead rule variants and controls; every `Rules` field, `Control` and `Policy` variant is still run by a mode, a test or a README row, so the cut came from shared helpers and test setups instead. Most of the crate's bulk is `joint`/`edges`/`trust`/`addenda` (legacy any-path models osis-perm's `walk` differentials still read): they go whole at the A1 switch, not line by line.
- tools/policy.py's code_refs resolves a doc citation's type by name across the tree: a new `lib.rs` type named `Search` broke held-model's citation of an unrelated `Search::Lists`. Pick names the tree's docs do not already cite.
- An engine scenario (`core/engine/tests/it/judgment.rs`) cites roles-model test names as `source:` strings that code_refs does not check, so deleting a model test leaves a silent dangling citation; grep for the name outside the crate before deleting.
