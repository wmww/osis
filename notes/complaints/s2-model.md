# s2-model
- `tools/policy.py` reports a path cited in a note as "no such path in the code" while the file is still untracked: `git add` new files before running it.
- Adding a field to held-model's `Aspect` or `Held` breaks osis-engine `tests/it/held.rs` (struct literals): a model-only brief still touches the engine's test adapter.
