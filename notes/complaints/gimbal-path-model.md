# gimbal-path-model
> Summary: Footguns met building the roles-model `paths` module.

- `cargo test -p roles-model --lib paths::tests -- --ignored repro_` ran the ignored properties too: a filter before `--` and one after are OR'd, so the all-core `_large` tests ran outside `tools/heavy` (5 s here). One filter, after `--`.
- roles-model's `joint`, `trust` and `addenda` could not be reused for a path-judged walk (authority there is a maximum over paths, the thing the design removes), so `paths` is self-contained and has no differential.
- `tools/heavy` prints "limit heavy: unchecked (no base unit for box osprey ...)" on every run.
