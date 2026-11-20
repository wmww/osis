# vouch-thing
> Summary: Mishaps met while modelling and building the per-thing vouch rule.

- Ran a `cargo build --release` of roles-model by reflex before remembering the no-release rule; the searches run from the dev profile (already optimized).
- A `tools/heavy sh -c` hold running test binaries copied into the scratch dir was auto-denied by the harness; `tools/heavy cargo test`/`cargo run` (which copies the binaries itself) works.
- `cargo test ... -- --ignored paths:: _plain` ORs the filters: it ran every repro_ (failing by design) and every module's plain property, past the short lane's cap. Name the tests with `--exact`.
