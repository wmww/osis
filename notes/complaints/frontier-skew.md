# frontier-skew
- `run.sh` with `TLC_KEEP_LOGS=<dir>` fails (`cp: ... Not a directory`) unless the dir exists; it does not create it.
- Started a `--release` roles-model build by reflex (notes/permissions.md says `cargo run --bin roles-model`, the dev profile is already optimized); stopped it.
- Reviewer: `roles-model -- N addenda` prints measured examples (body loss etc.) after its summary, so a `tail` of a passing run looks like a counterexample trace; read the `FAIL ...` counters on the first line.
