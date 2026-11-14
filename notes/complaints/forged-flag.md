# forged-flag
- Sampling one law over 50 `OSIS_CRDT_SEED` values means 50 runs of the whole crdt lib binary filtered to one test (about 2.5 s each, over 2 min in all); a seed-list env var for one test would make this one run.
- The model crates are named `crdt-model`/`held-model`, not `osis-*`: the first `cargo test -p osis-crdt-model` fails to match.
