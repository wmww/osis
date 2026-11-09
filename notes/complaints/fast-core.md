# fast-core
- `Cargo.lock` of libs/kit needs a refresh when a core crate gains a dep (`cargo metadata --offline` in libs/kit); easy to miss.
- Tier 1 under load 25 took over 10 minutes.
