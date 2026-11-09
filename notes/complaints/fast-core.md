# fast-core
- `Cargo.lock` of libs/kit needs a refresh when a core crate gains a dep (`cargo metadata --offline` in libs/kit); easy to miss.
- Tier 1 under load 25 took over 10 minutes.
- Sourcing a guibox env in a shell, then `guibox start` from it, fails ("failed to create display"): start from a fresh shell. `wl-copy` hangs a foreground call there.
