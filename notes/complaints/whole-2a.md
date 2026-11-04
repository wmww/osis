# whole-2a
- Tier 1 under load 35-40: the first full run took 13 min (mostly compile); `cargo test --workspace` stops at the first failing crate, so the first run hid 27 node failures behind one engine failure: use `--no-fail-fast` for a format change.
- About 20 node tests forged a commit mixing expiring and plain parts (the late-parts harness, waits/shred/parts): a format rule change lands mostly as test triage; the brief's "about 95 sites" was the easy part.
- Seed-pinned order histories depend on commit ID order, so any header byte change can silently move them (seed 34000 now ignored).
