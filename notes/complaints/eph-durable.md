# eph-durable
- `cargo test ... | grep` hides compile errors: a run reported exit 0 with an empty result after a test failed to compile. Grep for `^error` too.
- Dev-build ephemeral probes are very slow at load ~35: 50 single-entry expiring writes took 32 s to write and 16 s to expire (`scale::eph_leftover_memory`); measure memory in release.
- A one-line debug print in osis-engine or osis-node relinks the whole `it` binary (2-8 min at load ~20): bisecting a node-level drop with prints took five rounds. A per-thread trace hook in `costs` (named events, not only spans) would have answered in one.
- Schema-less (`Ak`) keys cannot take sequence ops (`Op::Insert` needs the writer's schema); an ephemeral list test needs a `~` aspect declared in the test schema (`common::LOG`).
