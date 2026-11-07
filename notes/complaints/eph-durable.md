# eph-durable
- `cargo test ... | grep` hides compile errors: a run reported exit 0 with an empty result after a test failed to compile. Grep for `^error` too.
- Dev-build ephemeral probes are very slow at load ~35: 50 single-entry expiring writes took 32 s to write and 16 s to expire (`scale::eph_leftover_memory`); measure memory in release.
