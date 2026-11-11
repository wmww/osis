# lifetimes-1
- `apply::check_rebuilt` samples ordinary joins (only at powers of four of an aspect's commits), so a debug check added there misses a broken join path in small tests: the reference index's join hook, disabled by hand, was caught only by the test's own assertion.
- `tools/gate.sh` instant stage rejects tests citing no spec section: a local index needs `spec: none` in its files' `//!` header (tools/spec_map.py); workers running only `cargo test -p` never see it.
