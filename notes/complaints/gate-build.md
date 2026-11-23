# gate-build
- CPU-s on ostrich swing about 2x with load for the same build (an engine-edit replay: 553 at load 6 in its gate, 1,270 at load 16 by hand): SMT siblings share a core, so a build stage's CPU limit reads box load as well as work.
- `cargo test --timings` is the quickest way to see a build stage's critical path (target/cargo-timings/cargo-timing.html, its UNIT_DATA); nothing in notes/build.md points at it.
