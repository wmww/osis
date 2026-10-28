# order-harness
- Box at load 30-80 from other agents for most of the task: tier-1 and tier-2 timings swing 2x; compare CPU-s (`/usr/bin/time`) not wall.
- My first exhaustive run nested a thread per core inside 4 seed threads (64 threads, load 80): `run` now splits cores between seeds and a seed's orders.
- `cargo test` blocks briefly on the package-cache lock while another cargo in the same worktree runs a test binary; harmless.
