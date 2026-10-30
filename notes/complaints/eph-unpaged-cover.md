# eph-unpaged-cover
- Two background cargo runs started together (tier-2 oracle and sim sweep) serialize on the build lock; harmless, but the sim sweep's 5 min ran alongside the 10 min oracle at full CPU.
- Reviewer: background `cargo test ... ; echo exit $?` reported `exit 0` over a failed oracle (the echo's exit): read the `test result` lines, as notes/build.md says. No `perf` on the box (paranoid 2, no binary): profiling meant temporary `costs::span`s.
