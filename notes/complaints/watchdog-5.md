# watchdog-5
- cargo-llvm-cov over osis-sync, osis-engine and osis: about 14 min under tools/heavy at load ~35 (instrumented build plus tests); its own target dir (target/llvm-cov-target) is several GB, removed after.
- `git stash list` is refused by the permission rules even read-only; fine, but surprising.
