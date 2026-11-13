# Absolute checkout paths baked into low crates defeat shared build caches
> Summary: `env!("CARGO_MANIFEST_DIR")` in osis-base (`testenv.rs` `KNOWN_FILE`) and osis-vectors (`root()`) puts the worktree's absolute path into library output, which likely makes every dependent miss a content-addressed build cache shared across worktrees. Unvalidated here; matters only if a shared cache is adopted.
> Priority: low
> Tags: build, tests, performance

- **Unvalidated.** Measured outside this repo on scratch clones with kache 1.2.2 (`cargo test --workspace --no-run`, a second worktree's first build): unpatched 71% of crates from cache (workspace crates missed); the two library sites patched and a cache-only config, 98% (misses: the `it` test binaries). The two runs also differ in kache config, so the path fix was not isolated.
- **Where**: library code (reaches dependents): `core/base/src/testenv.rs` `KNOWN_FILE` (compiled into the lib, not behind `cfg(test)`), `core/test/vectors/src/lib.rs` `root()`. Test code (leaf cost only): `CARGO_MANIFEST_DIR` in `core/schema/tests/it/codegen.rs`, `cli/tests/it/cli.rs`; `CARGO_TARGET_TMPDIR` in `core/node/tests/it/memory.rs`, `cli/tests/it/cli.rs`, `cli/tests/it/localhost.rs`.
- **Why it cascades**: a cache key covers each `--extern` dependency's contents, so a per-checkout osis-base output changes every key above it.
- **Untested side effect**: `known()` reads `KNOWN_FILE` at run time, so a test binary run after its worktree is gone panics with `reading {KNOWN_FILE}`, and otherwise reads that checkout's file.
- **To validate**: build one commit in two checkouts with `--remap-path-prefix` mapping both roots to one path and confirm libosis_base's rlib differs by the baked path; confirm it does not once the two sites are fixed; compare hit rates with one fixed cache config.
- **Fix**: find the repo root at run time. Not a cwd-relative path (a dependent's tests run elsewhere), not a run-time `CARGO_MANIFEST_DIR` (the dependent's directory), not `include_str!` (`KNOWN_FILE` is read at run time so adding a name rebuilds nothing). A policy check could then keep these macros out of library code.
