# Absolute checkout paths baked into low crates defeat shared build caches
> Summary: `env!("CARGO_MANIFEST_DIR")` in osis-base (and osis-vectors) puts the worktree's absolute path into compiled output, which likely makes every dependent miss a content-addressed build cache in another worktree. Found by a Claude outside this project and not yet validated here.
> Priority: low
> Tags: build, tests, performance

- **Provenance: unvalidated.** A Claude working outside this project wrote this while experimenting with shared Rust build caches, on scratch clones at `f32242bd`, knowing only the code and notes/build.md. Validate before acting on it. Its raw logs and `path-fix.patch` (under `/home/ai/rust-builds/`) are gone from this machine; the steps below reproduce what matters.
- **No effect on today's workflow as far as tested.** Each worktree has its own `target/`, so cargo builds work as usual. This matters only if worktrees or machines are to share build outputs through a cache, or if a binary outlives its checkout.
- **Where (library code, reaches dependents):**
  - `core/base/src/testenv.rs:10`: `KNOWN_FILE`, in the bottom crate, compiled into the lib rather than behind `cfg(test)`, so everything above it is affected.
  - `core/test/vectors/src/lib.rs`: `root()`.
- **Where (test code, a leaf cost only):**
  - `CARGO_MANIFEST_DIR`: `core/schema/tests/it/codegen.rs` (`DIR`), `cli/tests/it/cli.rs:466,492`.
  - `CARGO_TARGET_TMPDIR`, also an absolute path: `core/node/tests/it/memory.rs` (`big_map_apply_memory`), `core/label/tests/it/scale.rs:61`, `cli/tests/it/cli.rs:60`, `cli/tests/it/localhost.rs:40`.
- **Why it would cascade:** a cache key covers the contents of each `--extern` dependency. If osis-base's output differs per checkout, every crate above it gets a different key, and that repeats up the graph.
- **Observed**, with kache 1.2.2 as the cache and `cargo test --workspace --no-run` (CPU-seconds, single runs, load 30-130, so compare ratios only):

  | First build in a second worktree | Crates from cache | CPU-s |
  |---|---|---|
  | Unpatched, kache defaults | 71% (workspace crates missed) | 2481 (cold: 2986) |
  | The two library sites patched, kache cache-only config | 98% (remaining misses: `it` test binaries) | 328 (cold: 3298) |

  **These two runs also differ in kache config, so the path fix is the likely cause but was not isolated.** Neither run's restored artifacts were put through the test suite.
- **Related, from reading the code and not tested:** `known()` reads `KNOWN_FILE` at run time, so a test binary run after its original worktree is gone should panic with `reading {KNOWN_FILE}`, and otherwise reads that checkout's file. notes/build.md describes copying test binaries for long runs, so this may be reachable there.
- **To validate:**
  1. Build the same commit in two checkouts with `--remap-path-prefix` mapping each root to one path, and confirm libosis_base's rlib differs because of the baked path (it stayed byte-identical across directories for a tiny test crate using that flag).
  2. Confirm it no longer differs once the two library sites are fixed.
  3. Using kache or a similar cache with one fixed config, compare new-worktree hit rates with and without the fix.
- **Fixing it is not as simple as the patch.** `path-fix.patch` was only for measuring builds and shouldn't be applied: it makes `KNOWN_FILE` relative to the cwd, and a run-time `CARGO_MANIFEST_DIR` gives the dependent's directory when another crate's tests run. `KNOWN_FILE` is read at run time on purpose, so that adding a variable name rebuilds nothing (see its doc comment); `include_str!` would avoid the path but give that up. Finding the repo root at run time keeps both properties. A policy check could then keep these macros out of library code.
- **Priority depends on a shared cache being adopted.** That isn't decided; it's still being evaluated outside this repo.
