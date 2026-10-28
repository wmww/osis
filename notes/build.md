# Build, test and merge workflow
> Summary: How a task goes from branch to main (warm task worktrees, one dev profile, gate in the worktree, fast-forward main), the command forms, what builds and tests should cost so you can tell when something is wrong, and a short history of the designs that were tried and dropped.

Read this if you coordinate, if a build or test run feels slow, or if disk is growing. Normal numbers on a laptop are seconds for an incremental build, under a minute for tier 1, a minute or three for the gate. If you are seeing tens of minutes, something is broken; it is not how this project builds. The numbers below are from one machine (16-thread Ryzen 7 PRO 6850U laptop, 30 GB RAM, LUKS disk); another machine scales them by a constant, and load scales them 2-5x, but the ratios between rows hold.

## Current state

**One idea:** a task is a branch in a warm worktree; the branch proves itself there; main only fast-forwards and is never built.

- **Layout**: `core/` holds the library crates in unprefixed directories with prefixed package names (`core/node` is osis-node, `core/base` osis-base); `core/test/` the test infrastructure (sim, vectors, fuzz, crdt-model, membership-model, tla); `schema/` the first-party schema files; `cli/` the CLI.
- Future projects (apps, tools) are top-level directories depending only on the `osis` crate.
- **Worktrees** (`tools/wt`): `tools/wt claim <branch> [<base>]` prints a task worktree `.worktrees/wt<N>` (gitignored, inside the repo; the tools that scan sources use explicit roots and never see it). Each has its own in-tree `target/`, kept between tasks, so a task's first build recompiles only what its branch changed: git rewrites only the files that differ, the path is the same, incremental state survives. `tools/wt release` when the branch is committed (it detaches HEAD; the branch is free to merge or delete), `tools/wt list`, `tools/wt trim [keep]`. Policy: two stay warm per device; more are created when more agents run at once and trimmed after. A new worktree builds cold once (about 80 s, 3.6 min through clippy-net). Never share a `target/` between checkouts and never build in the main checkout.
- **One profile for all per-branch work**: dev. Cargo.toml: workspace crates `opt-level = 1`, `debug = "line-tables-only"`, incremental; dependencies and osis-crypto `opt-level = 2`, no debuginfo; no `split-debuginfo` (its per-build `.dwo` files only accumulate). Every new combination of profile, `-p` subset, features, `RUSTFLAGS`, `CARGO_INCREMENTAL` or target dir is another full artifact set, so there are exactly these command forms:
  - tier 1: `cargo test --workspace` (`--no-run` to build; narrow with `--test it <module>::` and name filters; `cargo build --workspace --all-targets` and `cargo run --bin <name>` reuse the artifacts)
  - lint: `cargo clippy --workspace --all-targets -- -D warnings` and `cargo clippy-net -- -D warnings` (the one networking feature set, 73 extra crates built once per worktree)
  - networking tier 2: `cargo test-net -- --ignored [filter]`
  - sim: `cargo run --bin sim-sweep -- --seeds N --budget-secs T`
  - tier 2 by name: `cargo test --workspace -- --ignored <name>`; the whole set `PROPTEST_CASES=256 cargo test --workspace -- --include-ignored --skip scale:: --skip bench:: --skip budget --skip sweep`
  - release, timing only (`scale::`, `bench::`, `budget*`, cost repros in issues/): `cargo test --release --workspace -- --ignored <filter>`, in your worktree; keep `target/release` (a few hundred MB), the next timing check is cheaper for it
- **Merge gate** (`tools/gate.sh`, in the worktree after `git rebase main`): `cargo test --workspace --locked`, both clippy runs, `tools/policy.py`, `tools/spec_map.py --uncited` and `--gaps`, `cargo deny check`, then the 30-seed dev sim sweep when the branch touches `core/test/sim/`, osis-node, osis-perm, osis-crdt or Cargo.toml/lock since its merge base (the crates it has caught regressions in; `--sweep-seeds N` forces, 0 skips). Each step prints its wall time. Then `git checkout main && git merge --ff-only <branch> && git push`. `git pull --rebase` everywhere; history is linear. The generated notes/testing-map.md is gitignored, so nothing conflicts on a rebase but real edits.
- **Coordinator pattern**: one opus worker per issue group in a worktree; a fresh opus reviewer on the same worktree (correctness review, small fixes committed on the branch, the tier-2 oracles for the area, then the gate); the coordinator fast-forwards main. At most three agents at once; three compiling put a 16-thread laptop at load 20-30.
- **Waiting**: a command that may pass a few minutes runs with `run_in_background` and is awaited with `claudewait ID` (CLAUDE.md). Never a shell wait loop.
- **Nothing is swept.** A target stays flat once nothing accumulates in it. If one misbehaves, delete it and take the cold build.

## What things should cost

Quiet machine, warm worktree, after the fixes this note records. If your numbers are more than about 3x these at low load, stop and find out why before doing anything else; the History section lists what it was last time.

| what | expect |
|---|---|
| no-op `cargo build --workspace` / `--all-targets` | 0.4 s / 2 s |
| edit osis-node, `cargo test --workspace`: build / tests | 8 s / 31 s |
| edit osis-crdt or osis-base (bottom of the stack), all targets | 10-16 s |
| clippy / clippy-net after a one-line edit | 3-7 s / 3.5 s |
| clean `cargo build --workspace`; then `--all-targets`; first clippy; first clippy-net | 82 s; +53 s; +17 s; +69 s |
| gate, warm, without / with the sim sweep | about 1 / 3 min |
| sim sweep 5 / 30 / 300 seeds | 20 s / 2.2 min / about 20 min |
| `core/test/tla/run.sh small` | 95 s |
| release `cargo test --release --workspace --no-run`: clean / after an edit (thin LTO relinks every test binary) | about 5 / 4 min at load 10-16; faster quiet |
| tier-2 oracle `order::arrival_order_alike_large` | about 2 min |
| tier 2 as a whole | over 25 min: a few single-threaded tests run alone at the tail of each binary; run it in the background, once per round |
| a task worktree's `target/` after a gate | about 5.5 GB; 6 with clippy-net; +0.7 GB release; flat afterwards (±0.1 GB per edit cycle) |
| test executables | 32, about 0.8 GB; an osis-node edit relinks the ten above it inside the 8 s build |

Signs of unravelling, in the order they appeared last time: a build on a tree that was built minutes ago compiles more than the crates you touched and their dependents; `target/` dirs growing by GB per day; agents' tool calls lasting exactly 10 minutes; a "wait for X" shell loop anywhere; `--jobs`, `--release`, `-p` or `--features` creeping into commands; a timing test running in dev.

## History (what was tried, briefly)

Three worktree designs preceded this one, all measured on a 4-core box shared with other agents:

1. **Seeded per-task worktrees**: a new worktree's `target/` hardlinked from the main checkout's by a post-checkout hook. Fast when the seed was fresh, but a changed core crate still compiled in full, the hook failed silently when main was mid-build, and a seed from a stale main rebuilt 83 crates. Dropped.
2. **One shared build checkout behind a queue** (`tools/b`, commit 691c11d): rsync the worktree's sources into one build tree with fresh mtimes on changed files, flock, run cargo there. Correct and as fast as a warm worktree, one target on the box; but the lock had to be held through test runs (tests read fixtures through the manifest dir baked in at compile time), so a sweep or tier-2 run blocked everyone, and outputs written into the tree stayed on the build side. Dropped for serialization, not correctness. Note: pointing two checkouts at one `CARGO_TARGET_DIR` is a different thing and is unsafe (cargo keys artifacts without the path and judges freshness by mtime: measured, a tree read as fresh with the other tree's code inside).
3. **Slots** (`tools/slot`, `../osis-wt/slotN`) with warm in-tree targets, plus `tools/sweep.sh` after every gate to delete orphaned artifacts: the design just before this one, and the right shape. What went wrong around it, found by measuring on a quiet box against the logs of a day's work:
   - The sweep counted a crate's build unit and its clippy check unit as one, kept the newest incremental dirs (clippy-net's, the last step) and deleted the build's. Every gate on main then compiled every changed crate from scratch: 16x the CPU, 4-7 min builds at load that should have been 10-60 s.
   - `split-debuginfo = "unpacked"` left a `.dwo` per rebuild in `deps/`, which neither cargo nor the sweep deleted: 2.7-5 GB per slot, three slots at 35 GB against 5.4 GB fresh.
   - Agents waited for background jobs in shell loops with guessed conditions (`until grep -q PATTERN log`, `until ! pgrep -f PATTERN` which matches its own shell) that hit the 10-minute Bash cap: 21-109 min per agent, orphaned loops running for hours. Replaced by `claudewait`.
   - Release timing builds ran under load (12-24 min each) and `target/release` was deleted after every one.
   - Dev-profile timing budgets sat in tier 2, so the whole set took over 40 min on one core.
   - The gate on main repeated the build the reviewer had just done in the slot.

The current design is slots with the slot renamed, moved inside the repo, the sweep and split-debuginfo gone, the gate moved to the worktree, and waiting done by one tool.
