# Build, test and merge workflow
> Summary: How a task goes from branch to main (warm task worktrees, one dev profile, gate in the worktree, fast-forward main), the command forms, what builds and tests should cost so you can tell when something is wrong, and a short history of the designs that were tried and dropped.

Read this if you coordinate, if a build or test run feels slow, or if disk is growing. Normal numbers on a laptop are seconds for an incremental build, under a minute for tier 1, a minute or three for the gate. If you are seeing tens of minutes, something is broken; it is not how this project builds. The numbers below are from one machine (16-thread Ryzen 7 PRO 6850U laptop, 30 GB RAM, LUKS disk); another machine scales them by a constant, and load scales them 2-5x, but the ratios between rows hold.

## Current state

**One idea:** a task is a branch in a warm worktree; the branch proves itself there; main only fast-forwards and is never built.

- **Layout**: `core/` holds the library crates in unprefixed directories with prefixed package names (`core/node` is osis-node, `core/engine` osis-engine, `core/base` osis-base); `core/test/` the test infrastructure (sim, vectors, fuzz, crdt-model, membership-model, tla); `schema/` the first-party schema files; `cli/` the CLI.
- Future projects (apps, tools) are top-level directories depending only on the `osis` crate.
- **Worktrees** (`tools/wt`): `tools/wt claim <branch> [<base>]` prints a task worktree `.worktrees/wt<N>` (gitignored, inside the repo; the tools that scan sources use explicit roots and never see it). Each has its own in-tree `target/`, kept between tasks, so a task's first build recompiles only what its branch changed: git rewrites only the files that differ, the path is the same, incremental state survives. `tools/wt release` when the branch is committed (it detaches HEAD; the branch is free to merge or delete), `tools/wt list`, `tools/wt trim [keep]`. Policy: two stay warm per device; more are created when more agents run at once and trimmed after. A new worktree builds cold once (about 80 s, 3.6 min through clippy-net). Never share a `target/` between checkouts and never build in the main checkout.
- **One profile for all per-branch work**: dev. Cargo.toml: workspace crates `opt-level = 1`, `debug = "line-tables-only"`, incremental; dependencies and osis-crypto `opt-level = 2`, no debuginfo; no `split-debuginfo` (its per-build `.dwo` files only accumulate). Debug sections are zlib-compressed at link time (`.cargo/config.toml`, Linux target): the test binaries weigh about 0.65 GB instead of 1.7 GB and backtraces keep file:line; zstd compression is not read by Rust's symbolizer, and `strip = "debuginfo"` would save another 0.3 GB at the price of frame locations. Every new combination of profile, features, `RUSTFLAGS`, `CARGO_INCREMENTAL` or target dir is another full artifact set (a `-p` subset is not: Feature unification below), so there are exactly these command forms:
  - tier 1: `cargo test --workspace` (`--no-run` to build; narrow with `--test it <module>::` and name filters; `cargo build --workspace --all-targets` and `cargo run --bin <name>` reuse the artifacts)
  - dev loop on one crate: `cargo test -p <crate>` (narrowed the same way; builds only that crate's tree, the same artifacts the workspace build uses)
  - lint: `cargo clippy --workspace --all-targets -- -D warnings` and `cargo clippy-net -- -D warnings` (the one networking feature set, 73 extra crates built once per worktree)
  - networking tier 2: `cargo test-net -- --ignored driver:: runtime:: quic relay lan` (always with filters: unfiltered it runs every ignored test of the workspace in dev, timing budgets included, which takes far longer; 25 tests, about 20 s)
  - sim: `cargo run --bin sim-sweep -- --seeds N --budget-secs T`
  - tier 2 by name: `cargo test --workspace -- --ignored <name>`; the whole set `PROPTEST_CASES=256 cargo test --workspace -- --include-ignored --skip scale:: --skip bench:: --skip budget --skip sweep`
  - release, timing only (`scale::`, `bench::`, `budget*`, cost repros in issues/): `cargo test --release -p <crate> --test it -- --ignored <filter>` (the crate holding the test), in your worktree; keep `target/release` (a few hundred MB), the next timing check is cheaper for it
- **Merge gate** (`tools/gate.sh`, in the worktree after `git rebase main`): `cargo test --workspace --locked`, the unification check (Feature unification), both clippy runs, `tools/policy.py`, `tools/spec_map.py --uncited` and `--gaps`, `cargo deny check`, then the 5-seed dev sim sweep (every scenario; seed breadth is a periodic check) when the branch touches `core/test/sim/`, osis-engine, osis-node, osis-perm, osis-crdt or Cargo.toml/lock since its merge base (the crates it has caught regressions in; `--sweep-seeds N` forces, 0 skips). Each step prints its wall time. Then `git checkout main && git merge --ff-only <branch> && git push`. `git pull --rebase` everywhere; history is linear. The generated notes/testing-map.md is gitignored, so nothing conflicts on a rebase but real edits.
- **Coordination** (worker, reviewer, fast-forward; periodic checks; the watchdog; complaints): notes/coordination.md.
- **Components pay for themselves**: with more projects in the workspace (app/, cli/, core/), iterating on one must not run the others' tests or checks. The gate selects its steps by what the branch touched (today: the sim sweep by crate; extend the same way per component), per-branch oracles and periodic checks are per component (notes/coordination.md), and the dev loop on one crate is `cargo test -p <crate>`, which builds only that crate's tree (Feature unification).
- **Waiting**: a command that may pass a few minutes runs with `run_in_background` and is awaited with `claudewait ID` (CLAUDE.md). Never a shell wait loop.
- **Nothing is swept.** A target stays flat once nothing accumulates in it. If one misbehaves, delete it and take the cold build. A change to a workspace crate's features (or its dependencies') leaves the old `incremental/` dirs behind: one worktree had 11 GB of them; delete the target after such a change.

## Feature unification
A package's features are the union of what everything in the build asks for, so `-p X` resolves differently from `--workspace` unless every crate's features are the same in both, and then rebuilds part of the tree as a second artifact set (before this was fixed, 20 of 21 packages recompiled 1-20 crates). cargo's `resolver.feature-unification = "workspace"` would do it outright but is unstable. The rules that keep it selection-invariant:
- No feature a member turns on that another build of the crate leaves off: optional features only for the networking opt-in set (osis/osis-node/osis-transport `iroh`, `lan`, `relay`, through `test-net`/`clippy-net`) and the default `driver` nobody turns off. QUIC, redb, `OsRng` and the server binary are unconditional.
- Third-party features in the `[workspace.dependencies]` table, the same for every member (tokio's set, blake3 `zeroize`, ed25519-dalek `hazmat`), not added per member; dev-dependencies add no features to a normal dependency.
- Pins: where a crate higher up enables features on a shared low dependency (quinn-proto: rand's defaults; libcrux-platform: libc's; x25519-dalek: zeroize's derive; crypto: blake3 `zeroize`), osis-base lists that dependency at the workspace's features (and crdt-model, which has no osis-base, as dev-dependencies), unused.
- Checked by the gate's `unification_check` (after the whole-workspace build, `cargo build -p <member> --all-targets` for every member from `cargo metadata` compiles nothing; 3 s when it holds). An offender: `cargo tree -e normal,build,dev --prefix none -f '{p}|{f}'` with `--workspace` and with `-p X`, diffed, names the crate and features; fix at the source by the rules above.

## What things should cost

Quiet machine, warm worktree, after the fixes this note records. If your numbers are more than about 3x these at low load, stop and find out why before doing anything else; the History section lists what it was last time.

| what | expect |
|---|---|
| no-op `cargo build --workspace` / `--all-targets` | 0.4 s / 2 s |
| one-line edit, `cargo test --workspace --no-run`: osis-node (`sync/`) / osis-engine | 2.5 s (4 crates) / 5.5 s (5 crates); before the split either was 5.5-7.5 s |
| `cargo test --workspace` tests, built | 31 s |
| edit osis-crdt or osis-base (bottom of the stack), all targets | 10-16 s |
| clippy / clippy-net after a one-line edit | 3-7 s / 3.5 s |
| clean `cargo build --workspace`; then `--all-targets`; first clippy; first clippy-net | 82 s; +53 s; +17 s; +69 s |
| osis-engine and osis-node from scratch (their incremental state gone) | 27 s: osis-node starts on osis-engine's metadata at 5 s and the two codegen in parallel (one osis-node: 40 s) |
| gate, warm, without / with the 5-seed sim sweep | about 1 / 1.5 min |
| sim sweep 5 / 30 / 300 seeds | 20 s / 2.2 min / about 20 min (5 in the gate, 300 per periodic check) |
| `core/test/tla/run.sh small` | 95 s |
| release `cargo test --release --workspace --no-run`: clean / after an edit (thin LTO relinks every test binary) | about 5 / 4 min at load 10-16; faster quiet |
| release, one crate: `cargo test --release -p osis-node --test it --no-run` clean / after an osis-node edit | 2.9 / 1.7 min at load 20-30 (no other test binary relinks) |
| `unification_check` in the gate (after the build) | 7 s |
| release timing check at 10^4: build + setup + measure | build 1.7 min after an osis-node edit; then each `scale::` test alone, `OSIS_SCALE_N=10000`, quiet box: 1-60 s of setup (`sync_aspect_pass_cost` 91 s: its 10^4-thing closure 81 s, issues/thing-creation-cost.md; `late_delta_deaths_cost` 61 s; `big_map_edit_cost` 55 s, the 10^6-key fill commit 51 s; `membership_change_and_open_cost` 49 s), each measured step milliseconds; all 14 one by one 6-7 min with the build. At load 7-25 2-3x that. In a dev build the sizes default smaller (`scale.rs` `size`): a first sync of 10^4 commits there takes 9 min (`check_unchanged` re-examines every pending commit), an edge write with 10^4 commits held 0.27 s; at the dev sizes each touched test runs 10-60 s |
| tier-2 oracles `order::arrival_order_alike_large` / `order::arrival_order_exhaustive_large` | 18 s / 2 min on 16 threads (300 / 200 seeds: 104 s / 13 min) |
| tier 2 as a whole | not measured since the perm set was sharded (2.4 min) and the budgets moved to release; the remaining single-threaded tails are the crdt decoder differentials at 1024 cases; a periodic check, never per branch |
| a task worktree's `target/` after a gate | about 5.5 GB; 6 with clippy-net; +0.7 GB release; flat afterwards (±0.1 GB per edit cycle) |
| test executables | 53 (tests and bins), about 0.65 GB with zlib-compressed debug sections; an osis-node or osis-engine edit relinks the ten above it inside the build |

Load: three cargo invocations each asking for 16 jobs on 8 physical cores reached load 60-80 (one rustc took 15 min of wall for 2.5 min of CPU). On a shared box cap jobs per invocation at the physical core count in the user-level `~/.cargo/config.toml` (`[build] jobs = 8` on this box; it changes no artifacts, so it is not a hygiene violation; never per command). Background and moved commands run at normal priority, measured: there is no idle-priority penalty, only contention.

Signs of unravelling, in the order they appeared last time: a build on a tree that was built minutes ago compiles more than the crates you touched and their dependents; `target/` dirs growing by GB per day; agents' tool calls lasting exactly 10 minutes; a "wait for X" shell loop anywhere; `--jobs`, `--release` or `--features` creeping into commands; the gate's unification check failing; a timing test running in dev.

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
