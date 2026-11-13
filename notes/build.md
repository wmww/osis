# Build
> Summary: Repo layout, task worktrees, the one dev profile and the fixed command forms, feature unification, the heavy lock, time limits (the table tools/limits.py reads), footguns, scripted renames, disk upkeep, and what builds and tests should cost so you can tell when something is wrong. The merge gate: notes/gate.md.

A task is a branch in a warm worktree; the branch proves itself there (notes/gate.md); main only fast-forwards and is never built. Much past What things should cost means something is broken. Process (worker, reviewer, release checks, watchdog): notes/coordination.md.

## Layout
- `core/` holds the library crates in unprefixed directories with prefixed package names (`core/node` is osis-node); `core/test/` the test infrastructure (sim, vectors, fuzz, crdt-model, roles-model, held-model, tla); `libs/` what some but not all users of osis want (`libs/chat` osis-chat, core; `libs/kit` osis-kit, GUI); `schema/` the first-party schema files; `cli/` the CLI. Further projects are top-level directories depending only on the `osis` crate.
- **One workspace** (root `Cargo.toml`): one `Cargo.lock`, one `deny.toml`, one `target/`, one copy of osis. `default-members` is core, so a bare `cargo build`/`test`/`clippy` never compiles the GUI. The GUI (`libs/kit/` osis-kit, `app/` osis-app, `app/android` osis-android) builds only when named with `-p`; `--workspace` means core and GUI. Its `[patch]` entries (libs/kit/patches/, vendored, not members) are in the root manifest. The GUI build reuses core's artifacts (Feature unification); its own first build is about 3 min, 1250 CPU-s (wgpu, Vello, winit). Core depends on nothing in it; it depends on `osis`, `osis-schema` and `osis-chat` only.

## Worktrees
`wt` (reasonable-rust-builds plugin): `wt claim <branch> [<base>]` prints a task worktree `.worktrees/wt<N>` (gitignored; tools that scan sources use explicit roots and never see it), with its own `target/` kept between tasks, so a task's first build recompiles only what its branch changed. `wt release` when the branch is committed (prunes the target, detaches HEAD), `wt list`, `wt trim [keep]`. A new worktree builds cold once (about 80 s).
- Never share a `target/` between checkouts (`CARGO_TARGET_DIR`): cargo keys artifacts without the path and judges freshness by mtime, so one tree reads as fresh with the other tree's code inside. Never build in the main checkout.
- Rejected: hardlink-seeded worktrees (a seed from a stale main rebuilt everything); one shared build checkout behind a lock (tests read fixtures through the manifest dir baked in at compile time, so it stays locked through test runs and serializes everyone).

## Profile and command forms
Dev profile for all branch work (Cargo.toml): workspace crates `opt-level = 1`, `debug = "line-tables-only"`, incremental, `lto = "off"` (Tess's call); dependencies and osis-crypto `opt-level = 2`, no debuginfo; build-time code (`[profile.dev.build-override]`) without debug assertions, which keeps build-time units apart (Feature unification). No `split-debuginfo`: its per-build `.dwo` files pile up (GBs per worktree). `.cargo/config.toml` zlib-compresses debug sections at link (test binaries about 40% of their uncompressed size, backtraces keep file:line; Rust's symbolizer cannot read zstd) and sets the test env (`PROPTEST_CASES=32`, `PROPTEST_DISABLE_FAILURE_PERSISTENCE`: Footguns).

Every new combination of profile, features, `RUSTFLAGS`, `CARGO_INCREMENTAL` or target dir is another full artifact set (a `-p` subset is not: Feature unification), so there are exactly these forms:
- **Default tests**: `cargo test --no-fail-fast` (without it cargo stops at the first failing binary and hides every later crate's failures); `--no-run` to build. `cargo build --all-targets` and `cargo run --bin <name>` reuse the artifacts.
- **One crate**: `cargo test -p <crate>`, narrowed with `--test it <module>::` and name filters after `--`. Never `--test it <filter>` without `-p`: it prints a `0 passed` line for every other crate's `it`, hiding the one that ran.
- **Lint**: `cargo clippy --all-targets -- -D warnings`. GUI: `cargo clippy -p osis-kit -p osis-app -p osis-android --all-targets -- -D warnings` (right after core's clippy it re-lints only kit and app; a `cargo check` instead re-checks every osis crate in a unit set apart from clippy's), `cargo test -p osis-kit -p osis-app`, `cargo run -p osis-app -- DIR`.
- **A property or by-hand test by name**: `cargo test -p <crate> --test it -- --ignored <name>` (or `cargo test --tests -- --ignored <name>`: `--tests` skips the doctests). Seeds and env vars: notes/test-harnesses.md.
- **Sim**: `cargo run --bin sim-sweep -- --seeds N --budget-secs T` (notes/test-sim.md).
- **Networking** (by hand): `tools/heavy cargo test --no-fail-fast --tests -- --ignored driver:: runtime:: quic relay lan --skip repro_`, always filtered (unfiltered it runs every ignored test; a `repro_` fails by design).
- **Release**: never inside a task (scaling is checked by counting work: notes/test-scale.md). Memory checks and `cargo bench` are the coordinator's, alone: `cargo test --release -p <crate> --test it -- --ignored <filter>`.
- **Old vs new**: `tools/bin-at REV OUT [--release] [-p CRATE] [--test NAME | --lib CRATE] [--patch FILE]... [--take PATH]...` builds REV's test binary in your worktree and copies it to OUT (default osis-node `it`; `--lib osis-engine`: its unit-test binary, run it from `core/engine`). A new test against an old REV: `--take core/node/tests/it/x.rs` (root-relative) or `--patch FILE` (a `git diff`), undone after. Needs a clean tree (wip-commit); checks REV out detached and your branch back (also on failure); the next build recompiles what REV changed. The binary keeps your worktree's manifest dirs, so fixtures are read from the checked-out tree. Refuses the main checkout. Compare under `tools/icount` (notes/test-harnesses.md, Measuring).
- **Jobs**: capped per invocation at the physical core count in the user-level `~/.cargo/config.toml` (`[build] jobs = N`; changes no artifacts), never per command: three invocations each asking for 16 jobs on 8 cores reached load 60-80. Agent shells run at nice 12 (`ps -o ni,cls -p $$`).
- **Scheduler**: `system76-scheduler` (Pop!_OS, `com.system76.Scheduler.service`) must be off (`sudo systemctl disable --now` and `mask`; an OS upgrade re-enabled it once): at its 60 s refresh it puts `cargo`, `rustc`, `ld` and all they spawn after in SCHED_IDLE, so a cargo run outliving a refresh crawls beside any other run (10-30x the wall at normal CPU-s; short builds escape). Unprivileged processes cannot leave SCHED_IDLE; `nice`/`chrt` wrappers don't help. Check: `ps -eo pid,cls,ni,comm | grep -E 'cargo|rustc'` shows `IDL`; the gate warns while the service runs.

## Feature unification
A package's features are the union of what everything in the build asks for, so `-p X` resolves differently from `--workspace` unless every crate's features are the same in both, and then rebuilds part of the tree as a second artifact set (cargo's `resolver.feature-unification = "workspace"` would fix it but is unstable). The rules that keep it selection-invariant:
- No feature a member turns on that another build of the crate leaves off: optional features only for the default `driver` nobody turns off. QUIC, the LAN loop, redb and `OsRng` are unconditional.
- Third-party features go in `[workspace.dependencies]`, the same for every member (tokio's set, blake3 `zeroize`, ed25519-dalek `hazmat`); dev-dependencies add no features to a normal dependency.
- Pins: where a crate higher up enables features on a shared low dependency (quinn-proto: rand's defaults; libcrux-platform: libc's; x25519-dalek: zeroize's derive; the GUI stack: bitflags `serde`, num-traits `libm`, tracing defaults), osis-base lists that dependency at the workspace's features, unused (crdt-model, which has no osis-base, as dev-dependencies). The reverse for the GUI: osis-kit pins regex-syntax at proptest's defaults. The pins cost core builds a few small crates once.
- Build-time units never share a unit with run-time ones: `[profile.dev.build-override]` gives them a profile of their own. Without it cargo merges a build-time and a run-time unit of the same crate when profiles and features match, the merged unit takes the run-time `lto = "off"`, and which crates merge depends on the selection (unicode-ident is a run-time dependency of naga, so in GUI builds only): a GUI build would compile every osis crate a second time. `[profile.dev.package."*"]` and `build-override` cannot set `lto`, and pinning unicode-ident would hold only until the next such crate; dropping `lto = "off"` would also fix it (Tess's call). Cost: about 20 small crates built once per side.
- Checked by the gate's unification check (only when a manifest, the lock or `.cargo/` changed): after `cargo build --workspace --all-targets`, `cargo build --all-targets` and `cargo build -p <member> --all-targets` for every member compile nothing. An offender: diff `cargo tree -e normal,build,dev --prefix none -f '{p}|{f}'` with `--workspace` and with `-p X`; fix at the source by the rules above. Same features but a different fingerprint `profile` hash is a per-unit profile difference: compare the unit's rustc line in `cargo build -v` of each selection.

## Heavy lock
`tools/heavy [--limit NAME] <cmd...>` runs a command under the box-wide lock (`$XDG_RUNTIME_DIR/osis-gate.lock`, flock): the gate's tests (one hold per gate), release checks, by-hand property and sim runs at size, TLC and roles-model runs. Two all-core runs at once each take about twice as long, so neither finishes sooner.
- Unlocked: builds and single-crate test runs, and anything that cannot use every core (a one-seed replay, a one-worker TLC, a TLC instance checking liveness, `tools/icount` at a few threads). Build every variant first and take the lock only for the all-core run: a lock wait is often 10+ min, so a seconds-long run under it costs an agent a quarter hour.
- The command sees `HEAVY_HELD=1`; a `tools/heavy` inside a hold refuses (it would wait on itself).
- Log: `~/.cache/osis/heavy.log` (JSON lines: who, command, wait, hold, CPU-s, the box's /proc/stat counters). `tools/heavy --report [--since HOURS]` lists runs and utilization; `tools/agent-times.py [--long N] [--since HH:MM|ISO|commit]` charges each agent its lock wait, hold, CPU-s and time by kind.

## Time limits
Every timed run has a CPU limit (tight: other work barely moves CPU-s) and a wall limit (looser: it also catches waiting, idle cores, a demoted process), as multiples of the box's base unit `u` (policy: notes/coordination.md, Time limits). `u` is the CPU-s of one fixed work quantum of `tools/baseunit.c` with every hardware thread busy; a CPU limit is `k u`, a wall limit `k u 16/threads`. Measure a box's with `tools/heavy tools/limits.py unit` (median of 5; varies 2-4% with load) and add its row. `tools/limits.py` reads both tables below: keep their shape.

`gate` and `gate.hold` are Tess's 5-minute cap, never raised. Every gate stage is a share of one of them (`share of`), each whole's shares summing to at most it with 1 u wall and 10 u CPU left for the steps between (`tools/limits.py split`, a gate instant check), so a gate over its cap names the stages over their share. The shares follow ostrich's cost when set and are all under what their stage takes today, so gates hit them until issues/gate-five-minutes.md is done: such hits belong to that issue. A hit is reported and logged, never fatal.

| box | unit (CPU-s) |
|---|---|
| fastbox-0 | 1.69 |
| ostrich | 2.3 |

| limit | CPU (u) | wall (u) | share of | what (fastbox-0, median of recent runs: CPU-s / wall at load) |
|---|---|---|---|---|
| `test` | 4.5 | 6.5 |  | one default test alone (`tools/limits.py tests`): over 10 s needs a reason |
| `rebuild` | 70 | 13 |  | an osis-base edit, `cargo build --all-targets` (`tools/limits.py run rebuild cargo build --all-targets`) |
| `build` | 55 | 10 | `gate` | the gate's builds: 207 / 44 s; after a rebase over a day of main up to 1000 / 200 s |
| `default-tests` | 700 | 50 | `gate.hold` | `cargo test --no-fail-fast`, built: 1190 / 123 s at load 16 |
| `gate.checks` | 5 | 3 | `gate` | the instant checks: 3 / 3 s |
| `gate.clippy` | 20 | 4 | `gate` | core clippy, warm: 15 / 5 s |
| `gate.gui-lint` | 5 | 1 | `gate` | the GUI's clippy after core's: 4 / 2 s |
| `gate.unify` | 20 | 3 | `gate` | the unification check: 241 / 13 s |
| `gate.deny` | 5 | 1 | `gate` | schema check, deny, core bans: 3 / 2 s |
| `gate.properties` | 530 | 34 | `gate.hold` | the selected properties: 705 / 54 s at load 35 (every crate: 43 tests) |
| `gate.sim` | 410 | 20 | `gate.hold` | every sim scenario at 15 seeds: 695 / 56 s at load 26 |
| `gate.gui-tests` | 10 | 2 | `gate` | GUI tests: 72 / 20 s |
| `gate.hold` | 1650 | 105 | `gate` | the gate's one heavy-lock hold: 2580 / 246 s at load 25 |
| `gate` | 1780 | 130 |  | the whole gate but its lock wait: 2920 / 338 s at load 24; 5 minutes wall is Tess's cap, its CPU what 5 minutes at the box's usual 85% busy allows |
| `heavy` | 2200 | 260 |  | any other heavy-lock hold |

- `tools/limits.py check NAME CPU WALL` prints `limit NAME: CPU a/b s, wall c/d s`, a `LIMIT NAME ...` line per limit exceeded (`over 2x` starts an investigation), and appends to `~/.cache/osis/limits.log`; it never fails the run. The gate checks each stage and itself (its lock wait left out); `tools/heavy` checks each hold (`--limit NAME`, default `heavy`). A whole over its limit prints `over its share of WHOLE:` for each part over its share.
- `tools/limits.py run NAME CMD` wraps a by-hand run; `tools/limits.py tests [--jobs N]` runs every default test as its own process and times again alone those past half the `test` limit (under the lock, about half an hour); `tools/limits.py table` prints every limit in seconds on this box; `tools/limits.py summary [--since H] [--all]` lists the box's hits, flags investigation triggers and prints the hits notes/time-limits.md lacks, in its format, to be added with their reasons.

## Footguns
- **Waiting**: a command that may pass a few minutes runs with `run_in_background`, awaited with `claudewait ID`. Never a shell wait loop, never `timeout` around cargo (it kills a test run with a green-looking log; a build killed mid-link leaves the crate unable to link). A foreground call past 120 s moves to the background and its later steps keep running: keep edits and reverts out of a call that may run long.
- **Exit codes**: `cmd > log; echo exit $?` ends with the echo's status, and a pipe through `tee`/`grep`/`tail` reports the pipe's: end a wrapper with the command's code and read the `test result` / `== gate passed` lines. A background run writing `> $D/x.log` into a dir not made yet fails at once: make it in an earlier call. `git rebase --exec` runs under dash (no `${PIPESTATUS}`).
- **Runs that test nothing and say ok**: a misspelled `--exact` name or seed env var, `--ignored --exact` on a test that is not ignored, `OSIS_SIM_ONLY=` set empty (read the `N runs` line). Check for `1 passed` and the printed seed range; oracle names carry a `_spec_*` suffix (`--list --ignored` shows them). Several libtest filters go after `--`. A `repro_` test fails by design: read test names, not the exit code.
- **Captured output**: libtest captures a passing test's output, threads it spawns included: an `eprintln!` probe shows nothing without `-- --nocapture` (misread as "never reached" a dozen times). A line written straight to the stream (`let _ = writeln!(std::io::stderr(), ..)`, as `testenv::visible` does) is never captured. A throwaway probe variable is named `OSIS_PROBE_*`: testenv refuses any other `OSIS_*` name missing from core/base/testenv-known.txt, and tools/policy.py fails while a probe is left in the sources.
- **Proptest**: `.cargo/config.toml` sets `PROPTEST_CASES=32`, which overrides a test's own `cases:` (deep runs pass `PROPTEST_CASES=N`), and `PROPTEST_DISABLE_FAILURE_PERSISTENCE` (no `proptest-regressions` files written or replayed). A test binary run outside cargo has neither: it runs 256 cases unless you set both.
- **Editing under a running build**: editing sources (or `git show rev:path > path`) while a background cargo runs builds the half-edited tree. For a chain of oracle runs build once and run a copy of the test binary: `cargo test -p <crate> --test it --no-run` prints the `Executable` path relative to the worktree root; `test -x` the copy first. `--message-format=json` lists sim-sweep's executable too: pick `/deps/it-`.
- **git**: `git checkout <file>` to undo a temporary edit drops the file's uncommitted work: wip-commit first. Squash with `git reset --soft $(git merge-base HEAD main)` (`reset --soft main` after main moved stages a revert of main's newer commits); `git diff $(git merge-base HEAD main)`, not `git diff main`. Never `git stash` (shared by every worktree).
- **Broken link** after a stopped build (`rust-lld: undefined hidden symbol anon.*`): `cargo clean -p <crate>` for the crate whose rlib the error names (deleting only its `incremental/` dirs left the bad rlib in place), then rebuild.
- **Clippy says `Compiling`** for osis-engine, osis, osis-chat, osis-kit and osis-app after an edit that reaches their build scripts: clippy builds a member's build script and its build-dependencies with clippy-driver, as units apart from `cargo build`'s. Once per edit, a few CPU-s; it is how build.rs gets linted.
- **Processes**: `pkill -f`/`pgrep -f` match the Bash tool's own `bash -c` wrapper and kill the caller, and other agents' test binaries look alike: stop your own background task with TaskStop.
- **grep** in agent shells may be Claude Code's ugrep shim, which rejects bounded repeats (`.\{0,150\}`): use `command grep` or python.
- **A load-dependent flake**: pin the test to few cores (`taskset -c 0-1 <copied binary> ...`); don't spin CPU burners (they load every other agent's gate).
- **Permission prompts** stall unattended agents: stay inside your worktree and scratch dir, absolute paths instead of `cd` in compound commands; no sudo, network fetches, writes outside the repo or scratchpad, killing processes you did not start, or `git worktree add` (use `wt`). Write files with the Write tool, not heredocs plus `chmod`/`rm`; never `rm` in the scratchpad (use fresh names).
- Test harness traps: notes/test-harnesses.md, Harness footguns.

## Scripted renames
Every reviewer of a scripted rename sweep found over-matches the worker's old-word hunt missed. Before running: list files holding both the old and the new word (shadowing, colliding names); protect third-party and other-sense names as exact tokens in every case (`x`, `X`, `X_Y`) with word boundaries (`/members(?!\w)`, not a prefix); filter paths with `git ls-files | grep -v`, not `':!path'` pathspecs (one silently matched nothing); print each rule's hit count, every rule must hit. After: hunt the new word as well as the old (`REHOLDERED`), census short forms (`sv`, `srv`), read the token pair table `tools/rename-table [REV | A..B | -]` (no argument: merge base to working tree; `count  old -> new  first-file`); same-token sense errors still need reading. TLA junction lists are indentation-sensitive: realign `/\` bullets and compare `run.sh <module>` state counts.

## Disk
- `wt release` prunes `<wt>/target`: it runs `.claude/wt-mark` (every standard command; the GUI's only where the GUI was built before; add a new standard command there too), then deletes every unit not used since, and in `incremental/` keeps the newest session per dir. No cold builds result.
- It needs a filesystem that records access times: on `noatime` it prints `wt: this filesystem doesn't record access times (noatime): targets not pruned` and targets only grow. `relatime` works (`findmnt -T .`).
- A warm target settles at 11-15 GB. Between rounds, `tools/prune-incremental.sh [hours]` (from any checkout; default 3 h) removes incremental sessions untouched that long from claimed worktrees and prints what it freed. A worktree over 15 GB where no cargo runs: keep only the newest incremental session per crate dir (what rustc does next anyway, no rebuild): `python3 -c 'import glob,os,shutil,sys; [shutil.rmtree(s) for d in glob.glob(sys.argv[1]+"/target/*/incremental/*/") for s in sorted((x for x in glob.glob(d+"s-*") if os.path.isdir(x)),key=os.path.getmtime)[:-1]]' .worktrees/wtN`. Past 20 GB delete the target. `wt trim` is not the cure: the next claim builds cold.
- A `libs/kit/target` in a worktree is dead (no workspace is rooted there; wt never prunes it): delete it.
- A full disk reads as a compile error (`failed to write query cache`, `failed to parse process output`): `df` before believing a build failure. A `du` of `/home/ai/*` takes over 10 minutes: use `df` and the worktrees only.

## What things should cost
Warm worktree. Compare CPU-s, wall follows load. More than about 3x the CPU-s: stop and find out why (3x at low load is a bug, not load). Gate stages: Time limits above (fastbox-0 medians). Rows marked (ostrich) are from the slower box (u 2.3 against 1.69) and older code: expect them lower here.

| what | expect |
|---|---|
| no-op `cargo build` / `cargo test --no-run` | 0.2 s / 0.3 s |
| one-line edit, `cargo test --no-run`: osis-node / osis-engine | 2.5 s / 30-70 s, about 200 CPU-s (osis-engine lib and its unit tests in parallel, then osis-node `it`); osis-engine lib alone 10-30 s (ostrich) |
| `cargo test --no-fail-fast`, built | 1190 CPU-s, about 2 min wall at load 16; per test and per binary: notes/testing.md, Default-test cost |
| edit osis-base, `cargo build --all-targets` / then `cargo test --no-run` | 40 s, 314 CPU-s / 230-280 CPU-s (ostrich) |
| rebase over changes in osis-commit, -engine, -node, -proto, -label, `cargo test --no-run` | 2280 CPU-s, 13 crates (ostrich) |
| clippy after a one-line edit | 3-8 s, then the GUI lint 3 s |
| clean `cargo build`; then `--all-targets`; first clippy | 82 s; +53 s; +17 s |
| first GUI build, `cargo build --workspace --all-targets` on a built core | 183 s, 1240 CPU-s (168 units, none of them core) |
| sim sweep, 15 seeds (the gate's) | 695 CPU-s, 56 s at load 26; heaviest per seed `concurrent_writers`, `future_format`, `work_sets`, `link_race` |
| properties at small size (a tenth of large) | every crate's: 775 s, 5860 CPU-s at load 20-40 (osis-node `it` 547 s of it); `OSIS_FULL=1` 13.4 min, 11,370 CPU-s (ostrich) |
| release `cargo test --release --no-run`: clean / after an edit (thin LTO relinks every test binary) | about 5 / 4 min at load 10-16 (ostrich) |
| `core/test/tla/run.sh <module>` | under 3 min each at one worker on a quiet box |
| a task worktree's `target/` | 4-6 GB after a gate and a pruning release (the GUI 1-3.5 GB more where built); 11-15 GB warm and not pruned |
| test executables relinked by an osis-node or osis-engine edit | the ten above it |

Signs of unravelling: a build on a tree built minutes ago compiles more than the touched crates and their dependents; `target/` dirs growing by GB per day; tool calls lasting exactly 10 minutes; a "wait for X" shell loop; `--jobs`, `--release` or `--features` creeping into commands; the unification check failing; a timing test running in dev; a long build whose CPU-s are normal but wall is 10x (`IDL` in `ps -o cls`: Scheduler above).
