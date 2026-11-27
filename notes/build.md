# Build
> Summary: Repo layout, job worktrees, the fixed command forms, the heavy lock, footguns, and what builds should cost. Profile, feature unification, disk upkeep, the scheduler and scripted renames: notes/build-internals.md; time limits: notes/time-limits.md; the merge gate: notes/gate.md.

CLAUDE.md (Building and testing) holds the rules every agent follows; this note adds the mechanics and traps behind them. A cost far past What things should cost means something is broken.

## Layout
- `core/`: the library crates, in unprefixed directories with prefixed package names (`core/engine` is osis-engine); `core/test/`: test infrastructure (sim, vectors, fuzz, crdt-model, roles-model, held-model, tla). `libs/`: what some but not all users of osis want (`libs/chat` osis-chat, core; `libs/kit` osis-kit, GUI). `app/`: the GUI app (osis-app; `app/android` osis-android). `schema/`: the first-party schema files. `cli/`: the CLI. Further projects are top-level directories depending only on the `osis` crate.
- One workspace (one `Cargo.lock`, one `target/`). Core depends on nothing in the GUI.

## Worktrees
- **Claim**: `W=$(tools/claim <name>)` from /home/ai/osis starts every job (fetch, base on origin/main, merge driver: its docstring). Never a bare `wt claim`: for a branch that exists locally it checks out the local copy and ignores the base.
- **Release**: `wt release` inside the worktree, last, in the background: it prunes the target (notes/build-internals.md, Disk). A claim whose name is still being released fails with "already used by worktree": wait for `wt list` to show it `free` (issues/upstream-wt.md).
- A new worktree builds cold once (about 80 s). Two checkouts sharing a `target/` break: cargo judges freshness by mtime, so one tree reads as fresh with the other's code inside.

## Profile and command forms
One dev profile (notes/build-internals.md, Profile). Every new combination of profile, features, `RUSTFLAGS`, `CARGO_INCREMENTAL` or target dir builds and keeps another full artifact set (a `-p` subset does not), so the forms below are the only ones. Jobs are capped in `~/.cargo/config.toml`, never per command.
- **The forms**: `cargo test --no-fail-fast` (the default tests: everything not `#[ignore]`); one crate `cargo test -p <crate> --no-fail-fast`; one component `cargo test -p <crate> --test it -- <module>:: <name>...` (filters after `--`: before it cargo takes one and refuses a second); `cargo clippy --all-targets -- -D warnings`; `cargo run --bin sim-sweep`. GUI: `cargo test -p osis-kit -p osis-app --no-fail-fast`, `cargo clippy -p osis-kit -p osis-app -p osis-android --all-targets -- -D warnings`. Properties and by-hand tests by name (notes/testing.md, When tests run).
- **`--no-fail-fast`** on every multi-binary run: without it cargo stops at the first failing binary (a failing lib skips `it`; an app failure skips kit). `--no-run` builds only.
- **Filters** are substrings and OR'd, never AND'd, including one before and one after `--`: `--lib m::tests -- --ignored repro_` also runs every ignored test in `m::tests`, `_large` properties included. `--exact <module>::<name>` for exactly one. For AND, `tools/test_names.py [--ignored] BIN FRAG...` lists a built binary's tests holding every fragment, for `--exact`. Never `--test it <filter>` without `-p`: it prints `0 passed` for every other crate's `it`, hiding the one that ran; with several `-p`, their lib tests and crates without an `it` silently do not run.
- **A property or by-hand test**: `cargo test -p <crate> --test it -- --ignored <name>`. osis-perm's `--ignored paths::` also runs the by-hand `paths::dump::paths_dump_readings`, which panics without `OSIS_DUMP`: add `--skip paths::dump`. Seeds and env vars: notes/test-harnesses.md.
- **Ignored by cause** (`#[ignore = "sync rewrite: ..."]`): `tools/ignores.py [--run LOGDIR] [PREFIX]` lists and runs them by name.
- **Binaries**: `cargo test -p X` does not build X's `[[bin]]`, so `target/debug/<bin>` may be stale: `cargo run -p X --`. The app: `cargo run -p osis-app -- DIR`.
- **Sim**: `cargo run --bin sim-sweep -- --seeds N --budget-secs T` (notes/test-sim.md).
- **Networking** (by hand): `tools/heavy --short cargo test --no-fail-fast --tests -- --ignored quic relay lan --skip repro_`. Always filtered: unfiltered it runs every ignored test, and a `repro_` fails by design.
- **Release builds**: never inside a task (`cargo run --bin roles-model` is the dev profile too). `tools/heavy` refuses `--release`/`--profile` unless `HEAVY_RELEASE=1` (the coordinator's benches), and any build in the main checkout. Memory checks and `cargo bench` are the coordinator's, run alone.
- **Old vs new**: `tools/bin-at REV OUT ...` (its header) builds REV's test binary in your worktree and copies it to OUT (one test on origin/main: notes/test-harnesses.md, One test on origin/main). It needs a clean tree (wip-commit first); while it builds the tree is REV's, so edit nothing and read your work with `git show`. A new test against an old REV: `--take PATH` or `--patch FILE` (a self-contained probe module applies more often). The branch's tests against a library's old sources: `tools/src-at REV CRATE OUT ...` (REV the merge base), never `git checkout REV -- <crate>/src` by hand (it has dropped uncommitted edits and pulled in sources needing newer siblings). Compare under `tools/icount` (notes/test-harnesses.md, Measuring).

## Heavy lock
`tools/heavy` (its docstring) runs a command under the box-wide lock: one all-core run at a time, since two at once each take about twice the wall and together can exceed the box's 30 GB. Its log: notes/build-internals.md, Heavy lock log.
- **Unlocked**: builds, single-crate test runs (`cargo test -p osis --test it` too), and anything that cannot use every core (a one-seed replay, a one-worker TLC, `tools/icount` at a few threads). Several of those side by side (`xargs -P`, `&` loops) are an all-core run and take a hold; so does a shrink of a property whose one seed runs its orders across threads (`OSIS_ORDER_SHRINK`). A shrink is never short-lane work.
- **A hold runs copies** of what `cargo test`/`cargo run` built at invocation, so later edits don't reach it. Not covered: doctests, files a test reads from the tree at run time, and cargo inside a script, which runs what is on disk when the lock frees: build first and don't edit while it waits. `tools/heavy sh -c '<copied binary> ...'` may be denied by the permission harness; `tools/heavy cargo test` copies the binaries itself.
- **Gates first**: a gate's hold (`tools/heavy --gate`, gate.sh's) goes ahead of every by-hand hold still waiting, so a by-hand run waits out every gate queued meanwhile; a running hold is never pre-empted. The short lane is unaffected.
- **Waits are long** (often 10+ min): build first, take the lock only for the run. Batch several runs into one `tools/heavy sh -c '...'` hold, with no `| head` inside. Use `--log FILE`, not a redirect. Options go before the command: `tools/heavy --no-fail-fast cargo test` prints usage and runs nothing.
- **Not beside your own hold**: your crate tests beside your own search push the hold past its wall limit. Give an exhaustive model search its own hold.
- **Short lane** (`--short`): judge by CPU-s, not wall (a roles-model search a README times at 15 s is about 230 CPU-s; a 15-seed sim sweep about 130: both take a hold). Past its caps (limit `heavy.short`, 4 GB resident) a run is stopped and rerun at once in a hold, so a slightly wrong guess costs little. Not for a command that edits the tree (`tools/mutate.py`), nor a loop of `--short` calls doing one big job.
- **A quiet hold yields** its lock to a waiting run and is SIGSTOPped if it then grows: wall-clock timeouts inside a stopped run see the stop.

## Footguns
**Waiting and exit codes**
- `claudewait` knows Bash background tasks only. A foreground call past 120 s moves to the background and its later steps keep running: keep edits out of a call that may run long.
- `timeout` around cargo kills a test run with a green-looking log; a build killed mid-link later fails with `rust-lld: undefined hidden symbol anon.*` (`cargo clean -p <crate>` for the crate the error names).
- `tools/logrun LOG CMD...` is the unpiped form: output to LOG, then its `test result`/`FAILED`/`panicked`/`error` lines and CMD's exit; it exits 1 when a filtered `cargo test` ran nothing. `cmd > log; echo exit $?` reports the echo's status. A pipe that stops reading (`| head`) ends the call while the binary runs on unseen; a `tail` of a failing differential cuts the panic line above its dump: write to a file (`> log 2>&1`) and grep it.
- A `&&` chain stops silently at its first failure (`git commit -qm wip && <edit>` skips the edit when there was nothing to commit): keep edits in their own call.
- `cat > file`, `python3 -` or `rg PATTERN` with nothing on stdin waits forever.
- Never nest heredocs: a `python3 - <<'EOF'` whose text holds its own `EOF` line ends there and bash runs the rest (once a test's `git push` against the real main). Write scripts with the Write tool and run the file.

**Runs that test nothing and say ok**
- A misspelled `--exact` name (oracle names carry a `_spec_*` suffix: `--list --ignored` shows them) or seed env var, `--ignored --exact` on a test that is not ignored, `OSIS_SIM_ONLY=` set empty. Check for `1 passed` and the printed seed range.
- libtest captures a passing test's output: an `eprintln!` probe needs `-- --nocapture`.
- **Proptest**: `.cargo/config.toml`'s `PROPTEST_CASES=32` overrides a test's own `cases:`. A test binary run outside cargo has neither that nor `PROPTEST_DISABLE_FAILURE_PERSISTENCE` and runs 256 cases (`tools/icount`, `tools/cpuprof`, `tools/mutate.py` and `tools/heavy cargo test` set them). Proptest counts move 5-10% between runs: compare with `PROPTEST_RNG_SEED=1` on both sides.

**Probe variables**
- A throwaway probe variable is named `OSIS_PROBE_*`, read with `std::env::var_os` (testenv's readers panic on names missing from core/base/testenv-known.txt) and switched off by unsetting it (`env -u`): `X= cmd` still sets it. tools/policy.py fails while a probe is left in the sources.
- testenv-known.txt is in append order: add at the end (a sort rewrites most lines, and the union merge then doubles them). A `tools/bin-at` binary from before a variable's rename refuses its old name: append the old name for the replay, then remove it.

**Editing and building**
- One cargo command per worktree at a time. A `cargo test` holds the target lock only while it builds: a build started while its binaries run replaces `deps/it-*`, so the run's later binaries are the new build's. Editing under a running build builds the half-edited tree; a chained `cargo test -p A; cargo test -p B` builds B from what is on disk when it reaches B. Wip-commit before a long run, so its results name a commit. For a chain of runs build once (`--no-run` prints the `Executable` path, which moves when a dependency changes) and run a copy.
- bash reads a script as it runs it: don't edit `core/test/tla/run.sh` under a running `run.sh`.
- Scripted edits over-match (a `sed` `.`, a `str.replace` hitting a near-identical block, a marker that occurs twice): use the Edit tool, or assert each replacement's count is 1. Renames: notes/build-internals.md, Scripted renames.
- The workspace denies `clippy::indexing_slicing`, `unwrap_used`, `panic` and more in library code: read `[workspace.lints.clippy]` in Cargo.toml before writing index-heavy library code.

**git**
- Wip-commit right before each probe: `git checkout <file>` and `git reset --hard` drop uncommitted work. Plant faults with `tools/mutate.py`, which restores from the text it read, not from git.
- Squash only with `git reset --soft $(git merge-base HEAD origin/main)`, never onto a branch or remote ref (a ref that moved gives the new parent with the old tree: a silent revert). Squash many wip commits rewriting the same lines before rebasing.
- Rebase with `git fetch origin && git -c rerere.enabled=false rebase origin/main`, unpiped, and read its result; resolve and `rebase --continue` in separate calls. `tools/land` refused names the files both sides changed: their crates' tests (and their dependents') are owed. Before landing, `git diff --stat origin/main...HEAD` lists only your files.
- Run policy unpiped and chained into what it guards: `python3 tools/policy.py && git commit ...`. Its last line is `policy: ok` or `policy: FAILED`.
- `git commit -a` leaves new files out while policy still passes (the file is on disk): `git add` each new file and check `git status --short` is empty before `tools/land`.
- `git commit --amend -- <path>` commits only that path.
- Never write, `checkout` or `switch` in the main checkout; read another revision with `git show REV:path`.

**Tools**
- `tools/mutate.py` (docstring: usage, batching): no other edit in that crate until its build ends. One mutation per OLD site; a rule read at two sites survives a plant of one: join them with `+`. Several plants in one call, never a shell loop splitting specs on `|`. A single plant leaves the mutant in `deps/` until the next build: rebuild before copying a binary. Its refusals exit 1: never follow it with `; echo`. Read its whole output (rows hold the plant's own `|`: split from the right on ` | `).
- `tools/icount` needs an absolute binary path (else `INSTR 0`, exit 127). `-q <module>::` is a substring (`content::` also counts `paths::content::`).
- Before removing a `pub` item, grep its callers whole (no `| head`). Filter `rg` hits on the text after `file:line:`, never the whole line.
- `tools/dup_windows.py` and `tools/spec_map.py --gaps --uncited` print nothing on a clean run.
- `grep` in agent shells is Claude Code's ugrep shim: it rejects bounded repeats and skips gitignored files. Use `rg`, `command grep` or python. Notes with one-line paragraphs print tens of KB per `rg -n` hit: `rg -o '.{0,300}word.{0,300}'`, or Read with offset and limit.
- Test harness traps: notes/test-harnesses.md, Harness footguns.

**Debugging**
- ostrich has no `gdb` and no `perf`; `strace`, `tools/icount` and `tools/cpuprof` work (cpuprof symbolizes against the binary as it is now: profile a copied binary). A hung test shows libtest's "running for over 60 seconds"; fixpoint loops carry loop guards (notes/test-harnesses.md, Loop guards). Debug backtraces resolve few frames: find a caller with `#[track_caller]` and `Location::caller()`.
- A load-dependent flake: pin the test to few cores (`taskset -c 0-1 <copied binary> ...`).
- A test or script that overrides `HOME` breaks rustup's `rustc`: set `RUSTUP_HOME` and `CARGO_HOME` explicitly (as tools/heavy_test.py does).

**Permissions and scratch**
- `.claude/settings.json` denies `git stash`, `pkill`, `killall` and `pgrep` anywhere in a command (`git stash list` too); stop your own background task with TaskStop.
- Permission prompts stall unattended agents: stay inside your worktree and scratch dir, use absolute paths instead of `cd` in compound commands; no sudo, network fetches or `git worktree add`. A call mixing an edit, a build and a hold, or using `${X/a/b}`, is denied whole: split it, write values literally.
- `mkdir -p` your scratch dir in an earlier call (a redirect into a missing dir ends a background run at once, reported exit 0). At your task's end delete copied binaries, profiles and TLC state dirs (GBs each).

## What things should cost
Warm worktree. Compare CPU-s; wall follows load. More than about 3x the CPU-s: stop and find out why. Gate stages: notes/time-limits.md, Limits.

| what | expect |
|---|---|
| no-op `cargo build` / `cargo test --no-run` | 0.2 s / 0.3 s |
| one-line edit, `cargo test --no-run`: osis-engine | 30-70 s, about 200 CPU-s |
| edit osis-base, `cargo build --all-targets` | 40 s, 330-390 CPU-s |
| clippy after a one-line edit | 3-8 s, then the GUI lint 3 s |
| clean `cargo build`; then `--all-targets`; first clippy | 82 s; +53 s; +17 s |
| first GUI build on a built core | 183 s, 1240 CPU-s |
| `cargo test -p osis --test it` | about 380 CPU-s |
| `core/test/tla/run.sh <module>` | under 3 min each at one worker; `netopen` about 5 |

A build's critical path: `cargo test --no-run --timings`. Signs of unravelling: a build on a tree built minutes ago compiles more than the touched crates and their dependents; tool calls lasting exactly 10 minutes; a "wait for X" shell loop; `--jobs`, `--release` or `--features` creeping into commands; normal CPU-s at 10x wall (the scheduler: notes/build-internals.md, Scheduler).
