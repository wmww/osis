# Build
> Summary: Repo layout, task worktrees, the fixed command forms, the heavy lock, footguns, and what builds should cost. Profile, feature unification, disk upkeep, the scheduler and scripted renames: notes/build-internals.md; time limits: notes/time-limits.md; the merge gate: notes/gate.md.

A task is a branch in a warm worktree; main only fast-forwards and is never built. CLAUDE.md (Building and testing) holds the rules every agent follows; this note adds the mechanics and traps behind them. A cost far past What things should cost means something is broken.

## Layout
- `core/`: the library crates, in unprefixed directories with prefixed package names (`core/engine` is osis-engine); `core/test/`: test infrastructure (sim, vectors, fuzz, crdt-model, roles-model, held-model, tla). `libs/`: what some but not all users of osis want (`libs/chat` osis-chat, core; `libs/kit` osis-kit, GUI). `app/`: the GUI app (osis-app; `app/android` osis-android). `schema/`: the first-party schema files. `cli/`: the CLI. Further projects are top-level directories depending only on the `osis` crate.
- One workspace (one `Cargo.lock`, one `target/`; default-members and the GUI: CLAUDE.md). Core depends on nothing in the GUI.

## Worktrees
- **Claim**: `W=$(tools/claim <branch>)` from /home/ai/osis starts every task (its docstring: fetch, base on origin/main, bring the branch to its pushed copy, merge driver). Never a bare `wt claim`: for a branch that exists locally it checks out the local copy and ignores the base. After any claim, compare `git log -1` with the pushed copy before reading the diff.
- **Release**: `wt release` (inside the worktree, or naming its path) as the last step: it prunes the target and detaches HEAD. The first release in a worktree, and the first after a manifest, lock or toolchain change, runs every standard build (1-4 min: notes/build-internals.md, Disk), so run it in the background; later ones take seconds. A claim of a branch whose release is still pruning fails with "already used by worktree" (`tools/claim` says so): wait for the release to end (`claudewait` on your own; another agent's: `wt list` until its worktree reads `free`), then claim again. Upstream fix wanted: issues/upstream-wt.md.
- A new worktree builds cold once (about 80 s). Two checkouts sharing a `target/` (`CARGO_TARGET_DIR`) break because cargo judges freshness by mtime: one tree reads as fresh with the other's code inside.

## Profile and command forms
One dev profile for all branch work (notes/build-internals.md, Profile). Every new combination of profile, features, `RUSTFLAGS`, `CARGO_INCREMENTAL` or target dir builds and keeps another full artifact set (a `-p` subset does not), so CLAUDE.md's forms are the only ones. Jobs are capped in `~/.cargo/config.toml`, never per command (`--jobs`).
- **Default tests**: `cargo test --no-fail-fast` (without it cargo stops at the first failing binary); `--no-run` to build only.
- **One crate**: add `--no-fail-fast` whenever the lib binary may fail, or `it` never runs.
- **Filters** are substrings, so a name other modules share runs theirs too (`--exact <module>::<name>` for exactly one). Filters are OR'd, never AND'd: one before and one after `--` are OR'd too, so `--lib m::tests -- --ignored repro_` also runs every ignored test in `m::tests`, `_large` properties included; `--ignored paths:: _plain` runs every ignored test of `paths::` and every `_plain` (and `repro_`) of the binary (`tools/heavy` refuses that mix of a module and a name fragment; `paths_ _agree_plain` runs every `paths_*` property). Before a run with several filters, list it (`-- --list --ignored A B`) and read the names, or run each with `--exact`. Never `--test it <filter>` without `-p`: it prints a `0 passed` line for every other crate's `it`, hiding the one that ran. `--test it` with several `-p` applies to every package named: their lib tests, and crates without an `it`, silently do not run.
- **GUI**: `cargo test -p osis-kit -p osis-app --no-fail-fast` (otherwise an app failure skips kit's tests); `cargo run -p osis-app -- DIR`.
- **A property or by-hand test by name**: `cargo test -p <crate> --test it -- --ignored <name>`. osis-perm's `--ignored paths::` also runs the by-hand `paths::dump::paths_dump_readings`, which panics without `OSIS_DUMP`: add `--skip paths::dump`. Seeds and env vars: notes/test-harnesses.md.
- **Binaries**: `cargo test -p X` builds X's tests, not its `[[bin]]`, so `target/debug/<bin>` may be stale: use `cargo run -p X --`.
- **Sim**: `cargo run --bin sim-sweep -- --seeds N --budget-secs T` (notes/test-sim.md).
- **Networking** (by hand): `tools/heavy --short cargo test --no-fail-fast --tests -- --ignored quic relay lan --skip repro_` (about 13 s). Always filtered: unfiltered it runs every ignored test, and a `repro_` fails by design.
- **Release builds**: never inside a task, roles-model searches included (`cargo run --bin roles-model` is the dev profile). `tools/heavy` refuses a cargo `--release` or `--profile` run unless `HEAVY_RELEASE=1` (the coordinator's benches), and any cargo run in the main checkout. Memory checks and `cargo bench` are the coordinator's, run alone.
- **Old vs new**: `tools/bin-at REV OUT ...` (its header) builds REV's test binary in your worktree and copies it to OUT, the only copy. It needs a clean tree (wip-commit first); while it builds the tree is REV's: edit nothing, read the branch with `git show <branch>:PATH`. A new test against an old REV: `--take PATH` or `--patch FILE` (a self-contained probe module with its own world applies more often than one using shared helpers; a patch from before a directory move needs its paths rewritten by hand). Several binaries at several revisions: one spare worktree per revision (header). Compare under `tools/icount` (notes/test-harnesses.md, Measuring).

## Heavy lock
`tools/heavy` (its docstring: the log, what a hold runs, the short lane, yielding) runs a command under the box-wide lock: one all-core run at a time per box, because two at once each take about twice the wall, which blurs every hold's wall limit, and together can exceed the box's 30 GB. The log and `--report`: notes/build-internals.md, Heavy lock log.
- **Unlocked**: builds, single-crate test runs (`cargo test -p osis --test it` too), and anything that cannot use every core (a one-seed replay, a one-worker TLC, `tools/icount` at a few threads).
- **A hold runs copies** of what a `cargo test`/`cargo run` built at invocation, so edits after it don't reach the hold. Not covered: doctests, files or binaries a test reads from the tree at run time, and cargo inside a script (`run.sh`, a python tool), which runs what is on disk when the lock frees: build first and don't edit while it waits. A `tools/heavy sh -c '<copied test binary> ...'` hold may be denied by the permission harness; `tools/heavy cargo test` copies the binaries itself.
- **Waits are long** (often 10+ min): build every variant first and take the lock only for the run. Several runs over the short lane's cap but each only minutes: batch them into one `tools/heavy sh -c '...'` hold, with no `| head` inside (the next printing search panics on the closed pipe). Use `--log FILE` rather than a shell redirect (it makes the directory).
- **Not beside your own hold**: your crate tests beside your own search push the hold past its `heavy` wall limit. Run them before or after, and give an exhaustive search (`custody-exh`) its own hold.
- **Short lane** (`--short`): judge by CPU-s, not wall: a roles-model search a README times at 15 s is about 230 CPU-s, and a 15-seed sim sweep, about 130, takes a hold. Its caps: limit `heavy.short` (`tools/limits.py table`) and 4 GB resident; a run past them is stopped and rerun at once in a hold (a cargo test from the binary it stopped on), so a guess wrong by a little costs at most one cap's CPU-s and the queue it would have waited in anyway. A run known to be over the cap goes straight to `tools/heavy`. Not for a command that edits the tree (`tools/mutate.py`), and not for a loop of `--short` calls doing one big job (that is a hold).
- **A quiet hold yields** its lock to a waiting run and is SIGSTOPped if it then grows (docstring): wall-clock timeouts inside a stopped run see the stop.

## Footguns
**Waiting and exit codes**
- `claudewait` knows Bash background tasks only. A foreground call past 120 s moves to the background and its later steps keep running: keep edits out of a call that may run long.
- `timeout` around cargo kills a test run with a green-looking log; a build killed mid-link fails later with `rust-lld: undefined hidden symbol anon.*` (`cargo clean -p <crate>` for the crate whose rlib the error names).
- `cmd > log; echo exit $?` reports the echo's status, and a pipe through `tee`/`grep`/`tail` the pipe's. A pipe that stops reading (`| head`) ends the call while the test binary runs on unseen: write output to a file (`> log 2>&1`; `2>&1 > log` sends stderr to the call), then grep it for `panicked` and `test result` (a `tail` of a failing differential cuts off the panic line above its dump).
- A `&&` chain stops silently at its first failure (`git commit -qm wip && <edit>` skips the edit when there was nothing to commit): keep edits in their own call.
- `cat > file` (or `python3 -`) with no heredoc after it waits on stdin forever.

**Runs that test nothing and say ok**
- A misspelled `--exact` name or seed env var, `--ignored --exact` on a test that is not ignored, `OSIS_SIM_ONLY=` set empty. Check for `1 passed` and the printed seed range; oracle names carry a `_spec_*` suffix (`--list --ignored` shows them). A `repro_` test fails by design.
- libtest captures a passing test's output: an `eprintln!` probe shows nothing without `-- --nocapture`.
- **Proptest**: `.cargo/config.toml`'s `PROPTEST_CASES=32` overrides a test's own `cases:` (deep runs pass `PROPTEST_CASES=N`). A test binary run outside cargo has neither that nor `PROPTEST_DISABLE_FAILURE_PERSISTENCE`: it runs 256 cases unless you set both (`tools/mutate.py` and `tools/heavy cargo test` run copies with cargo's env).

**Probe variables**
- A throwaway probe variable is named `OSIS_PROBE_*` and switched off by unsetting it (`env -u`): `X= cmd` still sets it (`var_os` is `Some`), so a `for v in 1 ""` toggle runs the probe both times. Read it with `std::env::var_os`: testenv's readers panic on any `OSIS_*` name missing from core/base/testenv-known.txt, probes included. tools/policy.py fails while a probe is left in the sources.
- testenv-known.txt is in append order: add a name at the end (a sort rewrites most lines, and its union merge beside another branch's addition then doubles them). A test binary reads it from its worktree at run time, so a `tools/bin-at` binary from before a variable's rename refuses its old name: append the old name for the replay, then remove it.

**Editing and building**
- Two cargo commands in one worktree wait on its target lock (`Blocking waiting for file lock`): start a build in the background when a run is going.
- A `cargo test` holds the target lock only while it builds: a build started while its binaries run replaces `deps/it-*`, so the run's later binaries (osis-sync's `it` after its lib tests) are the new build's. No build in a worktree while a run of it is going; a probe builds after, or runs a copied binary.
- Editing under a running build builds the half-edited tree: edit and build in separate calls, one cargo test per worktree at a time. A chained `cargo test -p A; cargo test -p B` builds B from what is on disk when it reaches B: no edit until the whole chain ends (wip-commit before a long run, so its results name a commit). For a chain of oracle runs build once and run a copy of the test binary: `cargo test -p <crate> --test it --no-run` prints the `Executable` path (take it from each `--no-run`: a dependency change moves `it-<hash>`). bash reads a script as it runs it: don't edit `core/test/tla/run.sh` under a running `run.sh`.
- Scripted edits over-match (a `sed` `.` matching any character, a `str.replace` hitting a near-identical block, a slice between markers that occur twice, renumbering items already renumbered): edit with the Edit tool, or assert each replacement's count is 1 and replace between two markers each found once. Renames: notes/build-internals.md, Scripted renames.
- The workspace denies `clippy::indexing_slicing` (and `unwrap_used`, `panic`, ...) in library code: read `[workspace.lints.clippy]` in Cargo.toml before writing index-heavy library code.

**git**
- Wip-commit right before each probe, edits made since the last probe included: `git checkout <file>` and `git reset --hard` drop uncommitted work. Plant faults with `tools/mutate.py`, which restores from the text it read, not from git.
- Squash only with `git reset --soft $(git merge-base HEAD origin/main)`, never onto a branch or remote ref (a ref that moved gives the new parent with the old tree: a silent revert). A branch long behind main whose commits rewrite the same lines conflicts once per commit: squash it first, then rebase once.
- Rebase with `git fetch && git rebase origin/main`, without a pipe, and read its result; a conflict resolve and `rebase --continue` go in separate calls (a failed resolve script followed by `;` commits conflict markers). A crate both sides changed includes a dependent of a crate main changed: a rebase over engine changes reruns sync's `it` for a sync branch.
- Before every push, `git diff --stat $(git merge-base HEAD origin/main)` lists only your files. A branch's first push names the ref (`git push origin HEAD:refs/heads/<coordinator>-<branch>`): `--force-with-lease origin HEAD:<name>` fails for a ref the remote lacks.
- `git commit --amend -- <path>` commits only that path (other staged changes stay staged).
- Chain policy into what it guards, unpiped: `python3 tools/policy.py && git commit ...` (and before a push). With `;` or a pipe (`| tail`) the commit or push runs past the violations it printed; its last line starts `policy: FAILED` or `policy: ok`, and a failure piped says the pipe hid it.
- A commit straight to main (coordinator bookkeeping) with `git commit -a` leaves new files out, and `tools/policy.py` still passes there because the file is on disk: `git add` each new file by name and check `git status --short` is empty after the push. Land with `tools/land --delete <branch>` (its header), never piped. A file left untracked in the main checkout that main cites (an issue a known-failures line names) fails policy in every branch's gate until it lands; agents never write in the main checkout, only in their claimed worktree.
- Never `git checkout`/`switch` in the main checkout (read another revision with `git show REV:path`).

**Tools**
- `tools/mutate.py` (its docstring has the usage and batching rules): no other edit in that crate until its build ends. One mutation per OLD site; a rule read at two sites (an incremental path beside the from-scratch check) survives a plant of one: join them with `+`. Give several plants in one call, never a shell loop splitting specs on `|` (Rust closures hold it). A single plant builds into the worktree's own target, so the `deps/` binary it leaves is the mutant until the next build: rebuild before copying a binary for a property run. Its refusals exit 1 before building: never follow it with `; echo`, which turns a refusal in a background run into exit 0. Read its whole output or `MUTATE_OUT`: a `| tail` hides the first rows, and a row holds the plant's own `|` (split from the right on ` | `).
- `tools/icount` needs an absolute binary path (else `INSTR 0`, exit 127). `tools/icount BIN -q <module>::` reports the module total only: per-test counts are one `--exact` run each.
- `tools/heavy` options go before the command and cargo's after `cargo test`: `tools/heavy --no-fail-fast cargo test` prints heavy's usage and runs nothing.
- Before removing a `pub` item, grep its callers whole (no `| head`). Filter `rg` hits on the text after `file:line:`, never the whole line: the path is in it (dropping `retention/` hits drops every line of the files under `retention/`).
- `tools/dup_windows.py` and `tools/spec_map.py --gaps --uncited` print nothing on a clean run.
- `grep` in agent shells is Claude Code's ugrep shim: it rejects bounded repeats (`.\{0,150\}`) and skips gitignored files. Use `rg`, `command grep` or python. Notes and READMEs with one-line paragraphs print tens of KB per `rg -n` hit: `rg -o '.{0,300}word.{0,300}'`, or Read with offset and limit; a long result line cut by `cut -c` loses what it prints last: `rg -o 'failing checks \{[^}]*\}'`.
- Not built, so don't look for them: a switch forcing a wire form across the suites (wip-commit an edit of the constructor, then reset), a `costs::count` at a product decision for a one-off question (a scratch count on a wip commit), a main-built test binary kept per base commit (`tools/bin-at origin/main OUT -p CRATE` once per task), osis-perm's `it` under `tools/cpuprof` (it cannot run there: time copied-binary runs per test).
- Test harness traps: notes/test-harnesses.md, Harness footguns.

**Debugging**
- ostrich has no `gdb` and no `perf`; `strace`, `tools/icount` and `tools/cpuprof` work (cpuprof's `--report` symbolizes against the binary as it is now: profile a copied binary). A hung test shows as libtest's "running for over 60 seconds" line; then put a round counter or `eprintln!` in the suspect loop (fixpoint loops carry `osis_base::loop_guard`: notes/test-harnesses.md, Loop guards). Debug test builds' `std::backtrace` resolves few frames (line-tables debuginfo): find a caller with `#[track_caller]` and `Location::caller()`. Which small functions the dev profile left out of line: `nm -S --demangle <test binary> | rg 'Type>::'`. Where gdb is installed, `ptrace_scope` 1 lets it debug only what it starts: `gdb --batch -ex run -ex 'thread apply all bt' --args <copied test binary> --exact <name>`.
- A load-dependent flake: pin the test to few cores (`taskset -c 0-1 <copied binary> ...`); don't spin CPU burners.
- A test or script that overrides `HOME` breaks rustup's `rustc` (tools/heavy reads `rustc -vV`): set `RUSTUP_HOME` and `CARGO_HOME` explicitly, as tools/heavy_test.py does.

**Permissions and scratch**
- `.claude/settings.json` denies `git stash`, `pkill`, `killall` and `pgrep` anywhere in a command (a call holding `git stash list` is denied whole); stop your own background task with TaskStop.
- Permission prompts stall unattended agents: stay inside your worktree and scratch dir, use absolute paths instead of `cd` in compound commands; no sudo, network fetches, killing processes you did not start, or `git worktree add`. A call mixing an edit, a build and a hold, or using a `${X/a/b}` substitution, is denied whole: split them, write values literally. Write files with the Write tool.
- Scratch (CLAUDE.md): gate logs and copied binaries included. `mkdir -p` it in an earlier call, not a parallel one (a redirect into a missing dir ends a background run at once, reported exit 0). At your task's end delete copied binaries, profiles and TLC state dirs (GBs each) in your own dir.

## What things should cost
Warm worktree. Compare CPU-s; wall follows load. More than about 3x the CPU-s: stop and find out why (3x at low load is a bug, not load). Gate stages: notes/time-limits.md, Limits.

| what | expect |
|---|---|
| no-op `cargo build` / `cargo test --no-run` | 0.2 s / 0.3 s |
| one-line edit, `cargo test --no-run`: osis-engine | 30-70 s, about 200 CPU-s |
| edit osis-base, `cargo build --all-targets` | 40 s, 314 CPU-s |
| clippy after a one-line edit | 3-8 s, then the GUI lint 3 s |
| clean `cargo build`; then `--all-targets`; first clippy | 82 s; +53 s; +17 s |
| first GUI build on a built core | 183 s, 1240 CPU-s |
| `cargo test -p osis --test it` | about 380 CPU-s |
| `core/test/tla/run.sh <module>` | under 3 min each at one worker; `netopen` about 5 |

Signs of unravelling: a build on a tree built minutes ago compiles more than the touched crates and their dependents; tool calls lasting exactly 10 minutes; a "wait for X" shell loop; `--jobs`, `--release` or `--features` creeping into commands; a long build whose CPU-s are normal but wall is 10x (the scheduler: notes/build-internals.md, Scheduler).
