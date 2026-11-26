# Build internals
> Summary: Why the build is set up as it is and how the box is kept healthy: the dev profile, feature unification (what keeps `-p` and `--workspace` builds sharing artifacts), the heavy lock's log, the scheduler that must stay off, disk upkeep, rejected worktree schemes, and scripted renames. For anyone changing manifests or the profile; the everyday rules are in notes/build.md.

## Profile
- Dev profile for all work (Cargo.toml): workspace crates `opt-level = 1`, `debug = "line-tables-only"`, incremental, `lto = "off"` (Tess's call); dependencies and osis-crypto `opt-level = 2`, no debuginfo; build-time code (`[profile.dev.build-override]`) without debug assertions, which keeps build-time units apart (Feature unification). No `split-debuginfo`: its `.dwo` files pile up (GBs per worktree).
- `.cargo/config.toml` zlib-compresses debug sections at link (Rust's symbolizer cannot read zstd) and sets the test env (notes/build.md, Footguns).
- The GUI's `[patch]` entries (libs/kit/patches/, vendored, not members) are in the root manifest; the GUI depends on `osis`, `osis-schema` and `osis-chat` only. One `deny.toml`.
- **Clippy says `Compiling`** for crates with build scripts after an edit reaching them: clippy builds build scripts with clippy-driver, as units apart from `cargo build`'s. A few CPU-s once per edit.

## Worktrees
Rejected: hardlink-seeded worktrees (a seed from a stale main rebuilt everything); one shared build checkout behind a lock (tests read fixtures through the manifest dir baked in at compile time, so the lock would serialize every test run).

## Feature unification
A package's features are the union of what everything in the build asks for, so `-p X` resolves differently from `--workspace` unless every crate's features are the same in both, and then rebuilds part of the tree as a second artifact set (cargo's `resolver.feature-unification = "workspace"` would fix it but is unstable). The rules:
- No feature a member turns on that another build of the crate leaves off: optional features only in the GUI (`accessibility`, off by default); osis-sync's `driver` is a default every member keeps. QUIC, the LAN loop, redb and `OsRng` are unconditional.
- Third-party features go in `[workspace.dependencies]`, the same for every member; dev-dependencies add no features to a normal dependency.
- Pins: where a crate higher up enables features on a shared low dependency (quinn-proto: rand's defaults; libcrux-platform: libc's; x25519-dalek: zeroize's derive; the GUI stack: bitflags `serde`, num-traits `libm`, tracing defaults), osis-base lists that dependency at the workspace's features, unused (crdt-model, which has no osis-base, as dev-dependencies). osis-kit pins regex-syntax at proptest's defaults.
- Build-time units never share a unit with run-time ones: `[profile.dev.build-override]` gives them their own profile. Otherwise cargo merges a build-time and a run-time unit of one crate when profiles and features match, the merged unit takes `lto = "off"`, and which crates merge depends on the selection: a GUI build would compile every osis crate a second time. Neither `[profile.dev.package."*"]` nor `build-override` can set `lto`; dropping `lto = "off"` would also fix it (Tess's call).
- Checked by the gate when a manifest, the lock or `.cargo/` changed: after `cargo build --workspace --all-targets`, `cargo build --all-targets` and `cargo build -p <member> --all-targets` for every member compile nothing. An offender: diff `cargo tree -e normal,build,dev --prefix none -f '{p}|{f}'` with `--workspace` and with `-p X`; same features but a different fingerprint `profile` hash is a per-unit profile difference: compare the unit's rustc line in `cargo build -v`.

## Heavy lock log
`~/.cache/osis/heavy.log` (JSON lines; tools/heavy's docstring lists the events). `tools/heavy --report [--since HOURS]` lists runs, utilization and memory (each run's peak resident GB, the box's lowest MemAvailable; short-lane and yielded holds marked). `tools/agent-times.py [--long N] [--since HH:MM|ISO|commit]` charges each agent its lock wait, hold, CPU-s and time by kind.

## Scheduler
`system76-scheduler` (Pop!_OS, `com.system76.Scheduler.service`) must stay off (`sudo systemctl disable --now` and `mask`; an OS upgrade can re-enable it): it puts `cargo`, `rustc`, `ld` and their children in SCHED_IDLE, and a cargo run then crawls beside any other (10-30x the wall at normal CPU-s; `nice`/`chrt` don't help). Check: `ps -eo pid,cls,ni,comm | grep -E 'cargo|rustc'` shows `IDL`; the gate warns while the service runs.

## Disk
- `wt release` runs `.claude/wt-mark`, then deletes every unit not used since the last release and all incremental sessions but the newest. The hook keeps a build key (a hash of `Cargo.lock`, the manifests, `.cargo/config.toml` and `rustc -vV`) in `target/.wt-mark-key`: unchanged, it only marks every unit read; changed or missing, it runs every standard build (1-4 min; add a new standard command there too) so the next job starts warm.
- Pruning needs access times: on `noatime` wt prints `targets not pruned` and targets only grow (`findmnt -T .`; `relatime` works).
- A warm target settles at 11-15 GB; 4-6 GB after a gate and a release. A worktree over 15 GB where no cargo runs: keep only the newest incremental session per crate dir (no rebuild): `python3 -c 'import glob,os,shutil,sys; [shutil.rmtree(s) for d in glob.glob(sys.argv[1]+"/target/*/incremental/*/") for s in sorted((x for x in glob.glob(d+"s-*") if os.path.isdir(x)),key=os.path.getmtime)[:-1]]' .worktrees/wtN`. Past 20 GB delete the target. Not `wt trim`: the next claim builds cold.
- A `libs/kit/target` in a worktree is dead (wt never prunes it): delete it.
- `core/test/fuzz/target` (nightly) is never pruned by wt (issues/upstream-wt.md): tools/claim drops its release profiles (by-hand fuzz runs) and empties it when its build key changes (`fuzz_target`).
- A full disk reads as a compile error (`failed to write query cache`, `failed to parse process output`): `df` before believing a build failure. A `du` of `/home/ai/*` takes over 10 minutes: use `df` and the worktrees only.

## Scripted renames
- Before: list files holding both the old and the new word (shadowing, collisions); protect third-party and other-sense names as exact tokens in every case with word boundaries (`/members(?!\w)`); filter paths with `git ls-files | grep -v`, not `':!path'` pathspecs (they can silently match nothing); print each rule's hit count: every rule must hit.
- A prose rename searches across newlines (a comment wraps `first\n// admin`). A renamed file moves in the same step, and links to its old slug are rewritten first. TLA junction lists are indentation-sensitive: realign `/\` bullets and compare `run.sh <module>` state counts.
- A field rename of a type used everywhere goes by the compiler: take the errors of `cargo build --message-format=json` and rename at each reported column.
- After: hunt the new word as well as the old, census short forms (`sv`, `srv`), and read the diff for same-token sense errors. A token-level diff (comments dropped, identifiers and literals compared pairwise) proves a rename pure in seconds.
