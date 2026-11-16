# `wt release` builds before it prunes, and the prune finds nothing
> Summary: `wt release` runs `.claude/wt-mark` (every standard command, the GUI's where built) before deleting units unused since; on a worker's tree that is a core rebuild, 20-120+ s, past the 120 s foreground limit in half the releases, while the unit deletion has freed nothing in every release logged (its GB are incremental sessions, which need no mark). Fix in the reasonable-rust-builds plugin: mark and prune units only when the build configuration changed.
> Priority: normal
> Tags: tools, tess-call

The plugin is wmww/agent-skills (Tess's), so the change is hers to take.

## Evidence (ostrich, Fathom's agents, 13 releases)
- Wall: 1-9 s on a tree its gate had just built (a lander that pushed without a rebase after), 20-121 s otherwise; 7 of 13 hit the 120 s foreground limit and finished in the background. A watchdog-5 release took 12 minutes (a GUI built in that worktree: the mark relinks the GUI test binaries after a core change).
- Every release printed `0 unused units` with 2.0-4.4 GB freed: all of it from `prune_incremental` (older incremental sessions), which reads no marks.
- The mark's build is mostly work the next claim redoes: the next claim branches from a later origin/main, and nearly every landing changes osis-engine or below, whose dependents (engine, sync, osis, chat, cli, sim test binaries: the bulk of the mark) rebuild again.

## Why units go stale at all
A unit's hash (`<name>-<hash>` in `deps/`, `.fingerprint/`) depends on the package ID and version, features, profile, target kind, rustc version and its dependencies' hashes, never on source text: editing a workspace crate rebuilds it under the same hash. So stale units come only from a changed `Cargo.lock` (a version, a dependency added or dropped), a changed profile or feature set (`Cargo.toml`, `.cargo/config.toml`), or a new toolchain. Stray flags (`--features`, `RUSTFLAGS`) are forbidden and caught by the watchdog's disk check.

## Fix (wt, `prune_target`)
1. Compute `key` = sha256 over the workspace's `Cargo.lock`, every `Cargo.toml` tracked under the target's parent (`git ls-files '*Cargo.toml'`), `.cargo/config.toml` if present, `rust-toolchain*` if present, and `rustc -vV` run in that dir.
2. Read the stored key from `.wt-pruned` (it is touched today; write the key into it).
3. If the key is unchanged: skip the mark and the unit deletion; still `prune_incremental` every used profile, reset atimes and touch the stamp as now.
4. If it changed (or no key is stored): mark and prune as now, then store the key.
5. In osis: nothing changes but notes/build.md, Disk (release cost) once the plugin version ships; `scripts/wt-mark` (a symlink kept for plugin 0.5.1, which sessions started before the 0.6.0 install still run) goes when no session runs 0.5.1.

Rejected: a size threshold for marking (a number with no principled value; at 0 it is today's behaviour, at infinity targets grow unbounded through lock changes); an osis-side `wt-mark` that exits early (wt then skips the incremental prune too, and the next prune deletes every unit the task did not touch, making the next claim cold).
