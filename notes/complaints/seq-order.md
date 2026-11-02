# seq-order
> Summary: `wt` not on the worker's PATH though the plugin was installed; the first build after an osis-crdt edit took 5.5 min behind another agent's lock.

- `wt` was not on PATH in this worker's shell (only the claudewait plugin's bin was added) though reasonable-rust-builds 0.5.1 is installed; used it by its install path `~/.claude/plugins/cache/wmww-agent-skills/reasonable-rust-builds/0.5.1/bin/wt`. Worth a PATH fix in the plugin or the settings.
- First `cargo test -p osis-node --test it` after an osis-crdt edit: 5 min 36 s, part of it "Blocking waiting for file lock on package cache" behind another agent's cargo (expected 10-16 s plus relinks on a quiet box).
- The order harness prints a shrunk `h` per failing seed; after a partial fix the same seed shrinks to a different `h`, and a probe built on the old one passes while the seed still fails. Re-read the failure line after every code change before probing.
- A failing osis-crdt proptest appended to `core/crdt/proptest-regressions/tests_seq.txt` (as notes/build.md warns): check `git status` before committing.
- `mark_if_bounded`/`note_copies` debugging: `cargo test -p osis-node --test it` after an osis-crdt or osis-engine edit was 1.5-3 min per iteration at load 15-120; about 15 such iterations here.
- Stopping a background chain (TaskStop) mid-build left osis-engine's rlib linking with `undefined hidden symbol ... .llvm.*` (notes/build.md names the footgun); deleting `target/debug/incremental/osis_engine-*` was not enough since cargo still took the rlib as fresh: `touch core/engine/src/lib.rs` to recompile it.
- Reviewer: rebasing onto main conflicted in atomic.rs (main's `rebuilt` gained a `skip` argument), notes/testing.md (main dropped `skip_chainless_part_order` from the same paragraph) and the closed equivocation issue (main appended a note); each `tools/bin-at` build then rebuilt osis-crdt's dependents (about 3 min at load 13).
