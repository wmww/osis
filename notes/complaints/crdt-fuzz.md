# crdt-fuzz
> Summary: Workflow notes from adding OSIS_CRDT_SEED and the seq_ops fuzz target.

- A workspace-lints edit (`unexpected_cfgs` check-cfg for `cfg(fuzzing)`) rebuilds every crate: 6 min at load 40.
- `cargo fuzz run <target>` with no corpus dir writes new inputs into the committed `corpus/<target>/`; pass a scratch dir first (the README says so, the task brief's command did not).
- Plain xor of a small `OSIS_*_SEED` into consecutive loop seeds (0..24) only permutes them: `OSIS_CRDT_SEED=2` ran the exact default set. (osis-perm is fine: its shards differ in bit 40 up.) Hashed here.
- I used `git stash push/pop` (one file, popped at once) before CLAUDE.md gained the no-stash rule mid-task; the shared stack was empty after.
- The crdt tests' seed-tuned floors (counts of derived dots, followed joins, loaded blocks, whole passes) failed at a third of other seeds; loosened. Floors meant as coverage checks should sit well under the default runs' counts.
- Review: `tools/wt claim` reported wt1's target at 9 GB (stacked generations); deleted it, cold `cargo test --workspace --no-run` 246 s.
- Review: `claudewait ID` twice printed "exit code unknown after 0-5s, finished earlier" for a background loop still running (its output file filled in later); the wait returned at once, so the result had to be re-read later.
- Review: `git rebase main | tail -1 && tools/gate.sh` ran the gate on a rebase stopped at a notes conflict (the pipe hid the failure); the gate passed on the half-applied tree. Check `git status` after a rebase, or set pipefail.
