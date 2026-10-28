# crdt-fuzz
> Summary: Workflow notes from adding OSIS_CRDT_SEED and the seq_ops fuzz target.

- A workspace-lints edit (`unexpected_cfgs` check-cfg for `cfg(fuzzing)`) rebuilds every crate: 6 min at load 40.
- `cargo fuzz run <target>` with no corpus dir writes new inputs into the committed `corpus/<target>/`; pass a scratch dir first (the README says so, the task brief's command did not).
- Plain xor of a small `OSIS_*_SEED` into consecutive loop seeds (0..24) only permutes them: `OSIS_CRDT_SEED=2` ran the exact default set. (osis-perm is fine: its shards differ in bit 40 up.) Hashed here.
- I used `git stash push/pop` (one file, popped at once) before CLAUDE.md gained the no-stash rule mid-task; the shared stack was empty after.
- The crdt tests' seed-tuned floors (counts of derived dots, followed joins, loaded blocks, whole passes) failed at a third of other seeds; loosened. Floors meant as coverage checks should sit well under the default runs' counts.
