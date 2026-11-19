# m1-open
- `wt claim m1-open origin/main` handed back a worktree four commits behind origin/main (fast-forwarded by hand before any edit).
- The 400,000-world `paths` search now costs about 6,300 CPU-s and passes `tools/heavy`'s heavy limit (5,060 CPU-s, 598 s wall): it runs to the end and only reports. A `-- N paths` mode cannot start at an offset, so it cannot be split into two holds; `random_worlds_hold_large` can (`OSIS_ROLES_START`).
- A `-- 10000 paths` short run passed the short lane's 115 CPU-s cap once the story grew; 7,000 fits.
- Each `tools/heavy cargo run` step of a chained script rebuilds from the working tree: no `.rs` edit while a chain of searches runs (a doc-only edit is safe).
- The story's honest answers skipped a node whose held set already carried a removal as evidence before it received it (`Sim::answers`' change key lacked the answers owed); found only by 400,000 worlds with the kiosk.
