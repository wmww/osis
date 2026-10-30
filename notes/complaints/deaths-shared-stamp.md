# deaths-shared-stamp
> Summary: workflow notes from the deaths-shared-stamp branch.

- `deaths_never_early_random` runs its seeds one at a time: 5000 seeds took 16 min while every other oracle uses `run_seeds` on all cores.
- The order harness's `alike` compares the index digest line by line as text; each new derived index (gives, snapshots, carried) a tolerated drop touches needs its own parser in the test.
