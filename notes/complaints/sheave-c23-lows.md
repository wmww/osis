# sheave-c23-lows
> Summary: Workflow snags of the C23 low-findings cleanup.

- Landing took three test rounds: the touched crates' tests (osis-engine and osis, about 14 minutes serial) ran after the first rebase, and main moved 8 commits meanwhile, so land refused and the overlap rule asked for the same crates again. A land that names the overlapping files could also say whether the overlap is in the same hunks; here every overlap was in other functions.
- The gate's selection at its random offset hit a differential seed that fails on main and is in no known line (secrets index live vs opened afresh). Proving it was not this branch took a `tools/bin-at` build of the base (about 4 minutes). Nothing to fix: noted so a worker expects it.
