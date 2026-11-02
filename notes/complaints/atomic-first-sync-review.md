# atomic-first-sync review (tiller-atomic-first-sync-review)
- Local `main` lags `origin/main`: `git rebase main` said up to date twice; the brief's base had moved twice. `git fetch` and rebase on `origin/main`.
- A foreground timed loop over a slow probe moved to the background at 180 s and kept running beside my next steps: stop it, or start with `run_in_background`.
- `git diff main` from the branch while local main lags shows other merges as this branch's: read `git show HEAD`.
