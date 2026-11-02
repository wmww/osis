# atomic-first-sync (tiller-atomic-first-sync)
- Local `main` lags `origin/main` when a coordinator says "rebase on main": fetch and rebase on `origin/main`, the plain `git rebase main` reported up to date.
- `claudewait` returning 124 with its output sent to /dev/null looks like completion: grep found an empty file and I read it as a pass for a moment. Check the exit before reading.
- A baseline run of the oracle at my offset found 4 of 120 seeds failing on main itself (40031, 40046, 40050, 40093): compare against main before chasing them.
