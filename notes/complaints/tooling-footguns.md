# tooling-footguns
- The perf_event_paranoid=4 complaints predate the fix: /etc/sysctl.d/60-perf.conf and the live value have been 2 since 11-12 01:45 (no reboot since); icount works. A complaint carried across a fix gets re-reported.
- Local main in the main checkout was 6 commits behind origin/main while this task ran; `wt claim` branches from it, so this branch starts stale too.
- CLAUDE.md still says the reviewer gates "after `git rebase main`"; the gate now refuses a HEAD without origin/main.
- Review gate waited 30 min for the heavy lock: a by-hand model run (wt10 history-cut-model) held it for over an hour.
