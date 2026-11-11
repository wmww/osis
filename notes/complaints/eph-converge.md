# eph-converge
> Summary: workflow notes from checking two ephemeral convergence issues.

- Both issues no longer reproduced on main 9ea6343b2; the issues named no commit that fixed them, so a stale-issue check cost a lock wait (5 min) plus about a minute of runs. A periodic sweep re-running open seed issues' replays would close such issues without an agent.
