# add-cost
> Summary: Mishaps while narrowing what a chat's add costs.

- A long compound command moved to the background at 180 s, twice with a build in it: the release build alone takes 3 min here while other jobs run.
- perf is denied on this box (`perf_event_paranoid` 4): a breakdown per node needed spans per database (`World::spans_by_db`).
