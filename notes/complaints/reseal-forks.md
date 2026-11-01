# reseal-forks
- `wt` was not on PATH in the agent shell though the plugin is installed; used `~/.claude/plugins/cache/wmww-agent-skills/reasonable-rust-builds/0.5.1/bin/wt` directly.
- Checking that a new assertion fails on main's code meant a throwaway branch in the task worktree (main's sources plus the assertion), a rebuild of most crates each way.
- Review: a random test's ground truth for demotions must come from the engine (`current_holders`), not from `demote` returning Ok: a demotion by an admin demoted concurrently is invalid, which looked like a leak (seed 72).
- Review: the load average sat at 20-25 all session; one forks_with_departures seed took 3-10 s, so seed surveys ran as one process per seed from a copied binary under `xargs -P`.
