# sim-seeds
- The NetSim trace shows dials and messages but not a node's `Close` actions or `Down` deliveries; a half-open link took two throwaway trace lines to find. Tracing both by default would make connection-lifecycle bugs readable from the failure's tail.
- The "not quiescent" failure lists what changed at the hosts since quiescence began, not over the last round, which reads like ongoing churn; the `busy:` part (outstanding requests) was the useful clue.
- `wt claim` of an existing branch can print a different worktree than the one released before; I ran git in the old path out of habit (a detached rebase there, undone). Always use the path the claim prints.
