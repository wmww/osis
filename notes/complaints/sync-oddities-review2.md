# sync-oddities-review2 complaints
> Summary: Mishaps met in the second review of sync-oddities.

- `parts::removed_author_differential_large` prints "two writes" panics for skipped histories (a step not writable by that actor); they read like failures. Grep the summary line.
- A forged lowering's actor cannot differ from its author: `CommitBuilder` refuses, and so does `validate` on arrival; `forge_*` helpers cannot express it (a non-issue, cost one build).
