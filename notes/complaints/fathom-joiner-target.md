# fathom-joiner-target
> Summary: footguns met while fixing the joiner's dropped target.

- `git checkout <rev> -- core/engine` to compare against main silently reverts uncommitted edits in that tree too; commit wip first.
- A sibling opening a rotation's own `keys.0` section relied on an incidental `Wake::Moved` (role commits un-counting); with nothing moving, the part stayed missing and two siblings stepped D's sync ID past each other's deposit keys until the storm cap.
- origin/main moved three times during the task (each a ~4 min rebuild).
- Review: confirming a regression on main needs a wip commit, a detached checkout and a full engine rebuild each way (~4 min each at load); a probe test patch made against the branch conflicts when applied to main.
