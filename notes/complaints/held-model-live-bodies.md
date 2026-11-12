# held-model-live-bodies
> Summary: Footguns met while making held-model judge live bodies.

- A failing `held_set_decides_plain` run prints no coverage tally (`OSIS_ORDER_STATS` only), so a 17-minute sweep that hits one unrelated seed says nothing about whether the new check was reached; a second run was needed for the counts.
- `git diff main --stat` in a worktree whose base main has since moved shows other agents' commits reversed; `git diff HEAD` (or `main...HEAD`) is the branch's own change.
- The order harness's judged nodes run no node-sync drop pass, so a new held-model drop check reads as passing while unreached; only `OSIS_ORDER_STATS=1` shows the counter at 0 (issues/order-harness-no-sync-drops.md).
