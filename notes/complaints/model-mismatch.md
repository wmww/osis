# model-mismatch
> Summary: Footguns met while chasing held-model and periodic-15 seeds.

- A probe piped through `grep` over a run that shrinks (`OSIS_ORDER_SHRINK` unset) printed nothing after 8 minutes: the shrink's last failure was not the one probed. Write the run to a file and set `OSIS_ORDER_SHRINK=0` first.
- Editing engine probes while a background tier 1 ran made its doctests fail (`found possibly newer version of crate osis_node`): no builds in the same worktree while tier 1 runs.
- `order::arrival_order_alike_large` seed 9300016 fails differently shrunk and unshrunk; the issue's repro (with the shrink) takes minutes, unshrunk 1 s.
- Review: the rebase over held-model-2 found its adapter listing an applied commit with a part waiting alone twice (applied and pending; the pending entry won), which purge seed 3039 at full size hit before the snapshot-drop check; only the full-size seed showed it.
