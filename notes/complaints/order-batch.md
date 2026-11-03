# order-batch
- The order oracle's shrink takes any failure, so a seed with several causes shrinks to whichever it meets first (733028 shrank to the dating one, hiding the `states` one the unshrunk run shows). A filter on the failure text (I used a throwaway `PROBE_ERR`) would help; worth a real env var.
- `then the rest` and `dating` failures print no `OSIS_ORDER_DUMP`; I wrote a per-step probe (state, drop/missing/valid per body) each time. A dump for those paths would save an hour per seed.
- Issue 1 (seed 28558) lives only on the held session-25 branch; it passes on main and on session-25's tip.
- Review: the rebase onto session-25 broke `bare_records` silently (it searched for `NTid(` dots; states now print `STid(..)/sess`). Harness parsers of `Debug` text break on any print change; only the pinned test caught it.
