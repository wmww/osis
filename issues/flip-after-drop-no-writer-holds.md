# After a flip on a dropped body, a writer's compaction may not settle the read
> Summary: spec/requirements.md Deterministic says nodes may read apart after a flip or purge on a dropped body "until a writer next compacts". About 1 generated history in 100 stays apart after every writer compacted: the writers lack the write, a node that kept it reads it, and only the next write on the aspect ends it.
> Tags: engine, retention, spec

`order::settled` leaves aspects under a keep at most out for this (`Judged::expired_pending` in `alike_exchanged`). Take that out: `arrival_order_settled_large` fails at seed 61840041 (`OSIS_ORDER_START=61840000`, 1 of 60), 1 of 200 from 61850000; `settled(purge_history(..))` at 7150 (1 of 60 from 7100). Always `t:gone.0` (keep at most 0): `Some(Str("v1"))` vs none, plain order. Shrinking removes the compactions, so the cause is read from the history, not traced: a write under at most 0, demotions on that thing, an order that dropped it before the flip.

A rule call: "until a writer holding it compacts, or the next write", or trace it first. Tess accepted "until any writer of that data comes online".
