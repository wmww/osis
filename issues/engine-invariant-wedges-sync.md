# A broken engine invariant outside any commit stops the node
> Summary: A fault (`Error::is_fault`) taking a received commit sets that commit aside (notes/engine-apply.md, Faults set a commit aside), but a deterministic fault outside any commit still stops the node: node-sync's step fails at every retry, or a re-examination round's shared part fails and `run_taken` reloads at every tick. No peer input is known to reach one (notes/engine-apply.md, Which local errors peer bytes can reach).
> Priority: normal
> Tags: engine, sync, security

- **A re-examination round's** end work (`Engine::run`: `end_drops`' re-judge, `retention::needed::settle`) or shared part (`reach::round`, `read_pending`, `promote_loose`'s `learn_records_in`) faulting sets `taken_failed`: each tick reloads and fails again (`reload_owed` keeps `next_timer` at now; `Engine::fail_round` plants the shared-part case). Fix: on a fault run the round's end work per commit (bisect to the commit whose end work faults, set it aside) and owe a reload only for a store failure.
- **A tick's own work** faulting (`dated_replaced_at` at a tick or a setting change) fails every tick. Fix: judge per body as a step; a body whose judging faults keeps its last verdict until the next open, reported.
- **An arrival whose transaction faults outside the commit** (end work about other state) faults again in the set-aside transaction: the step fails for good. Fix: find the state the end work faulted on and set that aside, as the round case.
- **The set-aside transaction keeps the bytes alone**: blobs handed in with the commit (`Engine::ingest`'s) roll back with the failed one, so after a fixed build's open the commit may wait for blobs nothing fetches (sync's path brings none). Fix: store them in the set-aside transaction too.
