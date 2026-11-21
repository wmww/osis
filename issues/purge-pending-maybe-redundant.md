# engine `purge_pending` may be redundant
> Summary: mutating `retention/pending.rs` `tx.core.ix.pending.contains_key(c)` to `false` in `purge_pending` fails no engine or osis test. Likely redundant: a purge request's re-examination (`lists_moved` → `Wake::Thing` → `pending_drops` → `strip_purged`) strips the waiting copy too. Not proven: the one waiting-aside state reachable by hand (outside the closure) cannot decode the part, so both paths look alike. A code reader decides: delete `purge_pending` and its call in `hold_valueless`, or write the test that needs it.
> Priority: low
> Tags: engine, retention, tests

A surviving mutant shows the tests are blind, not that the check is redundant (notes/coordination.md): decide by reading every path that reaches a waiting copy of a purged part.
