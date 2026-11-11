# Engine: lifetime judgment
> Summary: How the engine judges thing lifetimes (`retention/lifetimes.rs`; design issues/thing-lifetimes.md, oracle held-model `lifetimes`): known/ended/unknown, the walk, the work list and `pending` as local rows, what queues, the engine API node-sync calls, and what is not built yet (the release request, forgetting, node-sync trigger).

## Principle
A walk reads only the current held state, so a release never rests on a queue or a cache: a missed queue only leaks. The kept state is two local row sets, `lw/` (work: things a change touched) and `lp/` (pending: judged unreachable, right not held).

## Reading
- Status (`lifetimes::status`): ended (`Core::ended`, or released earlier in the run), known (`exists`, a minting held, not a kept copy `forget::copy_of`), else unknown.
- List: `retainers^.0` read whole as `set<tid>`; absent or not a set of tids: standalone (kept).
- References: the reference index (notes/engine-refs.md): a durable row from R to X other than `retainers^.0` (`refs::references`); listers: X's `retainers^.0` rows (`refs::listers`).
- The walk (`walk`) as held-model `walk`: up the list through known retainers referencing what is below them; unknown or standalone: kept. A pending thing is walked through, never read as failed: `pending` is stale for a thing the same run made reachable (held-model `a_stale_pending_thing_is_walked_through`).

## Queueing
- `refs::note`: a durable reference row appearing or going queues its target; any join or rebuild of `retainers^.0` queues its thing (an empty list moves no row).
- `atomic::learn_record`, `end::end_ended` (ended or fallen), `forget::forget` (lost): the thing and its listers.
- `update_timelines` sets `Core::lifetimes_rights`: the next judgment re-judges every pending thing (a right may have come).
- An index rebuild (`refs::write_all`) queues every referenced target and every list: rare, brute force.

## API (engine, through `internals` in osis tests)
`Engine::judge_lifetimes(heard)` judges the work list (and pending when rights moved); a thing whose walk read a thing `heard` refuses stays queued. Returns `Judged { release, waiting, judged }`: `release` the unreachable things the node's writer may end (`purge::would_hold_right` over every held minting), each followed by its cascade. `lifetimes_due`, `lifetimes_pending`, `lifetime_status`.

## Not built yet (issues/thing-lifetimes.md step 3)
The release request (its wire form, validity, applying as an ending), forgetting it at `ROLE_KEEP`, What is kept through `ending_evidence`/`ended_certificate`, the node-sync trigger when heard out. Until then `judge_lifetimes` only reports.

## Tests
node `lifetimes::` (the judgment against held-model over random batches, judged counts at n and 10n, a node missing a retainer); held-model `spec_lifetimes`.
