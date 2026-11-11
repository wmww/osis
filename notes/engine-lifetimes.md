# Engine: lifetime judgment
> Summary: How the engine judges thing lifetimes and releases (`retention/lifetimes.rs`; design issues/thing-lifetimes.md, oracle held-model `lifetimes`): known/ended/unknown, the walk, the work list and `pending` as local rows, what queues, the release request as a purge of the creation, the engine API node-sync calls, and what is not built yet (forgetting, What is kept for listers, node-sync trigger).

## Principle
A walk reads only the current held state, so a release never rests on a queue or a cache: a missed queue only leaks. The kept state is two local row sets, `lw/` (work: things a change touched) and `lp/` (pending: judged unreachable, right not held).

## Reading
- Status (`lifetimes::status`): ended (`Core::ended`, or released earlier in the run), known (`exists`, a minting held, not a kept copy `forget::copy_of`), else unknown.
- List: `retainers^.0` read whole as `set<tid>`; absent or not a set of tids: standalone (kept).
- References: the reference index (notes/engine-refs.md): a durable row from R to X other than `retainers^.0` (`refs::references`); listers: X's `retainers^.0` rows (`refs::listers`).
- The walk (`walk`) as held-model `walk`: up the list through known retainers referencing what is below them; unknown or standalone: kept. A pending thing is walked through, never read as failed: `pending` is stale for a thing the same run made reachable (held-model `a_stale_pending_thing_is_walked_through`).

## Queueing
Only a known thing is queued; a thing turning ended or unknown loses its `lw/` and `lp/` rows, so a forgotten thing leaves none.
- `refs::note`: a durable reference row appearing or going queues its target; any join or rebuild of `retainers^.0` queues its thing (an empty list moves no row).
- `atomic::learn_record`, `end::end_ended` (ended or fallen), `forget::forget` (lost): the thing and its listers.
- `update_timelines` sets `Core::lifetimes_rights` (also set at open): the next judgment re-judges every pending thing (a right may have come). Brute force: O(pending) per role timeline change.
- Listers are read from `node/refs to` filtered by AK: O(rows naming the thing), not O(listers). Paid when a thing becomes known, ended or forgotten, and when its judgment flips (`below`).
- An index rebuild (`refs::write_all`) queues every referenced target and every list: rare, brute force.

## The release request
- A commit of `released.0` deltas alone (`timestamp`, fixed retention `author_or_admin`, no history), one per thing, no purge field, `expires = wall_ms(ts) + ROLE_KEEP` (`Header::validate`, `osis_commit::retention::release_expires`; `write_expires` gives it). Per-thing deltas, so an evidence copy names only its own thing.
- **One ending path**: `Header::requests()` reads it as a purge item on `created.0` of each such thing; every reader of a request (`purge.rs`: `names`, `note_requests`, `apply_request`, rejudging, `requests_resting_on`; `end::per_minting`; `View::purges`, fetch order, addenda's plain commits) goes through it. So validity is the purge right over each minting (`holds_right`, the ending's cut included), the minting goes value-less, `end_thing` ends the thing; a late minting or stale copy ends on arrival while the header is held.
- Differences from a purge, both erasure's alone: it names every minting whatever its `expires` (`names`: a purge in an expiring commit reaches only deltas expiring no later), and `purge_one` writes no lasting-header mark for it.
- Keep: an ending by request keeps the record, value-less creation, `roles.0` and the request parts (`end::judges_ending`: `created.0`, `roles.0`, `ENDING_REQUESTS`) while the request is held. Evidence for dependents: `ending_evidence` and node-sync's `ended_certificate` carry `ENDING_REQUESTS` parts, purge and release alike.

## API (engine, through `internals` in osis tests)
`Engine::judge_lifetimes(heard)` judges the work list (and pending when rights moved); a thing whose walk read a thing `heard` refuses stays queued. The unreachable things the node's account may end (`purge::would_hold_right` over every held minting), with their cascade, go in one release request it writes in a second transaction (`Engine::release`; a refusal leaves them judged, not pending: a leak). Returns `Judged { release, waiting, judged, request }`. `Engine::release(xs)` writes a request for any things (`Permission` without the right; `w.release` builds on it). `lifetimes_due`, `lifetimes_pending`, `lifetime_status`.

## Not built yet (issues/thing-lifetimes.md step 3)
Forgetting the request and the released thing at its `expires`, What is kept for listers and referencers (`ending_evidence`/`ended_certificate`), the node-sync trigger when heard out.

## Tests
node `lifetimes::` (the judgment against held-model over random batches, judged counts at n and 10n, a node missing a retainer, a cascade releasing an actor in one commit); node `ending::a_release*`/`a_released*` (absent at every node, refused without the right, dependents keyed by the frozen holders); held-model `spec_lifetimes`.
