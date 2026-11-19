# A commit dropped before its thing's record arrived is never fetched again
> Summary: A commit on thing W that arrives before W's record pends, and goes at the pass end when nothing held needs W. If W's record later arrives in the same transaction as a strong that brings W into the node closure, nothing is pulled anew, so the dropped commit never comes back. Same commits, different end state by arrival order.
> Priority: normal
> Tags: engine, spec

## How it shows
Repro: `cargo test -p osis-engine --test it -- --ignored --exact closure::repro_dropped_before_its_record_never_fetched_again`.

Peer 0's commit C mints W with X's strong to it (peer 1 holds X); commit D writes W again. Peer 1 given C then D holds both. Given D, then a pass end, then C, it holds C only: D pended for W's record, went at the pass end (nothing held needs W, spec/commits.md §5 What a held thing needs), and C's strong to W pulls nothing anew because W's record arrived in the same transaction (spec/sync-judgement.md §3 Dropped bodies, "unless its record arrived in that transaction"). The engine evaluated "record not held" after learning the record before the certificates rule too, so the gap predates it.

## Why the exception exists
Without it, every commit minting a thing together with a strong to it (the usual way to make a thing in a shared unit) would make every reader pull that unit's sync IDs anew from every source: a from-the-start pull per new thing.

## Options
- **Mark what was forgotten**: pull anew only where the node forgot something the strong could bring back: keep a durable mark per sync ID (or per thing) whenever a pass end, release or stripping drops as never received something that came under it, cleared by a pull anew from the start. A new thing with nothing forgotten pulls nothing; this case pulls. Needs the engine to know which sync ID carried a dropped pending commit (its carrier entries do), and a bound on marks.
- **Keep the pending commit while its entry is held**: spec/commits.md §4 Pending storage already keeps a pending commit while the node holds an entry carrying it; the needs rule then drops it with W. If a pending commit awaiting a record stayed while its entry is held, D would apply when C brings the record. Needs the needs rule and Pending storage reconciled, and a bound for hostile pending input (the unvouched-input bounds may be enough).
