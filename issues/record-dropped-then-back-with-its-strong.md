# A thing's record dropped, then back with the strong to it, pulls nothing anew
> Summary: The same-transaction exception (spec/sync-judgement.md §3 Dropped bodies) assumes nothing of a thing whose record the node lacks was ever forgotten. False once the record was held and dropped: content forgotten meanwhile never comes back when the record returns with a strong in one transaction.
> Priority: normal
> Tags: engine, spec

## How it shows
Repro: `cargo test -p osis-engine --test it -- --ignored --exact closure::repro_record_dropped_then_back_with_its_strong`.

Peer 0's C mints W with X's strong to it (peer 1 holds X); D writes W again. Peer 1 takes D (pends for W's record), then a record blob carrying W's record under X's sync ID: D awaits it, so it is learned (spec/commits.md §4 Records), D applies, and at the pass end W, outside the node closure and needed by nothing, goes whole with D's part on it and its record. C then brings W's record with the strong in one transaction: nothing is pulled anew, D never comes back. Given C then D, peer 1 holds both.

Honest nodes reach it when a record blob carrying W's record and D reach a node in a pass before C does: a record blob under X's sync ID carries W's record once W is on a chain certificate there (W mint admin of a thing of the unit, or a holder on a grant chain, spec/permissions.md §4) or once W's minting is below the seal floor (spec/crypto.md §4); record blobs are fetched first in a pass (spec/sync-judgement.md §1), so a source holding D and the record blob but not yet C delivers this order. Rare: it needs a source holding D and not C. `Root::Awaited` has no say here: D, once applied, awaits nothing. Any path where W's record is held, content on W is forgotten (outside the node closure) and the record then dropped ends the same way.

## What holds
A commit on W arriving before W's record pends and is kept while carried (W held for itself while awaited, spec/commits.md §5 What a held thing needs), so the plain order (D, a pass end, C) ends alike (`closure::a_record_arriving_with_the_strong_*`). The gap is only where the record came and went first.

## Recommended: content waits outside the node closure
One rule closes both this and the awaited case: **nothing but certificates applies on a thing outside the node closure.** A content part (`forget::content`) on such a thing waits under Pending storage like an unjudgeable part (spec/commits.md §4: kept while carried, counted as not received), examined again when the thing enters the node closure; the thing is held for itself while something waits on it (its record as a certificate, as `Root::Awaited` does for a record). Then no content of a thing outside the closure is ever applied and stripped, so nothing of it is forgotten while a carrier holds it, and the same-transaction exception (spec/sync-judgement.md §3) is sound by construction; what the node no longer carries it cannot fetch from itself anyway. It subsumes `Root::Awaited` (one root: awaited, by a record or by closure entry) and the pass-end strip of arrivals (the strip stays for a release, whose content applied while in the closure and is marked forgotten). No new durable state; bounded by carriers as any pending copy.
To settle when building: a commit minting W with the strong bringing it in (C) must not wait on its own part on W: the closure is settled after the commit's strongs, so judge content parts on a thing the same commit brings in after the closure moves (or treat that thing as in), else every mint costs a second examination. Spec: §4 Unjudgeable gains the clause, §5 What a held thing needs drops "a content part on it goes as at a release" for arrivals, sync-judgement §3 keeps its exception unchanged.

## Alternatives
- **Mark what was forgotten**: a durable mark per thing whose content the node forgot as outside the node closure, kept while its record is not held; a strong newly reaching a marked thing pulls anew even if its record arrived in that transaction; the pull clears it. New durable state with its own bound (a hostile writer can make content on many things the node learns records of).
- **Learn no record for content alone**: a record awaited only by content parts on a thing outside the node closure is not learned (it stays loose). Closes this repro; leaves the paths where the record is learned for a certificate need that later goes.
- **No exception**: pull anew on every strong newly reaching a thing outside the closure. O(unit) per mint at every reader: no option.
