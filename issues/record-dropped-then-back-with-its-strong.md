# A thing's record dropped, then back with the strong to it, pulls nothing anew
> Summary: The same-transaction exception (spec/sync-judgement.md §3 Dropped bodies) assumes nothing of a thing whose record the node lacks was ever forgotten. False once the record was held and dropped: content forgotten meanwhile never comes back when the record returns with a strong in one transaction.
> Priority: normal
> Tags: engine, spec

## How it shows
Repro: `cargo test -p osis-engine --test it -- --ignored --exact closure::repro_record_dropped_then_back_with_its_strong`.

Peer 0's C mints W with X's strong to it (peer 1 holds X); D writes W again. Peer 1 takes D (pends for W's record), then a record blob carrying W's record under X's sync ID: D awaits it, so it is learned (spec/commits.md §4 Records), D applies, and at the pass end W, outside the node closure and needed by nothing, goes whole with D's part on it and its record. C then brings W's record with the strong in one transaction: nothing is pulled anew, D never comes back. Given C then D, peer 1 holds both.

Honest nodes reach it only when a record blob of W (a certificate, or the record of a minting below a seal floor, spec/crypto.md §4) reaches a node before W's minting does. Any path where W's record is held, content on W is forgotten (outside the node closure) and the record then dropped ends the same way.

## What holds
A commit on W arriving before W's record pends and is kept while carried (W held for itself while awaited, spec/commits.md §5 What a held thing needs), so the plain order (D, a pass end, C) ends alike (`closure::a_record_arriving_with_the_strong_*`). The gap is only where the record came and went first.

## Options
- **Mark what was forgotten**: a durable mark per thing whose content the node forgot as outside the node closure, kept while its record is not held; a strong newly reaching a marked thing pulls anew even if its record arrived in that transaction; the pull clears it. Needs a bound on marks (a hostile writer can make content on many things the node learns records of; marks could go with the last entry known of the forgotten commits).
- **Learn no record for content alone**: a record awaited only by content parts on a thing outside the node closure is not learned (it stays loose), so what awaits it keeps pending until a strong in the node closure awaits the record too. Closes this repro; leaves the paths where the record is learned for a certificate need that later goes.
- **No exception**: pull anew on every strong newly reaching a thing outside the closure. O(unit) per mint at every reader: no option.

The first is the only one closing every path.
