# Undoing a removal of expiring content re-adds it without expiry
> Summary: undo re-adds a removed map entry (and other removed values) with a fresh dot in a delta without `expires` (osis-crdt `undo.rs` "re-add the removed value with a fresh dot"; engine undo `Resolved { expires: None }`, ephemeral and durable), so undoing the removal of a disappearing message, before or after its T, brings the content back for good: expiry stops being the hard upper bound.
> Tags: crdt, engine, ephemeral

Found in review of eph-expiry-vanish. Repro (ephemeral): A puts `k` expiring in 5 s, removes `k`, reverts the removal, advances 6 s: A and its holder both still read `k` (convergent, but past T). spec/crdt.md §4.7 strips "an undelete repeating the content" by dot; the fresh dot escapes that.

Likely fix: an undo delta re-adding content of an expiring delta takes that delta's expiry (the earliest one, per aspect, as the §4.7 SHOULD for writes into expiring elements), or re-adds it under its old dot so the dot attribution applies. Needs the undo log (ephemeral) and the undo commit (durable) to know the undone content's expiry.
