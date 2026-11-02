# A junk part on a thing whose record is away keeps out the true part
> Summary: a part's hash needs its thing's record (the dedup secret), so before the record comes a junk part in the slot is stored in the pending copy, and `merge_parts` keeps what came first. When the record comes the junk goes as a bad part and the true part is gone with it, until something delivers it again. Any relay can do it without the author's key.
> Tags: security, engine, sync

Repro (fails): `cargo test -p osis-node --test it -- --ignored repro_waiting_part_poison`.

Not new with parts waiting alone (a whole pending commit merged the same way); more parts now wait this way. Check first whether node-sync fetches a body again once its commit shows the part missing. Fix sketch: keep each distinct candidate of a slot while it cannot be checked, bounded per slot, or let a later copy replace an uncheckable one and judge last-comer; a junk copy then costs a re-fetch, not the part.
