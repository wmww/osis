# An admin's unknowing fork puts an old read key in force for outsiders
> Summary: An admin that has not received a writer's removal rotation may rotate read boxing the removed party and step; `keys.0` keeps one read keyset, so an outsider holding both seals its fire to the admin's fork, which the removed party reads, until the admin receives the removal and rotates again.
> Priority: low
> Tags: security, sync, keys, tess-call

- Found by core/test/tla/rotation/FireKey.tla (F2, `FK_fork`); notes/sync-inbox.md What a fire is sealed to.
- Holders reading both epochs judge the fork uncovered and rotate before they encrypt (spec/crypto.md §4); an outsider holds `keys.0` alone and cannot judge coverage, and the later keyset write hides the knowing one.
- Window: until the admin receives the removal (its next step then waits for its own rotation). Content written by a node that has not heard of a departure has the same window; the difference is that the sender here holds the knowing keyset.
- Question for Tess: does spec/requirements.md Permissions ("a writer has written since") bind an outside sender in this race? If yes, the fix needs `keys.0` to keep every current read keyset (with the read key naming all it saw), or the sender to read coverage it cannot judge today.
