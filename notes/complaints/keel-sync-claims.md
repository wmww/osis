# keel-sync-claims
- "The thing of a sync ID" was answered in four places with four tie-breaks (rows fold: greatest reader; `sync_set_now`: lowest by `or_insert`; `sync_owner_of`: lowest namer; `sync_bodies_read`: last insert). Grep for every per-S "the thing" accessor before trusting one.
- A test registering a step straight into a store (`Store::take_register` on a clone) must kick the node (`w.write(i, |_| ())`): `w.run()` alone steps nothing, so a close never reached `unread`. That hid the closing-head test's real gap behind the ignore.
- The engine test via hand-placed tickets opened nothing: a ticket's secret is not taken without the role commits its fire carries; deliver the grant's fire instead.
