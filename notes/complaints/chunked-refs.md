# chunked-refs
- `new_thing` (test helper and `Engine::new_thing`) puts a strong in the admin's `holds.0`: a test wanting a thing held only by the reference under test must mint with `m.create(e.thing_record(admin, None))`; easy to miss until backlinks show an extra row.
- `lp.share` leaves the grant commits undelivered: a later "deliver the new commits" loop that snapshots `commit_ids` after it finds its commits pending on `UnknownCreated`. `sync_all` after `share` first.
