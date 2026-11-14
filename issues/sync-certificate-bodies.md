# Record blobs are not logged or opened under sync IDs
> Summary: certificate commits (chain certificates, cards, account rotations, revokes' parts, header-only mintings) are in `sync_bodies` and logged as copies; the raw creation records a chain needs (record blobs, spec/wire.md §3, spec/permissions.md §4) are neither logged by read nor taken by `open_entry`, so a node that meets an actor only under a sync ID never learns its record.
> Priority: normal
> Tags: sync, engine

`Engine::sync_certificates(t)` names the records a sync ID's chains need (`Certs::records`), but read judges per commit and a record blob is no commit: nothing logs one (spec/permissions.md §4: the records missing go as one record blob of the logging node's, counted once opened and held at every source) and `open_entry_now` does not recognize one (it should decode `osis_commit::record_blob` and take the records as `receive_records` does). A record blob is never must-not-hold but under an emptied sync ID (spec/sync-judgement.md §2), so read must not judge it outside the required set either: today a record blob entry never names a commit here, so read never judges it.

Needed by a link's first contact (issues/sync-link-first-contact.md): the redeemer must learn the sharer account's and L's records from K's sync ID alone.
