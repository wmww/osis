# Every reader seals its own record blob
> Summary: a reader takes a pulled record blob (`Opening::Taken`) and keeps no entry of it, and read's `cert_blobs_missing` counts only own record blobs, so each reader of S logs its own record blob of the records S's certificates need: one per reader where one would do.
> Priority: low
> Tags: sync, read, streams

Same pattern as bodies before readers kept the writer's blob (notes/sync-store.md, A reader's store of S): `EngineGround::open` answers `Opening::Taken` for `Opened::Records`, `Live::cert_blobs_missing` puts a record blob with no own entry into `gone` (its row forgotten) and logs a fresh one (`log_cert_blob`, `Engine::seal_records`). Fix shape: keep a pulled record blob as it came (as `Opening::Held` does for commits) and count any entry of it under S in `cert_blobs_missing`; check that a record blob kept from a peer still leaves when the records it carries are no longer needed. Seen too for a link's K: one record blob per node per sync ID.
