# Readers log duplicate blobs of one thing
> Summary: Two cases where each reader of S logs its own blob where one would do: a pulled record blob is taken but not kept, so each reader seals its own record blob of what S's certificates need; and two readers finding a body must-hold and unlogged in one pass each log a fresh encryption. Bounded, charged to S's caps, deduped only at store sources.
> Priority: low
> Tags: sync

## Every reader seals its own record blob
A reader takes a pulled record blob (`Opening::Taken`) and keeps no entry of it, and read's `cert_blobs_missing` counts only own record blobs, so each reader of S logs its own record blob of the records S's certificates need: one per reader where one would do.

Same pattern as bodies before readers kept the writer's blob (notes/sync-store.md, A reader's store of S): `EngineGround::open` answers `Opening::Taken` for `Opened::Records`, `Live::cert_blobs_missing` puts a record blob with no own entry into `gone` (its row forgotten) and logs a fresh one (`log_cert_blob`, `Engine::seal_records`). Fix shape: keep a pulled record blob as it came (as `Opening::Held` does for commits) and count any entry of it under S in `cert_blobs_missing`; check that a record blob kept from a peer still leaves when the records it carries are no longer needed. Seen too for a link's K: one record blob per node per sync ID.

## Readers logging one body at once leave copies in different blobs
Two readers of S that find a body must-hold and unlogged in the same pass (e.g. an old rotation line's header-only copy replacing its with-part copy) each log a fresh encryption; peers then hold the same body in two blobs, deduped only at store sources.

- Seen in `flows::writers_of_two_accounts_keep_each_others_certificates_spec_sync_judgement_2`, which compares stores by (commit, parts), not by blob.
- Bounded: at most one blob per reader racing, each charged to S's caps; store sources drop all but the lowest blob ID (spec/sync-compaction.md §1 Duplicates). A reader's own store keeps both (equal delta sets are no strict subset).
- Deterministic header-only bytes (salt and blob key derived from the commit) would give one blob ID everywhere, but conflict with spec/sync-judgement.md §1: a copy refused as tombstoned goes again as a fresh encryption, which needs new bytes. An own-store duplicates rule (the same as at store sources) is the smaller fix.
