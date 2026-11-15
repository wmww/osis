# Readers logging one body at once leave copies in different blobs
> Summary: two readers of S that find a body must-hold and unlogged in the same pass (e.g. an old rotation line's header-only copy replacing its with-part copy) each log a fresh encryption; peers then hold the same body in two blobs, deduped only at store sources.
> Priority: low
> Tags: sync

- Seen in `flows::writers_of_two_accounts_keep_each_others_certificates_spec_sync_judgement_2`, which compares stores by (commit, parts), not by blob.
- Bounded: at most one blob per reader racing, each charged to S's caps; store sources drop all but the lowest blob ID (spec/sync-compaction.md §1 Duplicates). A reader's own store keeps both (equal delta sets are no strict subset).
- Deterministic header-only bytes (salt and blob key derived from the commit) would give one blob ID everywhere, but conflict with spec/sync-judgement.md §1: a copy refused as tombstoned goes again as a fresh encryption, which needs new bytes. An own-store duplicates rule (the same as at store sources) is the smaller fix.
