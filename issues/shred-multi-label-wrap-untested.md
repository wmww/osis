# A purge leaving a blob's wraps under its other labels fails no test
> Summary: node-sync `drop_blob` zeroes the blob's wrap in every label's entry; a plant zeroing it only when the blob sits under one label (7 drops of two-label blobs in the forensic-attack tests) fails no default test, while zeroing none fails `shred_sync::purged_synced_body_crash_safe`. Either a two-label purge with a marker check is missing, or those wraps are unreachable for another reason; not examined.
> Priority: low
> Tags: tests, security, osis-node

Plant: in `core/node/src/sync/inbound.rs` `drop_blob`, skip `e.wrap = [0; WRAP_LEN]` when `labels_of(b).len() > 1`; then `cargo test -p osis-node --test it -- shred metadata flows nodelog lifetimes keep parts leaving` passes. Next: find which tests drop a two-label blob and whether they check a marker of its body after the drop; if none does, add a `shred_sync` case purging a commit carried under two labels.
