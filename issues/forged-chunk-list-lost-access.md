# Losing access to a thing releases chunks a forged listing named
> Summary: Unverified, from the forged-chunk-list review. `retention/forget.rs` (lost access) releases every blob a removed commit's chunk list names unless a kept commit lists it, with no check that the blob is of the lost thing. A writer of t1 who reads t2 lists t2's chunks in a t1 commit; a node that later loses access to t1 but keeps t2 drops its local copies of t2's chunks once t2's own listers are forgotten (own replaces), and reads them `Missing` until fetched again.
> Priority: low
> Tags: security, engine

- Local only: hosts keep the blobs (no delete is sent), so a lazy fetch recovers them if the node still knows an entry for them (`forget_records` gets the same set as `extra`: check whether it drops those entries too, which would make the loss stick).
- Fix direction: release only blobs whose held prefix bears the removed commit's entry (the `Engine::chunk_entry_borne` check, spec/sync.md §7), as `dropped_chunks` does; a test in the style of `deletion::chunks_listed_by_another_thing_stay_spec_crypto_7` with the victim removed from t1's group.
