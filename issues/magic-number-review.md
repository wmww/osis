# Tess's review of the picked tradeoff values
> Summary: some picked numbers trade one real thing against another (clock skew, how long an offline node may return, inbox lifetime, LAN tag window, ...); Tess reviews them at some point (Tess: "lets handle the magic numbers later"). The full, kept-current list of every picked number with its justification is notes/arbitrary-values-table.md.
> Priority: low
> Tags: tess-call, spec

## Values awaiting the review
Values no choice makes free; each is in the spec or should be. Listed with what it trades.

| value | trades | where |
|---|---|---|
| `MAX_DRIFT` 1 h | clock skew tolerated vs how far a commit's `ts` may lie ahead (and every bound measured from it) | wire §2 |
| `ROLE_KEEP` 90 days | how long an offline node can return and sync cleanly vs replaced rotations and steps kept | wire §2 |
| `INBOX_LIFETIME` 90 days | how long an offline recipient's grant waits at the host vs host storage of undelivered blobs | wire §2 |
| `TOMBSTONE_LIFETIME` 30 days (recommended) | a holder offline longer re-uploads a deleted entry (re-deleted by the next writer that judges it) vs tombstone storage | wire §2, sync §4 |
| `MAX_CLAIMS` 65 536 | most claim keys per step: caps the holders of a label that can catch up by claim at one step vs claim-set size | wire §2 |
| LAN tag window 10 min | discovery stability vs trackability of the tag | sync §10 |
| `MAX_INBOX_RESENDS` 3 (node policy; spec: MAY bound) | a recipient silent for 3 × 90 days is given up vs re-sends forever | `sync/local.rs` |
| `INBOX_COPY_MIN_LEFT` = `INBOX_LIFETIME` / 2 (spec sync §3) | at 0 a stranger with the deposit seed recycles the deposit budget by short expiries and gets grants copied without bound; at `INBOX_LIFETIME` nobody copies. Past it a node opening a late blob applies the grant without copying: if no node copied it earlier, the actor's later nodes never find it (applying counts as acting, so no re-send). Tess's sign-off pending | `sync/pass.rs` |
| `MAX_READ` 1 GiB (node policy) | large values beyond 1 GiB stream only | `engine/large.rs` |
| schema limits `MAX_EXPAND` 64, `MAX_TYPE_DEPTH` 256, `MAX_INSTANCES` 10 000, `MAX_CHECK_WORK` 100 000, `MAX_NEST` 64 | decide whether a schema is valid but are not in the spec: another implementation could accept what osis refuses | `schema/` |
