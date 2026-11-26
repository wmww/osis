# A replaced expiring delta never received is wanted until it expires
> Summary: under purge on replace, a node that gets an expiring delta's header after every holder dropped its body (replaced and covered) counts it never received and wants it until its expiry: no snapshot's tables reach an expiring delta (`snapshot::covered_join`, spec/commits.md §5 Covered), so it is never covered as never received.
> Priority: low
> Tags: engine, sync

- Repro: `setting::covers_settle_over_mixed_lifetimes_and_skewed_clocks_spec_commits_5` with an assert that no replaced write is `Meta::missing` at any peer fails after write 6: peer 2 writes field 0 expiring in 1 h, peer 0 concurrently expiring in 3 h; peer 2 covers and drops its own before peer 0 or 1 ever held the body, so both hold it `Missing(Plain)` until its end.
- Not from the expiring cover: `covered_join` never counts an expiring delta not held covered, whatever covers it (a lasting cover of one a lasting write overwrote alike).
- Cost: fetches no peer can answer; while missing, the node's own frontier for that session may stop at the gap (`frontiers_upto` walks held ranges), so its lasting snapshots reach none of the session's later never-received deltas until the expiry. Bounded by the expiry, which may be long.
- A fix needs a way for a cover to vouch for an expiring delta it does not carry (its tables claim nothing, spec/crdt.md §8), or a judgment that a delta never received is replaced from its header and the state alone.
- Not settled by superseded expiring writes (notes/ephemeral.md): that rule compares two held bodies' reads, so a header alone judges nothing; it applies to memory commits only, and a memory entry no source lists is forgotten anyway (spec/sync-compaction.md §2 Presence).
