# Networking rework model: assumptions
> Summary: What NetStream.tla and NetShared.tla abstract away from issues/net-reconnect.md and issues/net-shared-set.md.

- One node and one peer (b, or c, a copy of b's store at any instant); one sync ID in NetShared, one or two in NetStream. A store restored from a backup is modelled as c replacing b; two live copies as c beside b.
- A connection is an ordered pair of queues; one outstanding Pull per direction. Beacon and Pull pages are bounded (one event per page) rather than sized.
- `follow`/Push is a Pull plus an announcement flag (`dirty`, `Notify`).
- Events are entry adds and deletions; compaction keeps each held entry's latest event. Bodies, `inline_limit`, ephemeral entries and blob dedupe across connections are out: an event carries its entry.
- Rights are ghosts: in NetStream who may open is `rights`; in NetShared a credential is the sync ID's current epoch number and J is a view of one peer actor. Key actors, covers across a departure, deposits, peers that cannot read (sync-key Hits) and account proofs are not modelled.
- The adversary is an honest-looking peer answering Hits; forged proofs are not.
- `Synced` is per source; "holds what the other holds" is judged modulo entries deleted somewhere (a deleted entry a long-absent node keeps is retention's).
- Cost is modelled as: a from-the-start reply where the log could have answered from a position; no byte counts.
