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
- A connection is taken as end to end: reliable, ordered and private between the two nodes, whatever carries it. A node between is not modelled, nor is a choice of paths.
- Log and record are one durable unit: `Apply`, a copy and a restore never separate a stored cursor from what it covers.
- Actions stronger than the wire: `Judge` under `Until` reads the peer's epoch (the real rule: `Lost` only after a Pull's cursor has passed `until`), `Reconcile` fires only with both queues empty and compares exact state. A digest crossing an in-flight reply is unchecked: a member one side has just opened looks like a difference.
- Bounds that exclude classes of bug: one credential per side, so a filter's additions cannot differ from the whole (GenBase and filter divergence are out of reach); at most one drop in the rotation cfgs, `T_rot`/`T_until` have none; the two copies in `S_copies` are never connected to a together. Faults are bounded, so `Settles` says nothing of a connection that keeps dropping.
- No property checks that a deletion arrives. `CaughtUpHolds` excuses every deleted entry and `NoWriteLost` only looks at inferred drops, so forwarding of deletions and the horizon's safety are unchecked.
