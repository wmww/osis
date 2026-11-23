# A purged write reads differently by whether its body was ever held
> Summary: Deleting someone's latest message shows nothing at a node that held the message's body when the purge came (its value-less leftover still wins, spec/crdt.md §4.7), but the previous message at a node that was missing the body then (dropped while invalid, so "never received", spec/commits.md §5), until a writer holding both re-snapshots, which may never happen. A read that depends on arrival order, possibly for good. Expiry has the same shape (the order oracle's `expired_by_now` excuse). engine `order::held_set_decides_plain` seed 512007751.
> Priority: normal
> Tags: crdt, engine

Repro (5 steps, Lists family): `Message{0,t0,m4}, Message{1,t0,m8}, Demote{0 → 1, backdated}, Edge{0 re-grants 1 write}, PurgeAuthor{2, of 1}`, time advancing between; the node getting m8 last reads m4, the in-order node reads nothing. Worked-out options on branch `mizzen-purged-shown` (complaints and test; its order-oracle exception for this case is not landed).

The purge request cannot stand for the leftover: a leftover's effect comes from its body's structure (keys, stamps, resets, positions), which the header lacks, and a purger often holds none of the bodies it names (by author, whole aspect, later arrivals).

**Options (for Tess):**
- **A. A purged write has no effect on the read**, at every node, body held or not: one rule, no body, no fetch, no wire change. Visible: purging a write brings back what it replaced everywhere (delete the newest message → the previous one shows; purge a map clear or list delete → that content returns; others' writes nested under a purged creation vanish everywhere). Expiry takes the same rule and `expired_by_now` goes. Coordinator's lean.
- **B. Leftovers verifiable and fetchable**: each delta split into a structure part and a values part, both hashed in the header; a purge deletes only values; nodes fetch a missing structure part. Keeps today's meaning (a purged write still wins, reads nothing). Cost: wire, stores and sync logging (the sync rewrite's area); structure kept and served for good, to check against requirements Deletion "No fingerprint".

**Decided (Tess): A.** A purged write has no effect on the read at any node, body held or not: purging a write brings back what it replaced. Expiry takes the same rule. Covers issues/purge-of-live-write-only-readers-hold.md too.
