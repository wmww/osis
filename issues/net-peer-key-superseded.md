# Rows kept by a superseded peer key stay
> Summary: what a reader keeps of a store it cannot read (presence, gone marks, heads, refusals, fills) is by `PeerKey`, and one peer can end up under a second key while the first's rows stay: they go only when the record is evicted (`RECORD_BUDGET`, then the next start) or never (a dialed key). Stale presence keeps `present_anywhere` true, so the entry is never dropped here (`absent_at`, `local_deletions`) and counts as held for `placed`.
> Priority: normal
> Tags: node

How a peer gets a second key (notes/node-sync.md, Presence at a peer that cannot read L):
- **A new record.** A Resume that finds no record makes a new one on both sides (spec/sync.md §10 Pair key) while the side that kept the old one keeps it: one side evicted it, lost it to a restore or a crash before commit, or both sides dialed at once with no record. The old record lingers until its own eviction, which only budget pressure brings.
- **Actor proof changes.** A dialed node that proved no known actor (`PeerKey::Node`, its dialed key) later proves one (a record), or the reverse: the dialed-key rows are never dropped.

Nothing here can link the two keys (no node key finds a record, by design), so the stale rows are never moved by a stream again. Effect: a leak of entry rows and blob bytes, and placement counting a store under a key no connection reaches. Not security: the rows were true when written.

Direction: tie what is kept of a store to something that dies when no connection can find it again (rows inside the record, counted by its budget and dropped with it; a dialed-key row set dropped when the node stops being wanted), or hold presence only while a connection reads the store and judge placement from live sources. 6c removes `PeerKey::Node` and `StreamAt` (issues/net-6c-plan.md, commit 6: a source is kept by its record, else for the connection), which ends the second cause at the root; the first needs its own fix (rows inside the record).
