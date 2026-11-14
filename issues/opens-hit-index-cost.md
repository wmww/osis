# A connection's first Hit costs O(sync IDs held)
> Summary: a Hit names no sync ID, so the receiver finds it by indexing every credential it shows on that connection (the Hits are bound to the connection's challenges): one beacon and one Hit hash per shown credential, and a J per sync ID, at the first Hit of each connection. A known peer that reconnects often while either side changes pays it each time, whatever the two share.
> Priority: low
> Tags: sync, performance

The index is built lazily (core/sync/src/opens/mod.rs `index_all`), so a reconnect the peer Hits nothing on costs nothing per sync ID; one Hit makes it O(n). A whole filter to a first contact is O(n) anyway; the cost that scales wrongly is a resumed record's.

Option (wire change): a Hit also carries the f-bit value of the beacon it hit in the receiver's filter. The record keeps value -> (S, credential) for its own filter (beacons depend on `r` only, so the map lives with the record and changes per changed S), and the receiver checks the Hit against the few candidates. Costs the record O(n) memory (it already keeps the peer's filter, O(n)) and one maintenance step per record per change of S, so it trades this cost for a per-change one across records: decide with the store's record rows (`RECORD_BUDGET`).
