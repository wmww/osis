# A Refused event lost with its connection leaves the entry waited for there for good
> Summary: a peer that cannot read L tells a refusal of a pulled entry once, by a cursorless Stream event 4 (spec/sync.md §10 Refused). If the connection drops (or the peer crashes) after the peer stored its stream cursor past the entry but before the event arrived, the source never learns of it: on reconnect the peer resumes past the entry, the source counts it lacking there (deletes there wait, status not idle) and nothing offers it again, not even once the peer's head moves (the head-move relog keys on the mark the lost event would have made).
> Priority: low
> Tags: node-sync, sync

- Same class for code 6 (the tombstone tell); Full recovers (room growing pulls L again from the start).
- Not data loss: the source keeps the entry; that peer lacks it and holds deletes back until a new stamp relogs it.
- Fix shapes: the peer keeps what it refused (blob, code) per L and tells it again on each new connection's join of L; or the peer does not store its cursor past a refused entry until the source acknowledged the event. Both cost state at the peer; pick the simpler once the race is seen to matter.
