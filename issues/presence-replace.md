# Presence upload that replaces the previous entry
> Summary: An author deletes its previous presence entry at every server on each update (one Delete, two signatures); an upload naming the entry it replaces would drop that message and match the untie operation member peers need.
> Tags: ephemeral, server, proto

Today (notes/ephemeral.md Coalescing): each presence update is an upload of the new cover, then a level-3 delete of the old entry (a delete signature plus a write-key signature, verified by the server). Deletes of presence entries are not rate-limited, so this is a cost item, not a liveness one.

Proposal: an Upload entry may name blob IDs it replaces. The server unties this connection from each named presence entry of the label (only entries this connection uploaded; bounded by the entries in the message) and removes an entry no other open connection uploaded (log record, no tombstone, as on close). Nothing else may be named (durable or plain ephemeral entries: refused or ignored).
- The untie step is the release operation the member-peer case needs (notes/ephemeral.md Step 4, Member peers: a peer cannot delete a session's entry when the session leaves; owner call). Decide both together.
- Wire: an optional field on the upload entry (spec/wire.md), proto `ServerConnection` (the tie lives there) and the hub's close logic, member-peer serving, the node sending it instead of the delete; vectors.
- A replay on the replayer's own connection could only untie that connection's entries.
