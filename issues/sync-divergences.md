# Sync design diverges from constraints
> Summary: Where notes/sync.md (2026-10-09) fails notes/constraints.md: one blob per commit breaks row/column sync and prompt deletion, keep-lists cost O(group), bodies are retained after deletion, blind-node labeling is unspecified, round trips are log(n) in the common case. Proposed fixes per item; owner to decide 2026-10-11.
> Tags: sync, crdt, security

Numbers refer to notes/constraints.md Tensions where relevant.

## 1. One encrypted blob per commit (tension 5, 4)
sync.md puts header and all deltas in one ciphertext. crdt-sync.md keeps header and per-aspect bodies separately addressed; sync.md silently dropped that.
- Row/column: a commit touching many things (sort, fill, bulk import, any multi-thing app op) is tagged under every group of every thing it touches. A node syncing one column downloads every such commit in full. Volume for a group = all commits intersecting it, not the group's share.
- Deletion: purging one thing's content means retiring commits that also carry other aspects, so each of those aspects needs a snapshot. Cost of deleting one cell approaches the size of every aspect that ever shared a commit with it.
- Fix: commit = header blob (author, HLC, signature, list of (tid, ak, body id, size)) plus body blobs. Pack deltas into one body per distinct `/groups` signature of their things (things in one group: one body, zero overhead; grid: one body per cell). Reconciliation set of label G = headers of commits touching G plus bodies whose things are in G. Purge = retire bodies; dangling body ids in a header already mean "purged". Overhead per body about 70-100 bytes; a bulk edit over N differently-grouped things pays N of them (the 2D grid bulk case, explicitly not the goal). Header size is proportional to commit size and is downloaded by every intersecting group.

## 2. Bodies retained after deletion (tension 4)
"Nodes keep commit bodies for the live generation (required, to serve peers)" means deleted content stays in every honest node's body store until some compaction, and in blind nodes until compaction plus grace period. That violates the deletion constraint for an unbounded time.
- Fix: a reset commit is followed by (or carries) a retire of the bodies holding the reset content, by the deleting node, immediately. Thing deletion: retire all of its bodies, no snapshot needed (state after reset is a timestamp). Partial deletion (one paragraph, one map entry): the old bodies also hold live content, so a snapshot of the aspect must be uploaded first; batch these with a short debounce so a backspace does not upload the document. Constraint wording then becomes "within the compaction debounce", which must be stated and bounded.
- Undo: "an actor's own bodies kept for the undo horizon" must exclude content reset by anyone, else the author's node keeps what others deleted.
- Grace period on blind nodes keeps deleted ciphertext intentionally. Make it a per-group policy in the retire message (keep for N days vs drop now), signed like any retire.

## 3. Keep-list compaction is O(group), not O(churn)
"retire N, keep [ids]" lists every surviving blob: 32 bytes per blob, so a million-blob group pays 32 MB per compaction. Fix: "retire [ids]" drop-list; blobs not named carry over. Blind nodes and peers keep a tombstone set of dropped ids for a horizon to reject stale re-uploads; generations stay as a cheap barrier or go.

## 4. Blind-node labeling is unspecified
Members tag commits locally from `/groups`, but nothing says which labels an uploader attaches at a blind node. If Alice uploads under "sheet" and Bob syncs only "row 3", Bob never sees Alice's edit through that server. Rule: upload every blob under the label of every group in its things' `/groups` whose sync key the uploader holds; the server creates labels it does not know (32 bytes per entry). Costs |/groups| entries per body. A thing in a group whose group thing the uploader cannot read gets no label there; note as a gap.
- Group membership change: add the thing's live bodies to the new label, retire them under the old one (retire is per label, blob survives by refcount).

## 5. Round trips (goal: small constant)
Range reconciliation is log(n) rounds and starts from scratch each session. Common case is "same peer, little changed". Fix: every node keeps a per-label append log with sequence numbers; a client stores (peer, label, cursor) and sends "since cursor" plus its own new ids; one round trip up and down, blobs inline. RBSR only when cursors are missing or invalid. Blind nodes see arrival order already, so the log leaks nothing new.
- With header+body blobs, a label's subscriber wants every blob under it, so the server sends blobs with ids; no header-then-body round trip.

## 6. Size hiding costs bandwidth (tension 3)
sync.md: fixed-size chunks and bucketed blob sizes. serialization.md: content-defined chunking. Fixed-size chunking makes an insert into a large blob re-upload everything after it. Owner allows volume to leak: use content-defined chunking, deterministic encryption keyed from the owner read key (so equal chunks dedup across groups and edits), coarse padding only. Decide bucket granularity.

## 7. Key rotation tied to compaction
"Permanent deletion reaches blind nodes at compaction, together with read-key rotation." Rotation does nothing for deletion against honest nodes and re-encrypting history is O(group). Decouple: deletion = retire (item 2); rotation only on member removal, lazy, new content only (notes/permissions.md).

## 8. Revocation through blind relays (tension 6)
With the receipt-time rule, Bob's edit uploaded to the server Wednesday and first downloaded by a member Sunday is invalid after a Thursday revoke. In blind-only groups this drops every not-yet-downloaded edit of the revoked member. Consistent with the rule; owner to confirm it is acceptable for the primary topology.

## 9. Minor
- Closure-growth loop for partial trusted peers adds rounds bounded by nesting depth; fine.
- Statements for revocation are per (aspect, author node); with blind relays, clients must download everything then apply permission commits first (cannot prioritize before decrypting).
- Per-label logs plus labels for every ancestor group mean the "sheet" label on a server holds every blob of every descendant; intended.
