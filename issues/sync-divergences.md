# Sync design diverges from constraints
> Summary: Proposed fixes to notes/sync.md not yet confirmed by owner: drop-list compaction, blind-node labeling rule, cursor logs for one-round-trip sync, content-defined chunking with coarse padding, rotation decoupled from deletion, blind-node retire authorization. Blob model, retention and revocation decided 2026-10-11 and moved to notes.
> Tags: sync, crdt, security

Tension numbers refer to notes/constraints.md.

## Keep-list compaction is O(group), not O(churn)
"retire N, keep [ids]" lists every surviving blob: 32 bytes per blob, so a million-blob group pays 32 MB per compaction. Fix: "retire [ids]" drop-list; blobs not named carry over. Blind nodes and peers keep a tombstone set of dropped ids for a horizon to reject stale re-uploads; generations stay as a cheap barrier or go.

## Blind-node labeling is unspecified
Members tag commits locally from `/groups`, but nothing says which labels an uploader attaches at a blind node. If Alice uploads under "sheet" and Bob syncs only "row 3", Bob never sees Alice's edit through that server. Rule: upload every blob under the label of every group in its things' `/groups` whose sync key the uploader holds; the server creates labels it does not know (32 bytes per entry). Costs |/groups| entries per body. A thing in a group whose group thing the uploader cannot read gets no label there; note as a gap.
- Group membership change: add the thing's live bodies to the new label, retire them under the old one (retire is per label, blob survives by refcount).

## Round trips (goal: small constant)
Range reconciliation is log(n) rounds and starts from scratch each session. Common case is "same peer, little changed". Fix: every node keeps a per-label append log with sequence numbers; a client stores (peer, label, cursor) and sends "since cursor" plus its own new ids; one round trip up and down, blobs inline. RBSR only when cursors are missing or invalid. Blind nodes see arrival order already, so the log leaks nothing new.
- With header+body blobs, a label's subscriber wants every blob under it, so the server sends blobs with ids; no header-then-body round trip.

## Size hiding costs bandwidth (tension 3)
sync.md: fixed-size chunks and bucketed blob sizes. serialization.md: content-defined chunking. Fixed-size chunking makes an insert into a large blob re-upload everything after it. Owner allows volume to leak: use content-defined chunking, deterministic encryption keyed from the owner read key (so equal chunks dedup across groups and edits), coarse padding only. Decide bucket granularity.

## Key rotation tied to compaction
"Permanent deletion reaches blind nodes at compaction, together with read-key rotation." Rotation does nothing for deletion against honest nodes and re-encrypting history is O(group). Decouple: deletion = retire (item 2); rotation only on member removal, lazy, new content only (notes/permissions.md).

## Blind-node retire authorization (constraints tension 8)
One sync keypair per group, held by every read member, authorizes both upload and retire. A read-only member, or an ex-member whose key was not yet rotated, can retire everything under a label. Not data loss while any member holds state (members re-upload snapshots) but vandalism of backups by the weakest role. Options: accept (readers are trusted enough); a second retire key wrapped only to write members (needs a writer-only secret, new concept); quotas and the grace period. Lean: accept plus grace period, revisit with an abuse case.

## Minor
- Closure-growth loop for partial trusted peers adds rounds bounded by nesting depth; fine.
- Statements for revocation are per (aspect, author node); with blind relays, clients must download everything then apply permission commits first (cannot prioritize before decrypting).
- Per-label logs plus labels for every ancestor group mean the "sheet" label on a server holds every blob of every descendant; intended.
