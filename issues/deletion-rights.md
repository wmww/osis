# Deletion: remaining open questions
> Summary: What is still open after purge rights were decided (author or admin; delete tokens at blind nodes, 2026-10-11): cross-author resets of ephemeral content at blind nodes, grace-period default, partial-purge debounce bound (also the undo window), default compaction policy, and local erasure including the chunk-key tension (constraints tension 10).
> Tags: sync, security, permissions, crdt

Decided (do not reopen): three retention classes, purge granularity one (commit, aspect) delta, no fingerprint after purge, forward-secure deletion as a requirement, read access never deletes at a blind node, rotation decoupled from deletion, purge rights author-or-admin, per-entry delete tokens for authors and the label key for admins at blind nodes (notes/constraints.md, notes/crdt-sync.md, notes/sync.md, notes/permissions.md).

## 1. Ephemeral content reset by another writer at blind nodes (constraints tension 8 residual)
Authors hard-delete their own bodies by token, admins by key. A `purge`-class body reset by a different writer is soft-retired and lingers at the blind node until the grace period ends, an admin acts, or one of the author's devices syncs the reset and presents the token. That window is where forward secrecy fails for anyone holding the label read secret.
- Candidate: the uploader tags each entry with the lowest role allowed to hard-delete it (`purge`-class commits: writer; everything else: admin). A vandal gains only what resetting ephemeral content already gives at every honest node. Costs to judge: the server learns which blobs are ephemeral; a commit mixing ephemeral and preserved deltas takes the stricter flag; whether the flag is fixed at first upload.
- Alternative: accept the window, since the author's own devices close it on their next sync.

## 2. Grace-period default
Per-label policy set by admins, carried in the retire (constraints tension 4). Unset. If item 1 takes the flag, the grace covers only non-ephemeral soft retires and a long default (30 days) is right. Otherwise it trades ephemeral linger against backup safety.

## 3. Partial-value purge debounce
Purging part of a value needs a snapshot of the surviving live content first, so the resetting node batches behind a debounce; the deletion constraint holds only within that bound, which is not set. Seconds is the obvious range. The deletion constraint covers the deleting node's own undo buffer, so for `purge`-class content the debounce is also the undo window (notes/crdt-sync.md); apps need to know that.

## 4. Default compaction policy
`undefined` retention lets nodes drop superseded bodies by local policy; compaction is what drops them at blind nodes (notes/sync.md). Candidate default: trigger on the ratio of superseded to live bodies under a label, done by the writer that notices on its next write, with a randomized delay against a thundering herd. Readers never drop locally: a local drop without a label retire gets the blob re-offered on every fallback reconciliation. Write into notes/sync.md once confirmed.

## 5. Local erasure and the chunk-key tension (constraints tension 10)
Forward-secure deletion requires that a node which deleted honestly and is compromised later yields nothing. Chunk keys and IDs derive from the permanent dedup secret, so crypto-shredding cannot cover chunks; commit-key wraps live in the same database as everything else, and common storage engines do not securely free pages. Both reduce to one node-local key store that can forget (key tree with a securely erasable root; Reardon, Basin, Capkun, "SoK: Secure Data Deletion", 2013). Decide:
- A stored, rotatable per-thing dedup secret that a purge replaces, costing one re-upload of the value afterwards, instead of the derivation from the creation nonce.
- The erasable root per platform: OS keychain, TPM, or overwrite of a small file where that is reliable.
- What "dropped" means for wraps held by other labels: a label the node is a member of keeps the blob legitimately (refcount); a wrap under a label the node is blind for is unopenable and may stay.
- Local references that are fingerprints for a dedup-secret holder: chunk IDs in retire lists, cursor logs and the "IDs gained" lists must go with the content.
