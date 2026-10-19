# Commits
> Summary: A commit is a signed header plus deltas per touched aspect: header fields, commit ID and signature, commit kinds, dot forms, verification and atomic application, retention and purge, expiry, undo.

## 1. Header
Encoding: spec/wire.md §4. Fields:
- Format version (spec/versioning.md §1).
- Author node tid and the actor tid it acts for.
- Kind: content or membership (§2); compaction-snapshot marker; import marker (content only, with the origins table, spec/permissions.md §7); roster-snapshot marker (membership only).
- `ts` (spec/crdt.md §2.2) and the dot form, node or commit (§3).
- Schema table `[(schema ID, revision)]` (spec/versioning.md §3).
- Aspect list: per touched `(tid, ak)`: counter range `[lo, hi)`, retention (§5), optional `expires` (§6), schema index or none, and the delta hashes of its deltas. A content commit has one delta per aspect; a membership commit may have several (§2), all sharing the aspect's range.
- Chunk list: the chunk, tree-node and page blobs the deltas introduce, each with its token hashes, one per token secret, in the order of the commit's token hashes (spec/crypto.md §7).
- Optional purge request (§5), optional `undoes: commit ID` (§7).
- Delete token salt (16 random bytes) and token hashes with their levels (spec/crypto.md §7); per aspect, the indices of the token hashes its deltas call for.
- Demotions only: the frontier (spec/permissions.md §5), inline or as a link to a chunk tree when it exceeds `CHUNK_THRESHOLD` (spec/data-model.md §6).
- The aspect, chunk, purge, token and origin lists are each inline, or a link to a chunk tree of the list's canonical bytes when it exceeds `CHUNK_THRESHOLD`; those blobs carry the commit's token commitments (spec/wire.md §5) and belong to every projection of it (spec/sync.md §3).
- Signature (spec/crypto.md §2).

- **Commit ID** = BLAKE3 of the canonical header without the signature. The signature is over the commit ID (spec/crypto.md §2).
- **Delta** bytes: spec/crdt.md §3. **Delta hash** = `kdf("delta", dedup secret of tid, delta bytes)` (spec/crypto.md §6).
- A commit may touch things of any owners and reader sets.
- A commit has no size limit: a delta pages (spec/crdt.md §8), the header's lists go by link, a projection splits by size (spec/sync.md §3), and only blobs are bounded (`MAX_BLOB`, spec/data-model.md §6). One delta MUST fit a blob after paging and chunking (only a struct or enum of many near-`CHUNK_THRESHOLD` registers cannot); a writer refuses such a write.

## 2. Kinds
- **Content**: deltas on aspects that are not membership-class.
- **Membership**: deltas only on membership-class aspects (spec/data-model.md §9). A membership commit changes at most one `/members` edge, except: a single-use link redemption (the grant plus L's self-removal, spec/permissions.md §9); a roster snapshot (spec/permissions.md §6). A grant also carries the grantee's `/secrets` boxes; rotations, re-seals and `/keys` and `/label` writes change no edge and may cover many things. Membership commits MUST NOT carry `expires`; their retention is fixed (§5) and a purge request never names them.
- A membership commit MAY carry several deltas for one `(tid, ak)` (a roster snapshot one per edge or ledger entry): they share the aspect's counter range, their commit-level writes share the stamp `(ts, source, lo)`, and their creations use distinct counters; the aspect's delta is their join.
- `/created` is carried by the thing's first commit, of either kind, and by snapshots that cover the thing.
- **Compaction snapshot**: content or membership kind with the compaction-snapshot marker; snapshot deltas (spec/crdt.md §8); no own writes, empty counter ranges (spec/sync.md §7). Written by a node that may write the aspect. `/members` and `/tenures` are never compaction-snapshotted: a roster snapshot resets and rewrites them under its own stamps (spec/permissions.md §6).
- **Import**: content kind with the import marker; deltas of writes re-sourced from origin commits, no own writes, empty counter ranges (spec/permissions.md §7).
- A commit spanning several kinds is invalid.

## 3. Dot forms
- **Node form**: dots `(author node, counter)`, counters per (aspect, node), contiguous.
- **Commit form**: dots `(commit ID, index)`, unlinkable across commits. Any author may use it. A key actor whose key is used from more than one device (link key, recovery key) MUST use it.

## 4. Verification and application
- A commit's signature MUST verify; receivers dedup by commit ID. Each **delta** is judged on its own, by its author's authority on that delta's thing (spec/permissions.md §5); an invalid delta is un-merged alone (spec/crdt.md §4.6), the commit's other deltas stand.
- A commit is **pending**, not applied and counted as not received, while: its author's chain certificates have not arrived; the `/created` record of a thing it touches is unknown; any part of it is parked (spec/versioning.md §2); its `ts` is more than `MAX_DRIFT` ahead (spec/crdt.md §2.2); or atomic apply waits.
- **Atomic apply**: a node applies a commit only once it holds every delta of it that belongs under a label it syncs (spec/sync.md §3: entitlement, not group membership, decides), with the pages of every paged delta (spec/crdt.md §8); dropped or expired deltas count as held, and chunk blobs of large atomic values (spec/data-model.md §6) are not waited for. It then joins all those deltas in one storage transaction and fires listeners after. Pending commits are re-examined when the node starts or stops syncing a thing. A delta of an already applied commit that arrives later (the node began syncing its label after applying) is joined on arrival.
- Membership commits are applied before content.
- Two commits by one node whose node-form counter ranges on one aspect overlap are both invalid.
- A delta whose bytes do not match the header's delta hash is bad input.
- A commit blob whose clear prefix disagrees with its header (expiry, the token commitments its deltas call for; spec/sync.md §1) is bad input.

## 5. Retention and purge
Every delta carries **retention** on the wire: who may purge it, how long its body is kept, and its expiry (§6). The writer fills it from the schema's defaults per AK (spec/data-model.md §2); a commit may set it per aspect; an untyped write (no schema for the AK) defaults to `author` with no keep bounds and no expiry. Retention is immutable: to change it, purge and write again.
- **Purgeable by**: `nobody` < `admin` < `author` < `writer`. The named role may drop the delta's body: by purge request (spec/permissions.md §8), by compaction, and by deleting its blobs at blind nodes (spec/sync.md §5). Delete tokens follow it (spec/crypto.md §7). A **right holder** is a node that holds the right now.
- **Keep at least** and **keep at most**: each optional; each an absolute time, a duration after the body is replaced, or both (the later bound counts for at least, the earlier for at most). A relative keep at most exists only under `writer`: whoever replaces a body must be able to delete it. Where the two bounds disagree, keep at most wins.
- A **body** is one blob of a commit (a projection, spec/sync.md §3, holds the deltas of one retention class). A write **dies** when a later write supersedes it or at its delta's expiry (spec/crdt.md §4.8), at the superseding commit's `ts` or at T. A body is **replaced** as its writes die; per body a node tracks the first and last death so far.
- A body is **covered** by a snapshot the node holds when joining each of its deltas into the snapshot's fragment of that aspect leaves its canonical bytes unchanged (spec/crdt.md §3.3): every live write of the body is in the snapshot, and canonical form carries no dead content. A body the node cannot join, or a snapshot whose pages the node has not fetched, establishes nothing: the body is neither covered nor uncovered for it (spec/sync.md §6).
- **Keep at least**: before the bound (last death so far plus D, or T) a body leaves the labels of its things' groups only by purge request: compaction MUST NOT drop it and right holders MUST NOT delete it at blind nodes. A body with no dead writes is past a relative bound.
- **Keep at most**: by the bound (first death plus D, or T) every node MUST drop the body; its live writes stay in the node's state. A body with live writes is deleted at a label only once a snapshot covering it is under that label (spec/sync.md §7). At most 0 after replaced: the replacing node drops the body in the transaction that applies the kill and deletes it at blind nodes in the same sync (after a covering snapshot when the body still has live writes, spec/sync.md §7). At most D after replaced: the replacing node sends blind nodes a delete timed at the bound (spec/sync.md §5). Absolute T: right holders delete at blind nodes when next online after T.
- Between the bounds a right holder may drop a covered body (compaction, spec/sync.md §7); `nobody` makes that window empty. Snapshot bodies follow the same rules.
- **Purge request**: a header field naming earlier deltas or a whole aspect history. Every node applying it drops, at any time, the named deltas its author may purge (spec/permissions.md §8): from then on it holds their value-carrying writes value-less (spec/crdt.md §4.7) and drops every body carrying their values, snapshots included. A writer that, after applying it, holds no covering snapshot of the aspect under a label it writes re-snapshots there (duplicates are harmless, spec/sync.md §7). A request SHOULD name dead writes; the writer resets live content in the same commit. It MUST NOT name membership deltas.
- Purging drops bodies, never headers. A commit with a purged delta is rewritten as a blob without that delta: same header and commit ID, new blob.
- Dropping a body means destroying every local copy (undo buffers and pre-reset snapshots included), its delta nonce and every local index entry derived from it, so that later compromise of the node recovers nothing (notes/local-store.md describes the mechanism).
- A dropped body cannot be undone (§7); under at most 0 others' resets beat undo.
- Fixed retention: membership deltas are `admin`, keep at least `MEMBERSHIP_KEEP` (90 days) after replaced (a roster snapshot replaces `/members` and `/tenures` deltas, compaction snapshots or later writes the other membership-class aspects, spec/permissions.md §6); `/created` is `nobody`, kept forever; a certificate copy carries its commit's. Compaction-snapshot deltas are `writer` with the aspect's bounds. Import deltas carry their origin delta's (spec/permissions.md §7).

## 6. Expiry
- `expires: T` (wall ms, `T > wall_ms(ts)`, else invalid), per aspect of the commit. The schema may give a default per AK as a duration from the write. The blob prefix carries the T of the deltas it holds (spec/sync.md §1, §3).
- At T every value-carrying write of the delta dies (spec/crdt.md §4.7): every node holds them value-less and drops the body, whatever the delta's keep-at-least bound.
- Blind nodes delete the blob at T unattended (spec/sync.md §5).

## 7. Undo
- An undo commit sets `undoes` to the undone commit's ID; its deltas are chosen per spec/crdt.md §4.6. A commit whose body was dropped cannot be undone. Redo is an undo of the undo commit.
