# Commits
> Summary: A commit is a signed header plus one delta per touched aspect: header fields, commit ID and signature, commit kinds, dot forms, verification and atomic application, retention classes and purge, expiry, undo.

## 1. Header
Field order and encoding: TBD (plans/protocol-spec.md). Fields:
- Format version (spec/versioning.md §1).
- Author node tid and the actor tid it acts for.
- Kind: content, membership or attestation (§2); compaction-snapshot marker; roster-snapshot marker (membership only).
- `ts` (spec/crdt.md §2.2) and the dot form, node or commit (§3).
- `sources` table (spec/crdt.md §2.4).
- Schema table `[(schema ID, revision)]` (spec/versioning.md §3).
- Delta list: per delta `(tid, ak, delta hash, counter range [lo, hi), schema index or none)`. A `(tid, ak)` appears once, except in a roster snapshot (spec/permissions.md §6).
- Chunk list: the chunk and tree-node blobs the deltas introduce, each with its token hashes, one per token secret, in the order of the commit's token hashes (spec/crypto.md §7).
- Optional retention class override (§5), optional `expires` (§6), optional purge request (§5), optional `undoes: commit ID` (§7).
- Delete token salt (16 random bytes) and token hashes (spec/crypto.md §7; list length capped, cap TBD).
- Attestations only: the answered revoke's commit ID and the entries (spec/permissions.md §5).
- Signature (spec/crypto.md §2).

- **Commit ID** = BLAKE3 of the canonical header without the signature. The signature is over the commit ID (spec/crypto.md §2).
- **Delta** bytes: spec/crdt.md §3. **Delta hash** = `kdf("delta", dedup secret of tid, delta bytes)` (spec/crypto.md §6).
- A commit may touch things of any owners and reader sets.

## 2. Kinds
- **Content**: deltas on aspects that are not membership-class.
- **Membership**: deltas only on membership-class aspects (spec/data-model.md §9), one membership write per commit, except a single-use link redemption (the grant plus L's self-removal, spec/permissions.md §9). A grant also carries the grantee's `/secrets` boxes. Roster snapshots and hand-over records are membership commits (spec/permissions.md §6, §7). Membership commits MUST NOT carry `expires` and are never purged; they retire only as spec/permissions.md §6 allows, and a partial-purge rewrite may drop their `/secrets` and `/keys` deltas.
- **Attestation**: header only, no deltas (spec/permissions.md §5).
- **Compaction snapshot**: content or membership kind with the compaction-snapshot marker; snapshot deltas (spec/crdt.md §8); no own writes, empty counter ranges (spec/sync.md §7). A roster snapshot is not one: it writes a reset and full state under its own stamps (spec/permissions.md §6).
- A commit spanning several kinds is invalid.

## 3. Dot forms
- **Node form**: dots `(author node, counter)`, counters per (aspect, node), contiguous.
- **Commit form**: dots `(commit ID, index)`, unlinkable across commits. Any author may use it. A key actor whose key is used from more than one device (link key, recovery key) MUST use it.

## 4. Verification and application
- A commit is valid iff its signature verifies and its author is authorized, at the commit's time, on every thing it touches (spec/permissions.md §5). Receivers dedup by commit ID.
- A commit is **pending**, not applied and counted as not received, while: its author's chain certificates have not arrived; any part of it is parked (spec/versioning.md §2); its `ts` is more than `MAX_DRIFT` ahead (spec/crdt.md §2.2); or atomic apply waits.
- **Atomic apply**: a node applies a commit only once it holds every delta of it that it may read and whose thing it syncs; purged or expired deltas count as held. It then joins all those deltas in one storage transaction and fires listeners after. Pending commits are re-examined when the node starts or stops syncing a thing.
- Membership commits and attestations are applied before content.
- A delta whose bytes do not match the header's delta hash is bad input.
- A commit blob whose clear prefix disagrees with its header (expiry, token commitments; spec/sync.md §1) is bad input.

## 5. Retention and purge
- Retention classes of content: `purge`, `preserve`, `undefined`. The schema gives a default per AK; a commit may override it for its deltas.
  - `purge`: once a delta's content is reset or superseded, every node applying the superseding commit MUST drop the superseded body immediately and irrecoverably. The resetting node, in the same sync, uploads a snapshot of the surviving live content of the aspect and hard-deletes the old bodies at blind nodes (spec/sync.md §7). No undo.
  - `preserve`: bodies are kept and synced until an explicit purge.
  - `undefined` (default): nodes drop superseded bodies by local policy, through compaction.
- **Purge request**: names earlier deltas or a whole aspect history. It purges the named deltas the requester may purge (spec/permissions.md §8).
- Purging drops bodies, never headers. A commit with a purged delta is rewritten as a blob without that delta: same header and commit ID, new blob.
- Dropping a body means destroying every local copy, its delta nonce and every local index entry derived from it, so that later compromise of the node recovers nothing (notes/local-store.md describes the mechanism).
- Undo buffers keep a node's own bodies only while nobody has reset their content; others' resets of `purge`-class content win over undo.

## 6. Expiry
- `expires: T` (wall ms, `T > wall_ms(ts)`, else invalid). The schema may give a default per AK as a duration from the write.
- At T every node holds the commit's value-carrying writes value-less (spec/crdt.md §4.7) and drops its body as purged. A multi-aspect commit expires whole.
- Blind nodes delete the commit's blobs at T unattended (spec/sync.md §5).

## 7. Undo
- An undo commit sets `undoes` to the undone commit's ID; its deltas are chosen per spec/crdt.md §4.6. Purged or expired commits cannot be undone. Redo is an undo of the undo commit.
