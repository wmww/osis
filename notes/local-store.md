# Local store: encryption at rest and forward-secure deletion
> Summary: A node keeps plaintext, wraps and indexes only inside an encrypted local store whose unit keys hang off a key tree rooted in platform erasable storage; deleting a unit erases its key, so freed pages never matter and no storage engine has to erase anything. Chunk keys are random and stored in links, so crypto-shredding covers large values too. Design decided; part of the MVP. Resolves tension 10.

## Requirement
spec/requirements.md, Deletion: a node that deleted honestly and is compromised later yields nothing, not even confirmation of a guess. Compromise means the attacker holds the device unlocked, so disk encryption does not help, and freed database pages, journals, undo buffers and indexes all count.

## Principle
No storage engine erases reliably (SSD wear levelling, copy-on-write filesystems, write-ahead logs), so never rely on erasing data. Erase keys instead. Every piece of local plaintext or key material lives in a unit encrypted under its own unit key; unit keys live in a key tree whose root sits in the one place the platform can erase; deleting a unit means dropping its key and rotating the path to a fresh root. (Reardon, Basin, Capkun, "SoK: Secure Data Deletion", 2013; DNEFS.) The storage engine, whether SQLite, redb or plain files, only ever holds ciphertext, so the backend choice is free and freed pages are harmless.

## Content keys (protocol side, on the wire)
- Commit blobs: random key, wrapped per label (spec/sync.md).
- Chunks and tree nodes of large values: random key per blob, stored in the parent's link; the root's link sits in the delta that carries the value. A link is (keyed content hash, blob ID, suite byte plus blob key), 97 bytes. Replaces the former derivation from the dedup secret and content, which made every chunk ID a fingerprint for every reader and left nothing to shred.
- Dedup by reuse, not by convergence: an editor holds the current tree, recomputes content-defined boundaries over the new content, matches chunks by content hash against the tree's links and reuses their (ID, key), unless the chunk's expiry is earlier than the new commit's (re-encrypted then, spec/sync.md §1); only new chunks become new blobs. Dedup across edits, devices and editors is unchanged. Lost only when two parties independently create equal content for the same thing, which was never common; cross-thing dedup never existed.
- Shredding a version: drop the wraps of its commit blob. Its deltas, hence its root links, hence every tree node and chunk that only this version reached, become unreadable. Surviving chunks stay reachable through the live tree. Purge cost is independent of value size.
- The dedup secret (KDF of the creation nonce) keys every content hash: delta hashes and links' content hashes. It keys no encryption any more, so it may stay permanent. Chunk IDs are hashes of ciphertext under random keys, so retire lists, cursor logs and IDs-gained lists are not fingerprints.
- Delete tokens (spec/crypto.md §7) derive from a chunk's prefix salt or a header salt, never from content; unaffected.

## Units
What a node holds and the unit each lives in:
- Blob ciphertexts: outside the store, plain files or rows; already opaque. Physically deleted when unreferenced, for space only.
- Wraps: the unit is a page of label entries, a few KB. Dropping a blob from a label rewrites its page without the wrap under a fresh page key. Needed because a member holds the label read secret, so a lingering wrap is a key.
- Aspect state, its undo buffer and pre-reset snapshots: one unit per small aspect. A large state (above about `PAGE_TARGET`) is paged like a snapshot (spec/crdt.md §8): page units at content-defined boundaries over consecutive elements, plus index units (`key -> page`, `dot range -> page`, for text `dot -> position`) that are themselves paged as a tree once large, so a million-key map write rewrites one page plus its index path (prolly-tree style). A purge rewrites the pages that held the purged body and their index path under fresh keys; a whole-thing purge drops the units. MVP requirement (scale: O(change) per edit).
- Decrypted chunk and tree-node caches, search and query indexes: units per aspect, or dropped and rebuilt. An index spanning aspects must be rebuildable and is dropped and rebuilt on a purge of anything it covers, or sharded per aspect.
- Membership and label secrets: units per actor; rotation on removal drops the old unit once nothing needs it (lazy rotation keeps old read secrets until then, by design). A node removed from an actor drops that actor's units and the content units only it opened (notes/permissions.md).
- Cursor logs, the IDs-gained list, diagnostics: blob IDs only, harmless; stored in the store anyway for uniformity.
- Memory, swap, core dumps, OS page cache: out of scope; mlock what is practical.

## Key tree
- Wide tree (256-ary) of 32-byte keys. Leaves are unit keys; an interior node is the list of its children's keys encrypted under its own key; the root key lives in platform storage. Three levels cover 16M units; more units add a level.
- Delete or rotate a unit: new unit key (or none), fresh keys along the path to the root, rewrite those nodes (about 8 KB each), write the new root to platform storage, then delete the old nodes. Batched per sync. Crash safety: the new root is written last; until it is durable the old root still opens the old tree, so the deletion counts as complete only after the root replacement is durable.
- Platform root storage, by trust: hardware-backed keystore (Secure Enclave and Keychain, Android Keystore, TPM-sealed key, Windows DPAPI or TPM); kernel keyring or secret service for the session; overwrite of a small file with fsync as last resort. The node records its tier and diagnostics report "best effort" below hardware-backed; nothing depends on that being read.
- Unlock loads the root once per session; the tree is cached in memory.

## What "dropped" means for a blob under several labels
- Also held under another label the node is a member of: keep the blob and that label's wrap, drop only the purged label's wrap. The content is legitimately still readable there.
- Under a label the node is blind for: keep; the wrap is unopenable here.
- A blind node or relay never has plaintext; it honours retires and tokens, nothing else.
- A blind node's recycle-bin copy stays openable by anyone holding the label read secret for the grace period; that is the accepted window of tension 4.

## Cost
- Reads: one unit decrypt per aspect load, cached. Writes: re-encrypt the unit; the tree is untouched unless a key rotates.
- Purge: O(pages holding the purged body), plus the wrap pages touched, plus three tree nodes and one platform write. Independent of history length and value size.
- Storage: 32 bytes per unit in the tree, plus about 64 bytes more per link inside large values, under 0.01% of a 1 MB chunk.
