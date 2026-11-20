# A2 draft: spec/wire.md
> Summary: Draft wire text for stage A2 (not in spec, not built): a certificate copy's bytes (one section holding one thing's edge-class parts, its identity (commit ID, thing), one blob wrapped per sync ID); and, for A3, a lowering's list root with role entries and per-thing leaves keyed so only the thing's readers find theirs, and the leaf blob. Map: notes/a2-spec/README.md.

Written over spec/wire.md §4 as it stands with A1's header (`signer`, `path`, `remains`) and notes/path-form.md's split form. Replaces, in §4 Commit blob: the copy sentence of `Section`'s bullet. **(A3)** replaces field 12 `frontier` and adds List root and Leaf blob; until A3, field 12 *stands*.

## 4. Commits
- **Commit blob**, the copy sentence of the `Section` bullet: a **copy** holds its parts in one section, with an empty chain, its `wrap` under `kdf("section", blob key)` in place of a read secret: whoever opens a wrap of the blob reads it. A **per-sync-ID copy** (spec/sync-judgement.md §1) holds S's body of its commit. A **certificate copy** (notes/a2-spec/permissions.md §4 Copies) holds exactly the edge-class parts of its commit on one thing (its `roles.0` delta, its `vouches.0` delta, those it has; at least one) and is identified by (commit ID, that thing's tid); in a commit whose `path` is a `Split` it holds none (role commits state one `Path`). A **header-only copy** has no section. A node encrypts one certificate copy once and wraps that blob under each sync ID it logs it under (spec/sync-judgement.md §1 Certificate blobs); two nodes' encryptions of one copy are two blobs of one commit (spec/sync-ids.md §1 Several blobs of one commit), judged as duplicates (spec/sync-compaction.md §1 Duplicates). The blob's prefix is its commit's (no expiry and no commitments for a role commit, spec/commits.md §5 Fixed retention).

## 4. Commits (A3)
**(A3)** Drafted for the evidence rule (spec/permissions.md §4, §5.1 Frontier drafts); A3's spec brief settles it (OPEN 5, notes/a2-spec/README.md).
```
ListRoot := [[commit_id*] | LINK, [[key, hash]*] | LINK]   ; role entries, then one pair per leaf
Leaf     := [tid, [commit_id+] | LINK, salt]
LeafBlobPlaintext := ["leaf", commit_id, Leaf]             ; the lowering's ID, its leaf
```
- Field 12 `frontier` on a lowering is Opt(ListRoot) in place of the frontier value: its **role entries**, the commit IDs ascending and distinct of the role commits it names (any thing); then its **leaves**, one pair per thing on which it names a commit with no edge-class part, ascending by `key`, distinct. Each list is inline iff its canonical encoding is at most `CHUNK_THRESHOLD`, else a LINK to a chunk tree of it keyed by the header's list key (Inline or link).
- A leaf's **key** is `kdf("list leaf", dedup secret of its thing, blind ‖ tid)`: 32 bytes, `blind` the header's field 10 (so a key serves one header; a reader of the thing computes it before it holds the leaf, a reader of nothing else cannot). Its **hash** is BLAKE3(`"osis v1 list leaf"` ‖ canonical bytes of the `Leaf`). A `Leaf` holds the thing, the named commit IDs ascending and distinct (inline iff at most `CHUNK_THRESHOLD`, else a LINK keyed by the thing's dedup secret) and a fresh random 16-byte `salt`.
- A **leaf blob** carries one LeafBlobPlaintext, its prefix as a record blob's (§3), wrapped per sync ID as a certificate copy is; it is the lowering's leaf for its thing iff the root of the lowering's header holds the pair (`key` for that thing and this header, `hash` of this `Leaf`); else it is bad input.
- What a reader of one thing learns of the others from a root: the number of leaves and of role entries, and opaque IDs.
