# A3 draft: spec/wire.md
> Summary: Draft wire text for stage A3 (not in spec, not built): a lowering's field 12 as a list root (role entries, then a sorted (key, hash) pair per leaf), the leaf and its key and hash, the leaf blob. Map: notes/a3-spec/README.md.

Written over spec/wire.md §4 with A1's header and A2's certificate copy (notes/a2-spec/wire.md, whose (A3) section this replaces). Replaces field 12 `frontier`; adds List root, Leaf, Leaf blob.

## 4. Commits
```
ListRoot := [[commit_id*] | LINK, [[key, hash]*] | LINK]   ; role entries, then one pair per leaf
Leaf     := [tid, [commit_id+] | LINK, salt]
LeafBlobPlaintext := ["leaf", commit_id, Leaf]             ; the lowering's ID, its leaf
```
- **Field 12** (`list`, was `frontier`) on a lowering (spec/permissions.md §5.1 Frontier) is a ListRoot; on any other commit absent (a present one is bad input). Its **role entries**: the commit IDs, ascending and distinct, of the role commits it lists. Its **leaf pairs**: one per thing on which it lists a commit with no edge-class part, ascending by `key`, distinct. Each of the two lists is inline iff its canonical encoding is at most `CHUNK_THRESHOLD`, else a LINK to a chunk tree of it (§6) keyed by the header's list key (Inline or link), at most `MAX_LIST_BYTES`.
- A leaf's **key**: `kdf("list leaf", dedup secret of its thing, blind ‖ tid)`, 32 bytes, `blind` the header's field 10: a key serves one header; a reader of the thing computes it from what it holds before it holds the leaf, a node reading nothing of the thing cannot. Its **hash**: BLAKE3(`"osis v1 list leaf"` ‖ canonical bytes of the `Leaf`).
- A **Leaf**: the thing's tid; the listed commit IDs, ascending and distinct (inline iff at most `CHUNK_THRESHOLD`, else a LINK to a chunk tree keyed by the thing's dedup secret, at most `MAX_LIST_BYTES`); a fresh random 16-byte `salt` (so equal lists of two lowerings hash apart).
- A **leaf blob** carries one LeafBlobPlaintext; its prefix is a record blob's (§3: no expiry, no commitments); it is wrapped per sync ID as a certificate copy is (one encryption, a wrap per sync ID it is logged under) and identified by (lowering commit ID, tid). It is the lowering's leaf for its thing iff the lowering's root holds the pair (the key for that thing and that header, the hash of this `Leaf`); else it is bad input. A held lowering whose root holds no pair for a thing lists nothing there.
- What a reader of one thing learns from a root: how many role entries and leaves it holds, the role entries' commit IDs, opaque keys and hashes (README OPEN 1, 3).
- Decoding: a root with a pair list not ascending or with a repeated key, a leaf with a list not ascending, empty or repeated, a leaf blob whose tid has no pair in its lowering's root, are bad input.
