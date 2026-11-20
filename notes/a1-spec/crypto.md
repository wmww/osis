# A1 draft: spec/crypto.md
> Summary: Draft spec text for stage A1 (not in spec, not built, but §5's path entry, which spec/crypto.md holds): §7's delete-key level 2 as the commit's one purge author's, the header list's base and thing blind under the signer, and a holder's level-2 signing. Map and status: notes/a1-spec/README.md.

Replaces, in spec/crypto.md §7: the Levels table, the Header list bullet, the `blind` sub-bullet of Commitment, and the last bullet (a holder tries every epoch). Delete base, Delete key, Commitment's other sub-bullets, Certificate blobs and Delete signature stand.

*Settled* for who holds the level-2 right: the purge author's chain (roles-model `paths` `purges`, control `-purge-any-path`), and that a store may act on whatever could hold it (purge worlds' `could hold`). OPEN, argued (notes/purge-model.md, Delete keys): keys are not modelled. Every holder of the `author` right holds level 2's secret (its path gives write on every edge up to the purge author, so it reaches the purge author's write secret by derivation, spec/permissions.md §3); a store checks one signature per commitment group (spec/sync-ids.md §6), so a deleter holds a right over every delta of the blob as of the epochs its header lists; a removed party's keys keep deleting blobs of epochs it held at unread stores until a writer holding the body logs it again, a later rotation keying only new blobs. One purge author per commit makes at most one level-2 key per commit the rule (wire field 11), not an Interim.

## 5. Blobs, wraps, sealed fires
The Path entry bullet is built: spec/crypto.md §5.

## 7. Delete keys
- **Levels** of a delta, by its retention (spec/commits.md §5), one per member of its set:

  | level | retention set members | secret |
  |---|---|---|
  | 1, admin | `admin`, `author_or_admin`, `writer` | the admin secret of its thing |
  | 2, author | `author_or_admin`, `writer` | the write secret of the commit's one purge author (spec/permissions.md §6), at the purge author's delete base (below; a key actor's: its signing key) |
  | 3, writer | `writer` | the write secret of its thing |

- **Header list**: a header lists, per level of each delta, the first of these for the level's base (the delete base of the delta's thing at levels 1 and 3, of its purge author at level 2); a writer holding none of them cannot write:
  - the base's delete key of the newest current epoch of that level's secret the writer holds;
  - the `delete_key` of the base's `keys.0` keyset of that role it holds.
  - A linked header list's chunks carry one empty group (spec/wire.md §4, §5): no delete key covers them; they go by the delete key or at their expiry (spec/sync-ids.md §6 Delete).
- **Commitment**, its `blind` sub-bullet:
  - `blind` of a commit blob is the 16 random bytes of its header. A blob reached by a link (a chunk, tree node, page or link page, of a value or of a header list) has its own **link blind**, the first 16 bytes of `kdf("link blind", blob key)`, and its `blind` is its **thing blind**, the first 16 bytes of `kdf("thing blind", link blind, tid)`, tid that of the thing whose dedup secret keys its link (a header list's: the header's `signer`): whoever holds a link to the blob and knows its thing can compute its commitments, nobody else, and commitments computed for another thing are not the blob's.
- A holder tries every epoch it holds of the level's secret up the base's record chain (a thing that became independent keeps its earlier content under its mint admin's keys) and signs with the one whose key the header lists, or, for a linked blob, the link names (spec/sync-compaction.md §1; level 2 up the dropped body's purge author's chain).
