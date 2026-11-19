# A1 draft: spec/crypto.md
> Summary: Draft spec text for stage A1 (not in spec, not built): spec/crypto.md §7's delete-key level 2 as the purge author's, the header list's base and thing blind under the signer, and a holder's level-2 signing. Map and status: notes/a1-spec/README.md.

Replaces, in spec/crypto.md §7: the Levels table, the Header list bullet, the `blind` sub-bullet of Commitment, and the last bullet (a holder tries every epoch). Delete base, Delete key, Commitment's other sub-bullets, Certificate blobs and Delete signature stand.

**PENDING MODEL** (purge authors: notes/a1-spec/README.md).

## 7. Delete keys
- **Levels** of a delta, by its retention (spec/commits.md §5), one per member of its set:

  | level | retention set members | secret |
  |---|---|---|
  | 1, admin | `admin`, `author_or_admin`, `writer` | the admin secret of its thing |
  | 2, author | `author_or_admin`, `writer` | the write secret of the delta's purge author (spec/permissions.md §6), at the purge author's delete base (below; a key actor's: its signing key) |
  | 3, writer | `writer` | the write secret of its thing |

- **Header list**: a header lists, per level of each delta, the first of these for the level's base (the delete base of the delta's thing at levels 1 and 3, of its purge author at level 2); a writer holding none of them cannot write:
  - the base's delete key of the newest current epoch of that level's secret the writer holds;
  - the `delete_key` of the base's `keys.0` keyset of that role it holds.
  - A linked header list's chunks carry one empty group (spec/wire.md §4, §5): no delete key covers them; they go by the delete key or at their expiry (spec/sync-ids.md §6 Delete).
- **Commitment**, its `blind` sub-bullet:
  - `blind` of a commit blob is the 16 random bytes of its header. A blob reached by a link (a chunk, tree node, page or link page, of a value or of a header list) has its own **link blind**, the first 16 bytes of `kdf("link blind", blob key)`, and its `blind` is its **thing blind**, the first 16 bytes of `kdf("thing blind", link blind, tid)`, tid that of the thing whose dedup secret keys its link (a header list's: the header's `signer`): whoever holds a link to the blob and knows its thing can compute its commitments, nobody else, and commitments computed for another thing are not the blob's.
- A holder tries every epoch it holds of the level's secret up the base's record chain (a thing that became independent keeps its earlier content under its mint admin's keys) and signs with the one whose key the header lists, or, for a linked blob, the link names (spec/sync-compaction.md §1; level 2 up the dropped body's purge author's chain).
