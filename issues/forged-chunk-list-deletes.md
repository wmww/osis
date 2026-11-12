# A forged chunk list can get another thing's chunk deleted
> Summary: Unverified, from the chunk-blind review. A header's chunk list is a writer rule nobody checks, and `dropped_chunks` guards a listed blob only by the held trees of the listing commit's things. A writer of thing T1 who reads T2 can list a live chunk B of T2 in a T1 commit; once that commit drops, a node holding the label delete key (an admin of the label) or a delete key B commits to (T1 and T2 sharing a delete base, spec/crypto.md §7) deletes B at hosts and forgets its local copy.
> Priority: normal
> Tags: security, sync, node

- Path: `pass/delete.rs` `dropped_chunks` takes the first dropped lister `(c, ch)`, then checks `held_trees` only for the things of `c`; `chunk_delete` signs with the label key, or with the delete keys `ch` names under the blind `ch` gives (a link blind: the forger needs B's link, so it must read T2).
- Safe while a held, not dropped commit lists B (a live introducer, or a durable compaction snapshot of T2: it lists every blob it links). Open when every T2 commit listing B is dropped or forgotten (B reused by own replaces, no snapshot yet), or the node holds none of T2.
- The label-key path predates link blinds; the delete-key path needs them (before, a forged entry signed under the forger's header blind, which B's prefix never used).
- Requirements touched: malicious writers bounded, reading never allows deleting (spec/requirements.md Threat model, Data a node cannot read).
- Directions: check `held_trees` for the things of every lister of B, not the first only (closes it while any T2 commit listing B is held); for the rest, a blob deleted only through a lister whose thing's held trees were walked, or the rule that a chunk list names only blobs the commit's own deltas link (checkable by a reader holding the trees, as a validity rule).
