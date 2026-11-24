# Delete-key check: what is left
> Summary: Delete keys are step keys and verdicts read the key check (spec/crypto.md §7 Checked keys; `Indexes::miskeyed`), and a writer lists the step its base's `sync.0` records or the step keys its `keys.0` publishes (notes/delete-keys.md). Left: link checks, the disputes note under F6, the demoted writer's level-2 residue.
> Priority: normal
> Tags: security, sync, engine

Built: notes/delete-keys.md. Level 2 stays unchecked (the purge author's own key). Stores do not change: a delta with a wrong key applies at no node that judges it, so a store deleting it loses nothing.

## Left
1. **Link checks** (spec/crypto.md §7: every link's delete keys against its delta's; a failing page link makes its delta bad, a chunk link reads as absent): not built. A writer listing other keys in a link than in its delta leaves the linked blob undeletable by the delta's keys at stores.
2. notes/disputes.md, Storage under a fork, reads a party's writes as valid on both sides of a fork: rewrite under F6 (a writer's commits list its side's step and apply nowhere on the other, notes/write-path-design.md §1).
3. The demoted writer's level-2 residue: issues/demoted-writer-deletes-at-stores.md.
