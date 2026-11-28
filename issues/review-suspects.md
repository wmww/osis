# Small open questions from the review since the sync rewrite
> Summary: Design questions left by the review since the sync rewrite, each with options: the public's role kept on a stale certificate; plus a revoked store never reopened, for the opening design; plus unconfirmed suspicions from the review of the engine and sync fixes (may_log's early return, cutoffs reading each other, own_on cost, two T/ owners, section trial cost).
> Priority: normal
> Tags: engine, keys, security

## The public's role on a stale certificate
`rotation::lost::role_here` counts the public's role wherever the node holds the public's grant, synced or not (spec/sync-set.md §2 Own things: "but for the public's"), and the lost-access drop judges by that role. A node that stops syncing A (unreached, unsynced), holding a public grant of A only as another commit's certificate, never receives the public's removal, so it keeps every secret of A for good: its own sealed history epochs included, which the public (granted without history) never had. The comment on `role_here` ("an outdated grant held gives only the open boxes") holds for boxes taken, not for secrets kept. Harm: no read (A's content goes with the unsync), but secrets of A stay with nothing synced to attribute them to, against "unsync all → zero". The exception exists so a node enters a public thing a strong reaches without a stub or signal.

Options:
1. **The public counts where A's grants count**, like any holder: drop the exception, and give entry to a public thing reached by a strong another way (its stub in the carrying unit, as for any granted thing). Removes a carve-out; needs checking that every route into a public thing still brings its stub.
2. Keep the exception for entry and the closure walk, but judge the lost-access drop by the role A's grants as synced give, without it: the node keeps only what A's grants as synced give. Two roles where there was one.
3. Keep as is and correct the comment.

The public's role now has this one source, its grant (a head listing it is gone, spec/sync-set.md §2 Own things).

## A revoked store never reopened (latent, no reproducer)
After a revocation nothing reopens S at a store whose credentials and `changed_at(S)` did not move, so it is never tested again (spec/sync-opens.md §5 Testing) and keeps S's entries. Rewritten by the opening design (spec/sync-opens.md §4-§6): judge against its open rule once it lands.

## Unconfirmed suspicions (review of the engine and sync fixes)
- **`Ground::may_log`'s early return** (core/sync/src/read/live.rs): it answers false when `may_log` over every stored blob is false, which is sound only if `may_log` grows with its blob list. `loses_among` (core/engine/src/sync/bodies.rs) skips a blob that loses to another blob in the list, so an extra stored blob may make a deciding one lose. Check monotonicity or run the early check over `held` alone.
- **Cutoffs reading each other** (memo/cutoff.rs `with_stale`, `WouldBlock => unreachable!`): cutoff A whose derivation reads B's rows, with B reading A's, panics on re-entry. No pair does today; detect it and treat it as stale, or state the rule in the Cutoff docs.
- **`own_on` cost** (core/engine/src/sync/units.rs): it iterates every holder in `roles_now(t)` and filters to own things, so a grant onto a widely shared thing costs its member count. An index from own things to targets would scale right.
- **Two owners of a `T/` record**: `forget_timed` follows the actor's secrets, but `prune_timed`'s "no longer held" sweep (rotation/lost.rs) still runs. Keep one.
- **Section trial cost** (775f5b29f): a wrong secret costs a Poly1305 pass over the whole section, not a 72 B wrap. Readers try held read secrets newest first, then the blob key, so a copy section of a thing with E held epochs costs E+1 passes, and a departed holder pays E passes per section of every commit it cannot read. Trying the blob key first for a blob with one empty-chain section would make copies cost one pass.
- **`records_moved`** (ed2d3ce2f) moves the wait to the current pass at every move of S's certificate records. If they move more often than a pass completes, a new reader's record blob is never logged.
- **Sides on release** (7d5b9dcec): a chosen side goes with R on a whole release. A node that syncs the thing again judges afresh, possibly taking the walk's side against what its user chose, and the dispute is told again. While the thing is held, R stays (spec/permissions.md §6 keeps role commits of any validity, and `roles.0` is never snapshotted), so sides stick while held.
