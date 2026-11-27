# Small open questions from the review since the sync rewrite
> Summary: Design questions left by the review since the sync rewrite, each with options: the public's role kept on a stale certificate; plus a revoked store never reopened, for the opening design.
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
