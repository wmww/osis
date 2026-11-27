# Small open questions from the review since the sync rewrite
> Summary: Design questions left by the review since the sync rewrite, each with options: a writer's own signed card commit freezing a card field, the public's role kept on a stale certificate; plus a revoked store never reopened, for the opening design.
> Priority: normal
> Tags: engine, keys, security

## A writer's own signed card commit freezes a field (security)
A card is stale per `keys.0` field by the newest signature-verified commit it carries writing that field; a verified commit the node does not hold valid counts as writing every field (`flows::cards::stale`, spec/sync-inbox.md §1). A writer W of A adds to its card a `keys.0` commit on A it signs itself (its own key, or a second-form header naming its own key under any signer: the signature verifies under the key the header names) with a far-future `ts`. Readers judge it invalid and take the older valid commits, so a stranger holding that card fires at an inbox an admin once chose; no honest node's current commit is ever newer, so none rewrites the card. Bounded as before: only an inbox an admin once validly chose, only at parties holding no newer `keys.0` of A, and a fire is sealed to A's keys. Validity cannot decide it: across a fork each side judges the other's commits invalid and the sides would rewrite each other's card forever.

Options:
1. **Ignore card commits stamped ahead of the node's clock** (a commit ahead of the clock waits anywhere, spec/commits.md §4): the freeze lasts until an admin next writes the field.
2. Count a commit for a field only where its signer ever held the role the field needs on A by an edge write held here (both sides of a fork hold both histories, so they agree), and a second-form key only where the signer's `signers.0` grants it.
3. Accept the bound as stated.

## The public's role on a stale certificate
`rotation::lost::role_here` counts the public's role wherever the node holds the public's grant, synced or not (spec/sync-set.md §2 Own things: "but for the public's"), and the lost-access drop judges by that role. A node that stops syncing A (unreached, unsynced), holding a public grant of A only as another commit's certificate, never receives the public's removal, so it keeps every secret of A for good: its own sealed history epochs included, which the public (granted without history) never had. The comment on `role_here` ("an outdated grant held gives only the open boxes") holds for boxes taken, not for secrets kept. Harm: no read (A's content goes with the unsync), but secrets of A stay with nothing synced to attribute them to, against "unsync all → zero". The exception exists so a node enters a public thing a strong reaches without a stub or signal.

Options:
1. **The public counts where A's grants count**, like any holder: drop the exception, and give entry to a public thing reached by a strong another way (its stub in the carrying unit, as for any granted thing). Removes a carve-out; needs checking that every route into a public thing still brings its stub.
2. Keep the exception for entry and the closure walk, but judge the lost-access drop by the role A's grants as synced give, without it: the node keeps only what A's grants as synced give. Two roles where there was one.
3. Keep as is and correct the comment.

The public's role now has this one source, its grant (a head listing it is gone, spec/sync-set.md §2 Own things).

## A revoked store never reopened (latent, no reproducer)
After a revocation nothing reopens S at a store whose credentials and `changed_at(S)` did not move, so it is never tested again (spec/sync-opens.md §5 Testing) and keeps S's entries. Rewritten by the opening design (notes/opening-design.md): judge against its open rule once it lands.
