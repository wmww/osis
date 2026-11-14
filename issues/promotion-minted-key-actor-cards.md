# A reader gets a card stamped for every key actor it mints
> Summary: Promotion takes a key actor's newest own card (`keys.0`, `node.0`, `reach.0`) under any sync ID (spec/sync-inbox.md §4), because reader nodes' cards go under every sync ID they sync (issues/account-signing.md step 7) and a group's writer cannot tie a node to its account. Anyone with the deposit key can mint key actors at no cost and write each a card with chosen bytes (`reach.0` items): each is stamped and kept. Bounded by the deposit rate and the sync ID's caps only.
> Priority: normal
> Tags: security, sync

Measured on the sync before the rebuild: 20 of 20 minted cards stamped, 4 KB each. The rebuilt sync promotes by the same rule; no test probes it yet.

Why not "cards only of authors of commits the sync ID must hold": a node authors nothing but its own card (its account authors the rest), so a pure reader node's card would never be stamped; it would sit deposited, count toward the clearing cap and be cleared and re-deposited past it. Co-readers no longer dial by a card under the group (core/engine/src/sync/dial.rs), so step 7 removing cards from groups costs no dialing.

Accepted as an interim limit until issues/account-signing.md step 7. Directions: step 7 (no node card under group sync IDs) removes the class. Short of it, the sync ID would need a writer-checkable node-to-account link (the account's devices actor edge naming the node, as a chain certificate) and a bound on nodes per account, which an account can grow at will too.
