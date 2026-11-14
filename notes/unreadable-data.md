# What a node learns about data it cannot read
> Summary: The full list of what a node keeping a sync ID unread learns and what it must not, the padding and wrap costs, and an index of the choices elsewhere that keep the list this short (each with where its reason lives). The requirement: spec/requirements.md, Data a node cannot read; the stated limits: spec/sync-hostile.md §2. Neighbours: notes/sync-reasons.md, notes/sync-access.md, notes/networking.md (transport keys).

## Learns
- Of each thing it keeps unread, its account's sync record: the tid, its sync IDs and secrets, and the granting account where the grant's signer's key is held (spec/sync-ids.md §2 What a sync holder learns, spec/sync.md §3).
- Overlaps between sync IDs (shared commit blobs and certificate copies; inbox, list and record blobs and per-sync-ID copies share nothing). Nesting only as far as overlap shows it.
- Blob counts, padded sizes, each blob's class (durable, ephemeral, relay-only), which entries carry a filler wrap (chunk, tree-node, page and inbox blobs), the delete-key commitments per level (which kinds of right may delete), expiry times, arrival times, deletions and pending deletion times.
- Which sync IDs one connection opens (so: holds a credential of), and client addresses.
- Which actors dial it: a dialer proves its account and the key actors it acts for to every key it chose to dial (spec/sync-opens.md §2), so the node links them to the sync IDs the connection opens; a node key only between nodes of one account.
- The roster bucket of each step's claim set (and of a rotation commit, by its padded size), which claim slots were used, when, and how many steps behind the claimant was (two late nodes of one account use one slot); roughly how many key actors read the thing (static entries are not points about half the time).
- Which entries were deposited and when (a grant or a non-writer's write).
- Header-only lasting blobs: one more small stamped entry with no commitments close to a deletion it already sees (notes/sync-convergence.md).
- Whether a node keeps S is visible to anyone holding S's public values (its filter goes to every connection; Behind's 13 against 14), and a depositor holding a team's `keys.0` learns whether a node holds the team's inbox (spec/sync-hostile.md §2).

## Does not learn
AKs, tids other than its dialers' proven actors and the things it keeps unread, thing or aspect counts, authors, role grants, rosters, another account's node identities, retention bounds. What it deleted (a delete, an expiry, a replaced entry) it forgets: its store shreds every removal, so a later compromise of that node, even one that also holds the read secret, recovers no deleted wrap (notes/sync-reasons.md, Nodes; notes/local-store.md).

## Costs
- Padmé padding costs at most about 12% under 256 B, 6% up to 64 KB, 3% above; 1-4% on average.
- The wrap costs about 25% on a minimal commit, under 5% on typical edits. Chunk, tree-node, page and inbox entries carry a filler wrap (57 random bytes) that hides nothing; it could be dropped for those kinds (a wire change).
- Claim keys: 32 B per reader per step (notes/sync-access.md).

## Choices that keep it so
- Delete-key commitments are blinded per blob, so a node cannot tell which blobs carry one author's or actor's deletes (notes/sync-reasons.md, Blob prefix).
- Opens gated by the head's credentials, Behind answers one sync key at a time, refusals carrying a code alone, opens ending at a new sync key (notes/sync-access.md).
- Claim-set padding keys are valid points; static entries are hashes until claimed (notes/sync-access.md).
- A node keeping S unread holds only a sync record of its thing: no roster, chain, `keys.0` or commit (spec/sync.md §3).
- The log ID is random per store, so a wiped node invalidates old cursors and two nodes' logs are unrelated (notes/local-store.md, Node log).
- A node dials with an ephemeral transport key per connection, each QUIC dial on its own UDP socket, and listens under its one dialable key (spec/sync-transport.md §1, §3, §5).
- Wake-up push tokens, if built, must not link sync IDs (notes/networking.md, Proposal).
- Nodes may batch writes to blur timing (policy).
